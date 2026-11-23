#!/usr/bin/env python3
"""
BGMI ID Info API  (Rooter shop /validate endpoint, guest-token first)

  /api/bgmi?uid=<UID>             -> {"success":true,"username":...}
  /api/bgmi?uid=<UID>&debug=1&key=<DEBUG_KEY>   -> + step-by-step trace
  /api/debug?uid=<UID>&key=<DEBUG_KEY>          -> trace + env + connectivity
  /health

Flow
  1. Rooter shop page se guest token (cookie `user_auth`) lo
  2. POST https://shop.rooter.io/v1/users/games/BGMI/validate
  3. Guest token reject ho (401/403) to ek baar fresh guest token,
     phir (agar set ho) ROOTER_TOKEN (logged-in account) pe fallback

Env vars (Vercel > Settings > Environment Variables)
  DEBUG_KEY      -> debug endpoints is key ke bina band rahenge (set karna zaroori)
  ROOTER_TOKEN   -> OPTIONAL fallback. accessToken ya poori user_auth cookie value
  DEVICE_ID      -> OPTIONAL, fixed UUID. Na ho to ek random UUID per instance
  PRODUCT_ID / SELLER_ID / VARIATION_ID -> OPTIONAL, defaults neeche hain
  LOG_LEVEL      -> DEBUG / INFO / WARNING
"""

import base64
import json
import logging
import os
import sys
import time
import traceback
import uuid
from urllib.parse import unquote

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("bgmi-api")

# ---------- Config ----------
CACHE_TTL = 300
USER_CACHE = {}          # uid -> {"data":..., "timestamp":...}
GUEST = {}               # {"token":..., "expires_at":..., "client_id":...}

SHOP_HOME = "https://shop.rooter.gg/product/bgmi-uc-purchase"
ORIGIN = "https://shop.rooter.gg"
REFERER = "https://shop.rooter.gg/"
VALIDATE_URL = "https://shop.rooter.io/v1/users/games/BGMI/validate"

# BGMI UC product ke IDs (HAR se). Product badle to env var se override karo.
PRODUCT_ID = os.environ.get("PRODUCT_ID", "68b68cd040686941011133fd")
SELLER_ID = os.environ.get("SELLER_ID", "68b674c47b5553796f3f2035")
VARIATION_ID = os.environ.get("VARIATION_ID", "68b68cd04068694101113403")

DEBUG_KEY = os.environ.get("DEBUG_KEY")
DEVICE_ID = os.environ.get("DEVICE_ID") or str(uuid.uuid1())

UA = ("Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/157.0.0.0 Mobile Safari/537.36")


# ======================================================================
# Helpers
# ======================================================================
def snippet(text, n=300):
    if text is None:
        return None
    text = str(text).replace("\n", " ").replace("\r", " ")
    return text[:n] + ("…" if len(text) > n else "")


def mask(token):
    if not token:
        return None
    return f"{token[:6]}…{token[-4:]} (len={len(token)})"


def jwt_claims(token):
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def jwt_info(token):
    c = jwt_claims(token)
    if not c:
        return {"error": "JWT parse nahi hua"}
    now = time.time()
    out = {"verified_user": c.get("isVerified")}
    if "exp" in c:
        out["exp_in_s"] = int(c["exp"] - now)
    return out


def looks_blocked(resp):
    body = (resp.text or "")[:2000].lower()
    hints = []
    if resp.status_code in (403, 429, 503):
        hints.append(f"HTTP {resp.status_code}")
    if "cloudflare" in body or "cf-ray" in {k.lower() for k in resp.headers}:
        hints.append("cloudflare")
    if "captcha" in body or "just a moment" in body or "attention required" in body:
        hints.append("captcha/challenge page")
    return hints


class Trace:
    """Har step ka record, taaki pata chale kaha toota."""

    def __init__(self):
        self.steps = []
        self.t0 = time.time()

    def add(self, step, ok, **info):
        entry = {"step": step, "ok": ok, "t_ms": int((time.time() - self.t0) * 1000)}
        entry.update({k: v for k, v in info.items() if v is not None})
        self.steps.append(entry)
        log.log(logging.INFO if ok else logging.WARNING, "[%s] ok=%s %s",
                step, ok, json.dumps(info, default=str)[:500])

    def first_failure(self):
        return next((s for s in self.steps if not s["ok"]), None)

    def to_dict(self):
        fail = self.first_failure()
        return {
            "total_ms": int((time.time() - self.t0) * 1000),
            "first_failure": {"step": fail["step"], "error": fail.get("error")} if fail else None,
            "steps": self.steps,
        }


# ======================================================================
# Tokens
# ======================================================================
def _token_from_cookie_value(raw):
    try:
        data = json.loads(unquote(raw))
        if isinstance(data, dict):
            return data.get("accessToken")
    except Exception:
        pass
    return None


def get_guest_token(trace, force=False):
    """Shop page kholo, `user_auth` cookie me guest accessToken milta hai."""
    now = time.time()
    if not force and GUEST.get("token") and GUEST["expires_at"] > now:
        trace.add("guest.cache", True, token=mask(GUEST["token"]),
                  expires_in_s=int(GUEST["expires_at"] - now))
        return GUEST["token"], GUEST.get("client_id")

    session = requests.Session()
    try:
        resp = session.get(SHOP_HOME, headers={
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }, timeout=10)
        blocked = looks_blocked(resp)
        raw = session.cookies.get("user_auth")
        token = _token_from_cookie_value(raw) if raw else None
        client_id = session.cookies.get("client_id")
        ok = resp.status_code == 200 and bool(token)
        trace.add("guest.fetch", ok, status=resp.status_code,
                  cookies=sorted(session.cookies.keys()),
                  blocked_hints=blocked or None,
                  token=mask(token), jwt=jwt_info(token) if token else None,
                  error=None if ok else "user_auth cookie/accessToken nahi mila "
                                        "(IP block ya site ne guest cookie dena band kiya)")
        if not token:
            return None, None
        ttl = 600
        exp_in = jwt_info(token).get("exp_in_s")
        if isinstance(exp_in, int):
            ttl = max(0, min(ttl, exp_in - 60))
        GUEST.update({"token": token, "client_id": client_id, "expires_at": now + ttl})
        return token, client_id
    except Exception as e:
        trace.add("guest.exception", False, error=f"{type(e).__name__}: {e}")
        return None, None


def get_account_token(trace):
    """Optional fallback: logged-in account ka token, sirf env var se."""
    raw = (os.environ.get("ROOTER_TOKEN") or "").strip()
    if not raw:
        return None
    if raw.startswith(("{", "%7B", "%7b")):
        raw = _token_from_cookie_value(raw) or ""
    if not raw:
        trace.add("account.token", False, error="ROOTER_TOKEN parse nahi hua")
        return None
    info = jwt_info(raw)
    trace.add("account.token", True, token=mask(raw), jwt=info)
    if isinstance(info.get("exp_in_s"), int) and info["exp_in_s"] <= 0:
        trace.add("account.expired", False,
                  error="ROOTER_TOKEN expire ho chuka hai - dobara login karke naya daalo")
        return None
    return raw


# ======================================================================
# Validate (username lookup)
# ======================================================================
def api_error(resp):
    try:
        j = resp.json()
        return snippet(json.dumps(j), 250)
    except Exception:
        return f"HTTP {resp.status_code}: {snippet(resp.text, 150)}"


def call_validate(uid, token, client_id, label, trace):
    """Return (state, username).  state: ok | invalid_player | auth_failed | error"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "device-type": "web",
        "device-category": "mobile",
        "app-version": "1.0.0",
        "device-id": DEVICE_ID,
        "x-s-country-code": "IN",
        "country-code": "IN",
        "x-language-code": "en",
        "User-Agent": UA,
        "Origin": ORIGIN,
        "Referer": REFERER,
    }
    if client_id:
        headers["x-client-id"] = client_id
    body = {"playerId": uid, "productId": PRODUCT_ID,
            "sellerId": SELLER_ID, "variationId": VARIATION_ID}

    def post():
        return requests.post(VALIDATE_URL, headers=headers, json=body, timeout=15)

    try:
        resp = post()
        if resp.status_code >= 500:  # upstream hiccup, ek retry
            trace.add(f"validate.{label}.upstream_error", False,
                      status=resp.status_code, error=api_error(resp))
            time.sleep(1.5)
            resp = post()

        blocked = looks_blocked(resp)
        if resp.status_code in (401, 403):
            trace.add(f"validate.{label}", False, status=resp.status_code,
                      blocked_hints=blocked or None, error=api_error(resp))
            return "auth_failed", None
        if resp.status_code not in (200, 201):
            trace.add(f"validate.{label}", False, status=resp.status_code,
                      blocked_hints=blocked or None, error=api_error(resp))
            return "error", None

        try:
            data = resp.json()
        except Exception as e:
            trace.add(f"validate.{label}", False, status=resp.status_code,
                      error=f"JSON nahi hai: {e}", body_preview=snippet(resp.text))
            return "error", None

        if data.get("isValid") and data.get("username"):
            trace.add(f"validate.{label}", True, status=resp.status_code,
                      username=data["username"])
            return "ok", data["username"]

        trace.add(f"validate.{label}", False, status=resp.status_code,
                  error="isValid=false (player ID galat/nahi mila)",
                  raw=snippet(json.dumps(data), 300))
        return "invalid_player", None
    except Exception as e:
        trace.add(f"validate.{label}.exception", False, error=f"{type(e).__name__}: {e}")
        return "error", None


def fetch_username(uid, trace):
    """Return (username, state)."""
    # 1) guest token
    token, client_id = get_guest_token(trace)
    if token:
        state, username = call_validate(uid, token, client_id, "guest", trace)
        if state in ("ok", "invalid_player"):
            return username, state
        if state == "auth_failed":
            # cache ka token purana ho sakta hai, ek baar fresh lo
            token, client_id = get_guest_token(trace, force=True)
            if token:
                state, username = call_validate(uid, token, client_id, "guest_fresh", trace)
                if state in ("ok", "invalid_player"):
                    return username, state

    # 2) logged-in account fallback (optional)
    acct = get_account_token(trace)
    if acct:
        trace.add("fallback.account", True, note="guest fail, ROOTER_TOKEN try ho raha hai")
        state, username = call_validate(uid, acct, client_id if token else None, "account", trace)
        return username, state

    return None, "error"


# ======================================================================
# Player info
# ======================================================================
def get_player_info(uid, trace, use_cache=True):
    now = time.time()
    if use_cache and uid in USER_CACHE and now - USER_CACHE[uid]["timestamp"] < CACHE_TTL:
        trace.add("cache.hit", True, uid=uid)
        return USER_CACHE[uid]["data"], 200
    trace.add("cache.miss", True, uid=uid)

    username, state = fetch_username(uid, trace)

    if username:
        result = {"success": True, "username": username, "uid": uid,
                  "server": "BGMI", "region": "India"}
        USER_CACHE[uid] = {"data": result, "timestamp": now}
        return result, 200

    if state == "invalid_player":
        return {"success": False, "uid": uid, "error": "Player ID invalid ya nahi mila"}, 404

    fail = trace.first_failure()
    return {
        "success": False,
        "uid": uid,
        "error": "Username fetch nahi ho paya",
        "reason": fail.get("error") if fail else "unknown",
        "failed_step": fail["step"] if fail else None,
        "hint": "Debug ke liye &debug=1&key=<DEBUG_KEY> lagao",
    }, 502


# ======================================================================
# Debug access (DEBUG_KEY set na ho to debug band)
# ======================================================================
def debug_allowed():
    return bool(DEBUG_KEY) and request.args.get("key") == DEBUG_KEY


def check_host(url):
    t = time.time()
    try:
        r = requests.get(url, headers={"User-Agent": UA}, timeout=8)
        return {"url": url, "reachable": True, "status": r.status_code,
                "ms": int((time.time() - t) * 1000),
                "blocked_hints": looks_blocked(r) or None}
    except Exception as e:
        return {"url": url, "reachable": False, "ms": int((time.time() - t) * 1000),
                "error": f"{type(e).__name__}: {e}"}


# ======================================================================
# Routes
# ======================================================================
@app.route("/")
def home():
    return jsonify({"service": "BGMI ID Info API",
                    "endpoint": "/api/bgmi?uid=<UID>",
                    "example": "/api/bgmi?uid=5120321397"})


@app.route("/health")
def health():
    return jsonify({"status": "ok", "time": int(time.time())})


@app.route("/api/bgmi", methods=["GET"])
def bgmi_info():
    uid = (request.args.get("uid") or "").strip()
    if not uid:
        return jsonify({"success": False, "error": "Missing 'uid' parameter"}), 400
    if not uid.isdigit() or len(uid) > 15:
        return jsonify({"success": False, "error": "UID must be numeric"}), 400

    want_debug = request.args.get("debug") in ("1", "true", "yes")
    if want_debug and not debug_allowed():
        return jsonify({"success": False, "error": "Debug band hai ya key galat hai"}), 403

    trace = Trace()
    data, status = get_player_info(uid, trace, use_cache=not want_debug)
    if want_debug:
        data = dict(data)
        data["debug"] = trace.to_dict()
    return jsonify(data), status


@app.route("/api/debug", methods=["GET"])
def debug_endpoint():
    if not debug_allowed():
        return jsonify({"success": False, "error": "Debug band hai ya key galat hai"}), 403

    uid = request.args.get("uid", "5120321397")
    if not uid.isdigit():
        return jsonify({"success": False, "error": "UID must be numeric"}), 400

    trace = Trace()
    result, _ = get_player_info(uid, trace, use_cache=False)
    return jsonify({
        "uid": uid,
        "result": result,
        "trace": trace.to_dict(),
        "environment": {
            "python": sys.version.split()[0],
            "vercel": bool(os.environ.get("VERCEL")),
            "vercel_region": os.environ.get("VERCEL_REGION"),
            "requests": requests.__version__,
            "account_fallback_set": bool(os.environ.get("ROOTER_TOKEN")),
            "device_id_fixed": bool(os.environ.get("DEVICE_ID")),
        },
        "cache": {
            "guest_token": mask(GUEST.get("token")),
            "guest_expires_in_s": max(0, int(GUEST.get("expires_at", 0) - time.time())),
            "users_cached": len(USER_CACHE),
        },
        "connectivity": [
            check_host("https://shop.rooter.gg/"),
            check_host("https://shop.rooter.io/"),
        ],
    }), 200


@app.errorhandler(Exception)
def handle_exception(e):
    log.exception("Unhandled error")
    body = {"success": False, "error": f"{type(e).__name__}: {e}"}
    if request.args.get("debug") in ("1", "true", "yes") and debug_allowed():
        body["traceback"] = traceback.format_exc()
    return jsonify(body), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    app.run(host="0.0.0.0", port=port, debug=False)
