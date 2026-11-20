#!/usr/bin/env python3
"""
BGMI ID Info API – Dynamic Region Detection (with built-in debug system)
Fetches username from rooter.gg, region from player profile.

DEBUG USAGE
-----------
  /api/bgmi?uid=<UID>&debug=1     -> normal result + full step-by-step trace
  /api/debug?uid=<UID>            -> trace + environment + connectivity checks
  /health                         -> quick liveness check

Env vars (optional):
  DEBUG_KEY  -> if set, debug endpoints need  &key=<DEBUG_KEY>
  LOG_LEVEL  -> DEBUG / INFO / WARNING (default INFO). Logs show in Vercel > Logs.
"""

import requests
import json
import time
import re
import os
import sys
import logging
import traceback
from urllib.parse import unquote
from flask import Flask, request, jsonify
from bs4 import BeautifulSoup

app = Flask(__name__)

# ---------- Logging ----------
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("bgmi-api")

# ---------- Config ----------
CACHE_TTL = 300
USER_CACHE = {}
TOKEN_CACHE = {"token": None, "expires_at": 0}
DEBUG_KEY = os.environ.get("DEBUG_KEY")

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")


# ======================================================================
# Debug helpers
# ======================================================================
def snippet(text, n=300):
    """Short, single-line preview of a response body."""
    if text is None:
        return None
    text = str(text).replace("\n", " ").replace("\r", " ")
    return text[:n] + ("…" if len(text) > n else "")


def mask(token):
    """Never expose a full token in debug output."""
    if not token:
        return None
    return f"{token[:6]}…{token[-4:]} (len={len(token)})"


def looks_blocked(resp):
    """Detect Cloudflare / bot-protection / rate-limit pages."""
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
    """Collects every step of a request so we can see exactly where it breaks."""

    def __init__(self):
        self.steps = []
        self.t0 = time.time()

    def add(self, step, ok, **info):
        entry = {
            "step": step,
            "ok": ok,
            "t_ms": int((time.time() - self.t0) * 1000),
        }
        entry.update({k: v for k, v in info.items() if v is not None})
        self.steps.append(entry)
        level = logging.INFO if ok else logging.WARNING
        log.log(level, "[%s] ok=%s %s", step, ok, json.dumps(info, default=str)[:500])

    def first_failure(self):
        for s in self.steps:
            if not s["ok"]:
                return s
        return None

    def to_dict(self):
        fail = self.first_failure()
        return {
            "total_ms": int((time.time() - self.t0) * 1000),
            "first_failure": {"step": fail["step"], "error": fail.get("error")} if fail else None,
            "steps": self.steps,
        }


# ======================================================================
# Token (rooter.gg)
# ======================================================================
def get_authorization_token(session, trace, force_refresh=False):
    global TOKEN_CACHE
    now = time.time()
    if not force_refresh and TOKEN_CACHE["token"] and TOKEN_CACHE["expires_at"] > now:
        trace.add("token.cache", True, note="using cached token",
                  token=mask(TOKEN_CACHE["token"]),
                  expires_in_s=int(TOKEN_CACHE["expires_at"] - now))
        return TOKEN_CACHE["token"]

    try:
        url = "https://www.rooter.gg/"
        headers = {
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        resp = session.get(url, headers=headers, timeout=10)
        blocked = looks_blocked(resp)
        trace.add("token.request", resp.status_code == 200 and not blocked,
                  url=url, status=resp.status_code, final_url=resp.url,
                  cookies_received=sorted(session.cookies.keys()),
                  blocked_hints=blocked or None,
                  error=(f"rooter.gg ne block kiya: {blocked}" if blocked else None),
                  body_preview=None if resp.status_code == 200 else snippet(resp.text))

        user_auth = session.cookies.get("user_auth")
        if not user_auth:
            trace.add("token.cookie", False,
                      error="'user_auth' cookie nahi mili — rooter.gg ne cookie dena band kiya ya "
                            "request block hui (server/Vercel IP block ho sakta hai)",
                      cookies_received=sorted(session.cookies.keys()))
            return None

        try:
            token_data = json.loads(unquote(user_auth))
        except Exception as e:
            trace.add("token.parse", False,
                      error=f"user_auth cookie JSON parse fail: {e}",
                      cookie_preview=snippet(unquote(user_auth), 120))
            return None

        token = token_data.get("accessToken")
        if not token:
            trace.add("token.parse", False,
                      error="cookie mil gayi par 'accessToken' key nahi hai",
                      keys_found=list(token_data.keys()) if isinstance(token_data, dict) else str(type(token_data)))
            return None

        TOKEN_CACHE["token"] = token
        TOKEN_CACHE["expires_at"] = now + 3600
        trace.add("token.parse", True, token=mask(token))
        return token

    except Exception as e:
        trace.add("token.exception", False, error=f"{type(e).__name__}: {e}")
        log.error("Token fetch error: %s", e)
        return None


# ======================================================================
# Username (rooter.gg)
# ======================================================================
def fetch_username(uid, trace):
    session = requests.Session()
    token = get_authorization_token(session, trace)
    if not token:
        return None

    url = f"https://bazaar.rooter.io/order/getUnipinUsername?gameCode=BGMI_IN&id={uid}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Device-Type": "web",
        "App-Version": "1.0.0",
        "Device-Id": "api-service",
        "User-Agent": UA,
        "Accept": "application/json",
        "Referer": "https://www.rooter.gg/",
    }

    def call():
        return session.get(url, headers=headers, timeout=15)

    try:
        resp = call()
        trace.add("username.request", resp.status_code == 200, url=url,
                  status=resp.status_code,
                  content_type=resp.headers.get("Content-Type"),
                  blocked_hints=looks_blocked(resp) or None,
                  body_preview=snippet(resp.text))

        # Token expire / invalid -> refresh once and retry
        if resp.status_code in (401, 403):
            trace.add("username.token_refresh", True,
                      note=f"HTTP {resp.status_code} aaya, token refresh karke retry")
            token = get_authorization_token(session, trace, force_refresh=True)
            if not token:
                return None
            headers["Authorization"] = f"Bearer {token}"
            resp = call()
            trace.add("username.retry", resp.status_code == 200,
                      status=resp.status_code, body_preview=snippet(resp.text))

        try:
            data = resp.json()
        except Exception as e:
            trace.add("username.json", False,
                      error=f"Response JSON nahi hai: {e}",
                      body_preview=snippet(resp.text))
            return None

        transaction = data.get("transaction") if isinstance(data, dict) else None
        if transaction == "SUCCESS":
            username = (data.get("unipinRes") or {}).get("username")
            trace.add("username.result", bool(username),
                      username=username,
                      error=None if username else "SUCCESS aaya par 'unipinRes.username' empty hai",
                      raw=None if username else snippet(json.dumps(data), 400))
            return username

        trace.add("username.result", False,
                  error=f"API ne SUCCESS nahi diya (transaction={transaction!r}) — UID galat ho sakta hai "
                        f"ya rooter ka response format badal gaya",
                  raw=snippet(json.dumps(data), 400))
    except Exception as e:
        trace.add("username.exception", False, error=f"{type(e).__name__}: {e}")
        log.error("Username fetch error for %s: %s", uid, e)
    return None


# ======================================================================
# Region (bgmionline.in)
# ======================================================================
def fetch_region(uid, trace):
    """Scrape bgmionline.in to get player's country/region."""
    try:
        url = f"https://bgmionline.in/player/{uid}"
        resp = requests.get(url, headers={"User-Agent": UA}, timeout=10)
        if resp.status_code != 200:
            trace.add("region.request", False, url=url, status=resp.status_code,
                      blocked_hints=looks_blocked(resp) or None,
                      error=f"bgmionline.in ne HTTP {resp.status_code} diya",
                      body_preview=snippet(resp.text))
            return None
        trace.add("region.request", True, url=url, status=200, html_bytes=len(resp.text))

        soup = BeautifulSoup(resp.text, "html.parser")

        flag = soup.find("img", src=re.compile(r"flag|country", re.I))
        if flag and flag.get("alt"):
            region = flag["alt"].strip()
            trace.add("region.parse", True, method="flag_img_alt", region=region)
            return region

        for elem in soup.find_all(string=True):
            txt = elem.strip()
            if txt and ("country" in txt.lower() or "region" in txt.lower()):
                parent = elem.parent
                if parent:
                    full = parent.get_text(strip=True)
                    match = re.search(r"[Cc]ountry\s*[:.]?\s*([A-Za-z\s]+)", full)
                    if match:
                        region = match.group(1).strip()
                        trace.add("region.parse", True, method="country_text", region=region)
                        return region

        trace.add("region.parse", False,
                  error="Page mila par region/flag nahi mila — site ka HTML badal gaya ya "
                        "player page JS se load hota hai. Default 'India' use hoga.",
                  page_title=soup.title.string.strip() if soup.title and soup.title.string else None,
                  body_preview=snippet(soup.get_text(" ", strip=True), 200))
        return None
    except Exception as e:
        trace.add("region.exception", False, error=f"{type(e).__name__}: {e}")
        log.error("Region fetch error for %s: %s", uid, e)
        return None


# ======================================================================
# Get Player Info
# ======================================================================
def get_player_info(uid, trace, use_cache=True):
    now = time.time()
    if use_cache and uid in USER_CACHE and now - USER_CACHE[uid]["timestamp"] < CACHE_TTL:
        trace.add("cache.hit", True, uid=uid)
        return USER_CACHE[uid]["data"]
    trace.add("cache.miss", True, uid=uid)

    username = fetch_username(uid, trace)
    region = fetch_region(uid, trace)

    if not username:
        # Fail ko cache NAHI karte, warna 5 minute tak galat "Unknown" milta rahega
        fail = trace.first_failure()
        return {
            "success": False,
            "uid": uid,
            "error": "Username fetch nahi ho paya",
            "reason": fail.get("error") if fail else "unknown",
            "failed_step": fail["step"] if fail else None,
            "hint": "Debug ke liye URL me &debug=1 lagao ya /api/debug?uid=<UID> kholo",
        }

    result = {
        "success": True,
        "username": username,
        "uid": uid,
        "server": "BGMI",
        "region": region or "India",
    }
    USER_CACHE[uid] = {"data": result, "timestamp": now}
    return result


# ======================================================================
# Debug access control
# ======================================================================
def debug_allowed():
    if not DEBUG_KEY:
        return True
    return request.args.get("key") == DEBUG_KEY


def check_host(url):
    """Connectivity check for one host."""
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
    return jsonify({
        "service": "BGMI ID Info API",
        "endpoint": "/api/bgmi?uid=<UID>",
        "example": "/api/bgmi?uid=5120321397",
        "debug": "/api/debug?uid=<UID>  or  /api/bgmi?uid=<UID>&debug=1",
    })


@app.route("/health")
def health():
    return jsonify({"status": "ok", "time": int(time.time())})


@app.route("/api/bgmi", methods=["GET"])
def bgmi_info():
    uid = request.args.get("uid")
    if not uid:
        return jsonify({"success": False, "error": "Missing 'uid' parameter"}), 400
    if not uid.isdigit():
        return jsonify({"success": False, "error": "UID must be numeric"}), 400

    want_debug = request.args.get("debug") in ("1", "true", "yes")
    if want_debug and not debug_allowed():
        return jsonify({"success": False, "error": "Invalid or missing debug key"}), 403

    trace = Trace()
    data = get_player_info(uid, trace, use_cache=not want_debug)
    status = 200 if data.get("success") else 502

    if want_debug:
        data = dict(data)
        data["debug"] = trace.to_dict()
    return jsonify(data), status


@app.route("/api/debug", methods=["GET"])
def debug_endpoint():
    if not debug_allowed():
        return jsonify({"success": False, "error": "Invalid or missing debug key"}), 403

    uid = request.args.get("uid", "5120321397")
    if not uid.isdigit():
        return jsonify({"success": False, "error": "UID must be numeric"}), 400

    trace = Trace()
    result = get_player_info(uid, trace, use_cache=False)

    return jsonify({
        "uid": uid,
        "result": result,
        "trace": trace.to_dict(),
        "environment": {
            "python": sys.version.split()[0],
            "vercel": bool(os.environ.get("VERCEL")),
            "vercel_region": os.environ.get("VERCEL_REGION"),
            "requests": requests.__version__,
            "flask_import_ok": True,
            "debug_key_set": bool(DEBUG_KEY),
        },
        "cache": {
            "token_cached": bool(TOKEN_CACHE["token"]),
            "token": mask(TOKEN_CACHE["token"]),
            "token_expires_in_s": max(0, int(TOKEN_CACHE["expires_at"] - time.time())),
            "users_cached": len(USER_CACHE),
        },
        "connectivity": [
            check_host("https://www.rooter.gg/"),
            check_host("https://bazaar.rooter.io/"),
            check_host("https://bgmionline.in/"),
        ],
    }), 200


@app.errorhandler(Exception)
def handle_exception(e):
    """Koi bhi unexpected crash — JSON me saaf error, traceback sirf debug mode me."""
    log.exception("Unhandled error")
    body = {"success": False, "error": f"{type(e).__name__}: {e}"}
    if request.args.get("debug") in ("1", "true", "yes") and debug_allowed():
        body["traceback"] = traceback.format_exc()
    return jsonify(body), 500


# ---------- Local Development ----------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    app.run(host="0.0.0.0", port=port, debug=False)
