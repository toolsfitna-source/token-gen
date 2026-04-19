import base64
import collections
import hashlib
import json
import json as _json_module
import os
import random
import re
import string
import struct
import sys
import threading
import time
import uuid
import zlib
from datetime import datetime
from typing import Optional, Dict, Any, Tuple, List
from urllib.parse import urlparse, urlencode

try:
    import zstandard
    _HAS_ZSTD = True
except ImportError:
    _HAS_ZSTD = False
    print("[gen] WARNING: zstandard not installed — Gateway will use zlib-stream instead of zstd-stream (detectable!)")
    print("[gen]          Install with: pip install zstandard")

import requests
import websocket

from http_client import _OkHttpProxyManager, _OkHttpSession, _OkHttpResponse, _CaseInsensitiveDict
from solvers import solve_aiclientz, solve_anysolver, solve_onyx, report_onyx, solve_hsj_local
from utils import Utils

if os.name == "nt":
    os.system("")


class _TokenLogger:

    def __init__(self, output_dir: str, enabled: bool = True):
        self.enabled = enabled
        self._entries: list = []
        self._start_time = time.time()
        self._output_dir = output_dir
        if enabled:
            self._log_dir = os.path.join(output_dir, "gen_logs")
            os.makedirs(self._log_dir, exist_ok=True)
        self._meta: dict = {}

    def set_meta(self, **kwargs):
        if not self.enabled:
            return
        self._meta.update(kwargs)

    def log_request(self, method: str, url: str, headers: dict,
                    body: str | None, proxy: str | None):
        if not self.enabled:
            return 0
        idx = len(self._entries)
        self._entries.append({
            "idx": idx,
            "ts": time.time(),
            "elapsed": round(time.time() - self._start_time, 3),
            "type": "request",
            "method": method,
            "url": url,
            "headers": dict(headers) if headers else {},
            "body_preview": (body[:2000] if body else None),
            "body_len": len(body) if body else 0,
            "proxy": proxy,
        })
        return idx

    def log_response(self, req_idx: int, status: int, headers: dict,
                     body: str | None, duration: float):
        if not self.enabled:
            return
        self._entries.append({
            "idx": len(self._entries),
            "req_idx": req_idx,
            "ts": time.time(),
            "elapsed": round(time.time() - self._start_time, 3),
            "type": "response",
            "status": status,
            "headers": dict(headers) if headers else {},
            "body_preview": (body[:2000] if body else None),
            "body_len": len(body) if body else 0,
            "duration_ms": round(duration * 1000, 1),
        })

    def log_error(self, req_idx: int, error: str, duration: float):
        if not self.enabled:
            return
        self._entries.append({
            "idx": len(self._entries),
            "req_idx": req_idx,
            "ts": time.time(),
            "elapsed": round(time.time() - self._start_time, 3),
            "type": "error",
            "error": error,
            "duration_ms": round(duration * 1000, 1),
        })

    def log_event(self, event: str, details: str = ""):
        if not self.enabled:
            return
        self._entries.append({
            "idx": len(self._entries),
            "ts": time.time(),
            "elapsed": round(time.time() - self._start_time, 3),
            "type": "event",
            "event": event,
            "details": details,
        })

    def save(self, result: str = "unknown"):
        if not self.enabled:
            return None
        username = self._meta.get("username", "unknown")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{ts}_{username}_{result}.log"
        filepath = os.path.join(self._log_dir, filename)

        total_duration = round(time.time() - self._start_time, 1)
        requests_count = sum(1 for e in self._entries if e["type"] == "request")
        errors_count = sum(1 for e in self._entries if e["type"] == "error")

        lines = []
        lines.append(f"{'='*80}")
        lines.append(f"TOKEN GENERATION LOG — {result.upper()}")
        lines.append(f"{'='*80}")
        lines.append(f"Timestamp:    {datetime.now().isoformat()}")
        lines.append(f"Duration:     {total_duration}s")
        lines.append(f"Requests:     {requests_count}")
        lines.append(f"Errors:       {errors_count}")
        lines.append(f"")
        lines.append(f"--- Session Info ---")
        for k, v in self._meta.items():
            lines.append(f"  {k}: {v}")
        lines.append(f"")

        for entry in self._entries:
            t = entry["type"]
            elapsed = entry.get("elapsed", 0)

            if t == "request":
                lines.append(f"{'─'*80}")
                lines.append(f"[{elapsed:8.3f}s] >>> {entry['method']} {entry['url']}")
                lines.append(f"  Proxy: {entry.get('proxy', 'none')}")
                lines.append(f"  Headers:")
                for hk, hv in entry.get("headers", {}).items():
                    val = hv
                    if hk.lower() == "authorization" and len(hv) > 20:
                        val = hv[:20] + "..."
                    lines.append(f"    {hk}: {val}")
                if entry.get("body_preview"):
                    lines.append(f"  Body ({entry['body_len']} bytes):")
                    lines.append(f"    {entry['body_preview']}")

            elif t == "response":
                dur = entry.get("duration_ms", 0)
                lines.append(f"[{elapsed:8.3f}s] <<< {entry['status']} ({dur:.0f}ms)")
                lines.append(f"  Headers:")
                for hk, hv in entry.get("headers", {}).items():
                    lines.append(f"    {hk}: {hv}")
                if entry.get("body_preview"):
                    lines.append(f"  Body ({entry['body_len']} bytes):")
                    lines.append(f"    {entry['body_preview']}")

            elif t == "error":
                dur = entry.get("duration_ms", 0)
                lines.append(f"[{elapsed:8.3f}s] !!! ERROR ({dur:.0f}ms): {entry['error']}")

            elif t == "event":
                lines.append(f"[{elapsed:8.3f}s] *** {entry['event']}: {entry.get('details', '')}")

        lines.append(f"\n{'='*80}")
        lines.append(f"END OF LOG")
        lines.append(f"{'='*80}")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        return filepath


def _wrap_session_with_logger(sess, logger: _TokenLogger):
    if not logger.enabled:
        return sess

    if hasattr(sess, '_request'):
        original_request = sess._request

        def logged_request(method, url, headers=None, body=None, proxy=None, timeout=30, **kwargs):
            req_idx = logger.log_request(method, url, headers, body, proxy)
            t0 = time.time()
            try:
                resp = original_request(method, url, headers, body, proxy, timeout, **kwargs)
                resp_headers = {}
                if hasattr(resp, 'headers') and resp.headers:
                    resp_headers = dict(resp.headers)
                logger.log_response(req_idx, resp.status_code, resp_headers,
                                    resp.text, time.time() - t0)
                return resp
            except Exception as e:
                logger.log_error(req_idx, str(e), time.time() - t0)
                raise

        sess._request = logged_request

    return sess


# ── Locale/timezone pools (Region → real (system_locale, accept_language, x-discord-locale, IANA-tz) tuples)
# Picked once per account in generate_one() and read by header builders via _thread_ctx.
_LOCALE_POOL_EU = [
    ("fr-FR", "fr-FR", "fr",    "Europe/Paris"),
    ("de-DE", "de-DE", "de",    "Europe/Berlin"),
    ("es-ES", "es-ES", "es-ES", "Europe/Madrid"),
    ("it-IT", "it-IT", "it",    "Europe/Rome"),
    ("nl-NL", "nl-NL", "nl",    "Europe/Amsterdam"),
    ("pl-PL", "pl-PL", "pl",    "Europe/Warsaw"),
    ("pt-PT", "pt-PT", "pt-BR", "Europe/Lisbon"),
    ("en-GB", "en-GB", "en-GB", "Europe/London"),
    ("sv-SE", "sv-SE", "sv-SE", "Europe/Stockholm"),
    ("fi-FI", "fi-FI", "fi",    "Europe/Helsinki"),
    ("cs-CZ", "cs-CZ", "cs",    "Europe/Prague"),
    ("ro-RO", "ro-RO", "ro",    "Europe/Bucharest"),
]
_LOCALE_POOL_US = [
    ("en-US", "en-US", "en-US", "America/New_York"),
    ("en-US", "en-US", "en-US", "America/Chicago"),
    ("en-US", "en-US", "en-US", "America/Denver"),
    ("en-US", "en-US", "en-US", "America/Los_Angeles"),
    ("en-US", "en-US", "en-US", "America/Phoenix"),
]

_thread_ctx = threading.local()


def _pick_locale(region: str = "eu") -> Tuple[str, str, str, str]:
    """Pick a (system_locale, accept_language, discord_locale, tz) tuple and bind it
    to the current thread. Subsequent calls to _super_properties/_build_headers on
    this thread read from _thread_ctx so every REST header + x-super-properties is
    internally consistent within one account.

    Honours RAIDER_FORCE_LOCALE: when set to a locale code that matches an
    entry in the EU or US pool (e.g. "fr-FR", "de-DE", "en-US"), every account
    in the run sticks to that locale — useful when your proxies are all from
    one country and you want Discord's verify email in that language.
    """
    forced = os.environ.get("RAIDER_FORCE_LOCALE", "").strip()
    if forced:
        for tup in _LOCALE_POOL_EU + _LOCALE_POOL_US:
            if tup[0].lower() == forced.lower():
                _thread_ctx.system_locale = tup[0]
                _thread_ctx.accept_language = tup[1]
                _thread_ctx.discord_locale = tup[2]
                _thread_ctx.timezone = tup[3]
                return tup
        # Unknown code — fall through to random pool pick.

    pool = _LOCALE_POOL_US if str(region).lower() == "us" else _LOCALE_POOL_EU
    tup = random.choice(pool)
    _thread_ctx.system_locale = tup[0]
    _thread_ctx.accept_language = tup[1]
    _thread_ctx.discord_locale = tup[2]
    _thread_ctx.timezone = tup[3]
    return tup


def _ctx_system_locale() -> str:
    return getattr(_thread_ctx, "system_locale", "en-US")


def _ctx_accept_language() -> str:
    return getattr(_thread_ctx, "accept_language", "en-US")


def _ctx_discord_locale() -> str:
    return getattr(_thread_ctx, "discord_locale", "en-US")


def _ctx_timezone() -> str:
    return getattr(_thread_ctx, "timezone", "Europe/Paris")


_DISCORD_WEB_TIMEZONE = "+00:00"

UA = "Discord-Android/324016;RNA"
CLIENT_VERSION = "324.16 - rn"
CLIENT_BUILD = 32401600369668
OS_VERSION = "36"
OS_RELEASE = "16"
DESIGN_ID = 2
HCAPTCHA_SITEKEY = "e2f713c5-b5ce-41d0-b65f-29823df542cf"
HCAPTCHA_SITEKEY_WEB = "a9b5fb07-92ff-493f-86fe-352a2803b3df"
HCAPTCHA_HOST = f"https://{HCAPTCHA_SITEKEY}.react-native.hcaptcha.com"
GATEWAY_CAPABILITIES = 1734655

WEB_UA = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36"
WEB_UA_WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
_web_build_lock = threading.Lock()
_web_build_cached = -1


def _fetch_web_build() -> int:
    global _web_build_cached
    with _web_build_lock:
        if _web_build_cached > 0:
            return _web_build_cached
    try:
        page = requests.get("https://discord.com/app", timeout=10).text
        assets = re.findall(r'src="/assets/([^"]+)"', page)
        for asset in reversed(assets):
            js = requests.get(f"https://discord.com/assets/{asset}", timeout=10).text
            if "buildNumber:" in js:
                val = int(js.split('buildNumber:"')[1].split('"')[0])
                with _web_build_lock:
                    _web_build_cached = val
                return val
    except Exception:
        pass
    return -1
WEB_SEC_CH_UA = '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"'

ANDROID_DEVICES = [
    "caiman", "shiba", "oriole", "raven",
    "cheetah", "panther", "felix", "lynx", "tangorpro",
]

DEVICE_HARDWARE = {
    "caiman": {"device_model": "Pixel 9", "device_brand": "google",
               "device_product": "caiman", "device_manufacturer": "Google",
               "smallest_screen_width": 412, "soc_name": "Tensor G4",
               "ram_size": 12.0, "max_cpu_freq": 3100},
    "shiba": {"device_model": "Pixel 8", "device_brand": "google",
              "device_product": "shiba", "device_manufacturer": "Google",
              "smallest_screen_width": 412, "soc_name": "Tensor G3",
              "ram_size": 8.0, "max_cpu_freq": 2910},
    "oriole": {"device_model": "Pixel 6", "device_brand": "google",
               "device_product": "oriole", "device_manufacturer": "Google",
               "smallest_screen_width": 412, "soc_name": "Tensor",
               "ram_size": 8.0, "max_cpu_freq": 2800},
    "raven": {"device_model": "Pixel 6 Pro", "device_brand": "google",
              "device_product": "raven", "device_manufacturer": "Google",
              "smallest_screen_width": 412, "soc_name": "Tensor",
              "ram_size": 12.0, "max_cpu_freq": 2800},
    "cheetah": {"device_model": "Pixel 7 Pro", "device_brand": "google",
                "device_product": "cheetah", "device_manufacturer": "Google",
                "smallest_screen_width": 412, "soc_name": "Tensor G2",
                "ram_size": 12.0, "max_cpu_freq": 2850},
    "panther": {"device_model": "Pixel 7", "device_brand": "google",
                "device_product": "panther", "device_manufacturer": "Google",
                "smallest_screen_width": 412, "soc_name": "Tensor G2",
                "ram_size": 8.0, "max_cpu_freq": 2850},
    "felix": {"device_model": "Pixel Fold", "device_brand": "google",
              "device_product": "felix", "device_manufacturer": "Google",
              "smallest_screen_width": 360, "soc_name": "Tensor G2",
              "ram_size": 12.0, "max_cpu_freq": 2850},
    "lynx": {"device_model": "Pixel 7a", "device_brand": "google",
             "device_product": "lynx", "device_manufacturer": "Google",
             "smallest_screen_width": 412, "soc_name": "Tensor G2",
             "ram_size": 8.0, "max_cpu_freq": 2850},
    "tangorpro": {"device_model": "Pixel Tablet", "device_brand": "google",
                  "device_product": "tangorpro", "device_manufacturer": "Google",
                  "smallest_screen_width": 600, "soc_name": "Tensor G2",
                  "ram_size": 8.0, "max_cpu_freq": 2850},
}

_DEVICE_BUILD_IDS = {
    "caiman": "BE2A.250530.026",
    "shiba": "BE2A.250530.026",
    "oriole": "BE2A.250530.026",
    "raven": "BE2A.250530.026",
    "cheetah": "BE2A.250530.026",
    "panther": "BE2A.250530.026",
    "felix": "BE2A.250530.026",
    "lynx": "BE2A.250530.026",
    "tangorpro": "BE2A.250530.026",
}


def _captcha_ua(device_name: str) -> str:
    hw = DEVICE_HARDWARE.get(device_name, {})
    model = hw.get("device_model", "Pixel 9")
    build_id = _DEVICE_BUILD_IDS.get(device_name, "BE2A.250530.026")
    return (
        f"Mozilla/5.0 (Linux; Android {OS_RELEASE}; {model} "
        f"Build/{build_id}; wv) AppleWebKit/537.36 "
        f"(KHTML, like Gecko) Version/4.0 Chrome/133.0.6943.137 Mobile Safari/537.36"
    )


CAPTCHA_UA = _captcha_ua("caiman")


_NAME_PARTS = [
    "shadow", "dark", "night", "storm", "frost", "blaze", "wolf", "hawk",
    "viper", "nova", "echo", "flux", "pixel", "zen", "drift", "void",
    "lunar", "solar", "neon", "cyber", "iron", "steel", "ruby", "jade",
    "onyx", "bolt", "spark", "ash", "ice", "fire", "wave", "cloud",
    "star", "rain", "mist", "dusk", "dawn", "fang", "claw", "wing",
    "hex", "arc", "rune", "grim", "wild", "swift", "keen", "true",
    "pale", "deep", "calm", "cold", "warm", "soft", "loud", "raw",
    "shy", "sly", "odd", "cool", "epic", "mega", "mini", "ultra",
    "max", "ace", "pro", "neo", "rex", "fox", "lynx", "oryx",
    "atlas", "axel", "blade", "cross", "crane", "delta", "ember",
    "flint", "ghost", "haven", "ivory", "joker", "karma", "lapis",
    "maple", "nexus", "opal", "prism", "quest", "raven", "scout",
    "titan", "umbra", "valor", "wraith", "xenon", "yeti", "zephyr",
]


def _random_username(length: int = 0) -> str:
    a = random.choice(_NAME_PARTS)
    b = random.choice(_NAME_PARTS)
    while b == a:
        b = random.choice(_NAME_PARTS)
    sep = random.choice(["_", "", "."])
    name = f"{a}{sep}{b}"
    suffix_len = random.randint(2, 4)
    suffix = ''.join(random.choice(string.ascii_lowercase) for _ in range(suffix_len))
    name = f"{name}{random.choice(['_', ''])}{suffix}"
    return name[:20]


def _random_password(length: int = 14) -> str:
    chars = string.ascii_letters + string.digits + "!@#$%^&*_+-="
    return ''.join(random.choice(chars) for _ in range(length))


def _human_password_typing_sequence(password: str) -> List[str]:
    """Return the ordered list of partial passwords a real user would validate as
    they type in the password field. Mirrors the HAR cadence:
        typed "C", "Ca", backspaced to "C", then restarted with "G", "Ga", ...,
        "Gange1234_", and the final value was posted TWICE (onBlur + onSubmit
        both fire a validate).

    Model:
      * ~20% chance of a false start: 1-2 random characters typed then
        backspaced one-at-a-time to a single char, then the real password is
        typed from scratch. Backspacing to empty does NOT fire validate.
      * Otherwise: straight character-by-character typing.
      * Final value is always duplicated.
    """
    seq: List[str] = []
    if len(password) >= 4 and random.random() < 0.20:
        wrong_len = random.randint(1, 2)
        wrong = ''.join(random.choices(string.ascii_letters, k=wrong_len))
        for i in range(1, wrong_len + 1):
            seq.append(wrong[:i])
        for i in range(wrong_len - 1, 0, -1):
            seq.append(wrong[:i])
    for i in range(1, len(password) + 1):
        seq.append(password[:i])
    seq.append(password)  # onBlur + onSubmit → final value fires twice
    return seq


def _random_birthday() -> Tuple[int, int, int]:
    return random.randint(1990, 2004), random.randint(1, 12), random.randint(1, 28)


def _generate_client_uuid(base: bytes, seq: int) -> str:
    counter = bytes([0, 0, seq & 0xFF, 0, 0, 0])
    return base64.b64encode(base + counter).decode()


def _make_uuid_base() -> bytes:
    return int(time.time() * 1000).to_bytes(8, "big") + os.urandom(10)


def _generate_nonce() -> str:
    DISCORD_EPOCH = 1420070400000
    ts = int(time.time() * 1000)
    return str((ts - DISCORD_EPOCH) << 22)


def _super_properties(
        device_name: str,
        device_vendor_id: str,
        client_launch_id: str,
        launch_signature: str,
        **extras,
) -> str:
    props = {
        "os": "Android",
        "browser": "Discord Android",
        "device": device_name,
        "system_locale": _ctx_system_locale(),
        "has_client_mods": False,
        "client_version": CLIENT_VERSION,
        "release_channel": "googleRelease",
        "device_vendor_id": device_vendor_id,
        "design_id": DESIGN_ID,
        "browser_user_agent": "",
        "browser_version": "",
        "os_version": OS_VERSION,
        "client_build_number": CLIENT_BUILD,
        "client_event_source": None,
        "client_launch_id": client_launch_id,
        "launch_signature": launch_signature,
        "client_app_state": "active",
    }
    props.update(extras)
    return base64.b64encode(json.dumps(props, separators=(",", ":")).encode()).decode()


def _web_super_properties(web_launch_id: str, web_launch_sig: str,
                          client_app_state: str = "focused",
                          referrer: str = "android-app://com.google.android.gm/",
                          referring_domain: str = "com.google.android.gm",
                          referrer_current: str = "",
                          referring_domain_current: str = "",
                          heartbeat_sid: str = None) -> str:
    _wb = _fetch_web_build()
    props = {
        "os": "Android",
        "browser": "Android Chrome",
        "device": "Android",
        "system_locale": "en-US",
        "has_client_mods": False,
        "browser_user_agent": WEB_UA,
        "browser_version": "146.0.0.0",
        "os_version": "10",
        "referrer": referrer,
        "referring_domain": referring_domain,
        "referrer_current": referrer_current,
        "referring_domain_current": referring_domain_current,
        "release_channel": "stable",
        "client_build_number": _wb if _wb > 0 else 521447,
        "client_event_source": None,
        "client_launch_id": web_launch_id,
        "launch_signature": web_launch_sig,
    }
    if heartbeat_sid:
        props["client_heartbeat_session_id"] = heartbeat_sid
    props["client_app_state"] = client_app_state
    return base64.b64encode(json.dumps(props, separators=(",", ":")).encode()).decode()


def _build_headers(
        device_name: str,
        device_vendor_id: str,
        client_launch_id: str,
        launch_signature: str,
        token: str = None,
        fingerprint: str = None,
        captcha_key: str = None,
        captcha_rqtoken: str = None,
        captcha_session_id: str = None,
        xcontext: str = None,
        **xp_extras,
) -> collections.OrderedDict:
    xp = _super_properties(device_name, device_vendor_id, client_launch_id, launch_signature, **xp_extras)
    parts: List[Tuple[str, str]] = []

    if token:
        if captcha_key:
            parts.append(("x-captcha-key", captcha_key))
            if captcha_rqtoken:
                parts.append(("x-captcha-rqtoken", captcha_rqtoken))
            if captcha_session_id:
                parts.append(("x-captcha-session-id", captcha_session_id))
        parts.append(("authorization", token))
        parts.append(("x-super-properties", xp))
    else:
        if captcha_key:
            parts.append(("x-captcha-key", captcha_key))
            if captcha_rqtoken:
                parts.append(("x-captcha-rqtoken", captcha_rqtoken))
            if captcha_session_id:
                parts.append(("x-captcha-session-id", captcha_session_id))
        parts.append(("x-super-properties", xp))
        if fingerprint:
            parts.append(("x-fingerprint", fingerprint))
        if xcontext:
            parts.append(("x-context-properties", xcontext))

    parts.extend([
        ("accept-language", _ctx_accept_language()),
        ("x-discord-locale", _ctx_discord_locale()),
        ("x-discord-timezone", _ctx_timezone()),
        ("x-debug-options", "bugReporterEnabled"),
        ("User-Agent", UA),
        ("Content-Type", "application/json"),
        # Don't set Accept-Encoding — OkHttp auto-adds "gzip" and auto-
        # decompresses. If we set it, OkHttp treats the response body as raw
        # and the Java proxy returns mangled UTF-8 bytes.
    ])
    return collections.OrderedDict(parts)


def _build_web_headers(web_launch_id: str, web_launch_sig: str,
                       fingerprint=None, referer=None, xcontext=None,
                       include_content_type=True, include_origin=True,
                       token=None,
                       referrer_url: str = "android-app://com.google.android.gm/",
                       referring_domain: str = "com.google.android.gm",
                       referrer_current: str = "",
                       referring_domain_current: str = "",
                       heartbeat_sid: str = None,
                       captcha_key: str = None,
                       captcha_rqtoken: str = None,
                       captcha_session_id: str = None):
    parts = []
    if captcha_rqtoken:
        parts.append(("X-Captcha-Rqtoken", captcha_rqtoken))
    parts.append(("sec-ch-ua-platform", '"Android"'))
    if token:
        parts.append(("Authorization", token))
    if xcontext:
        parts.append(("X-Context-Properties", xcontext))
    parts.append(("X-Debug-Options", "bugReporterEnabled"))
    parts.append(("sec-ch-ua", WEB_SEC_CH_UA))
    parts.append(("sec-ch-ua-mobile", "?1"))
    parts.append(("X-Discord-Timezone", _DISCORD_WEB_TIMEZONE))
    if captcha_key:
        parts.append(("X-Captcha-Key", captcha_key))
    parts.append(("X-Super-Properties", _web_super_properties(
        web_launch_id, web_launch_sig,
        referrer=referrer_url,
        referring_domain=referring_domain,
        referrer_current=referrer_current,
        referring_domain_current=referring_domain_current,
        heartbeat_sid=heartbeat_sid,
    )))
    if captcha_session_id:
        parts.append(("X-Captcha-Session-Id", captcha_session_id))
    # Locale/Accept-Language have to match the register flow, not be hard-
    # coded en-US. A register that ran in fr-FR followed by a verify with
    # en-US headers is a visible mismatch Discord can flag.
    parts.append(("X-Discord-Locale", _ctx_discord_locale()))
    parts.append(("User-Agent", WEB_UA))
    if include_content_type:
        parts.append(("Content-Type", "application/json"))
    if fingerprint:
        parts.append(("X-Fingerprint", fingerprint))
    parts.append(("Accept", "*/*"))
    if include_origin:
        parts.append(("Origin", "https://discord.com"))
    parts.append(("Sec-Fetch-Site", "same-origin"))
    parts.append(("Sec-Fetch-Mode", "cors"))
    parts.append(("Sec-Fetch-Dest", "empty"))
    if referer:
        parts.append(("Referer", referer))
    _al = _ctx_accept_language()
    parts.append(("Accept-Language", f"{_al},{_al.split('-')[0]};q=0.9"))
    return collections.OrderedDict(parts)



class CyberTempMail:
    BASE = "https://api.cybertemp.xyz"

    def __init__(self, api_key: str):
        self.headers = {"X-API-KEY": api_key}
        self.domains = self._get_domains()
        if not self.domains:
            raise RuntimeError("CyberTemp: no domains available")
        print(f"[mail] CyberTemp: {len(self.domains)} domains loaded")

    def _get_domains(self) -> list:
        try:
            r = requests.get(f"{self.BASE}/getDomains?type=discord", headers=self.headers, timeout=10)
            if r.status_code != 200:
                r = requests.get(f"{self.BASE}/getDomains", headers=self.headers, timeout=10)
            r.raise_for_status()
            data = r.json()
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return data.get("domains", [])
        except Exception as e:
            print(f"[mail] getDomains failed: {e}")
        return []

    def create_email(self, username: str) -> str:
        domain = random.choice(self.domains)
        email = f"{username}@{domain}"
        try:
            r = requests.get(
                f"{self.BASE}/getMail",
                params={"email": email, "limit": 1},
                headers=self.headers,
                timeout=15,
            )
            if r.status_code == 403:
                for alt_domain in self.domains:
                    if alt_domain == domain:
                        continue
                    email = f"{username}@{alt_domain}"
                    r2 = requests.get(
                        f"{self.BASE}/getMail",
                        params={"email": email, "limit": 1},
                        headers=self.headers,
                        timeout=15,
                    )
                    if r2.status_code != 403:
                        return email
                raise RuntimeError("CyberTemp: all domains returned 403")
        except requests.RequestException as e:
            raise RuntimeError(f"CyberTemp create failed: {e}")
        return email

    def wait_for_verification(self, email: str, timeout: int = 60) -> Optional[str]:
        start = time.time()
        while time.time() - start < timeout:
            try:
                r = requests.get(
                    f"{self.BASE}/getMail",
                    params={"email": email, "limit": 10},
                    headers=self.headers,
                    timeout=15,
                )
                if r.ok:
                    data = r.json()
                    messages = data if isinstance(data, list) else data.get("emails", [])
                    for msg in messages:
                        body = msg.get("text", "") or msg.get("html", "") or msg.get("body", "")
                        match = re.search(r"upn=([^\s&\"']+)", body)
                        if match:
                            return match.group(1)
            except Exception:
                pass
            time.sleep(3)
        return None

    def delete_mailbox(self, email: str):
        try:
            requests.delete(
                f"{self.BASE}/deleteMail",
                params={"email": email},
                headers=self.headers,
                timeout=10,
            )
        except Exception:
            pass


class HotmailProvider:
    IMAP_HOST = "outlook.office365.com"
    IMAP_PORT = 993
    OAUTH_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"

    def __init__(self, mail_file: str = "io/input/mails.txt", tokens_file: str = None, verbose: bool = False):
        self._lock = threading.Lock()
        self._verbose = verbose
        self._accounts: Dict[str, Dict] = {}
        self._order: List[str] = []
        self._load_mail_file(mail_file)
        if tokens_file:
            self._load_tokens_file(tokens_file)
        if not self._accounts:
            raise RuntimeError(f"HotmailProvider: no accounts loaded")
        self._index = 0
        has_tokens = sum(1 for a in self._accounts.values() if a.get("refresh_token"))
        print(f"[mail] Hotmail: {len(self._accounts)} accounts loaded ({has_tokens} with OAuth tokens)")

    _UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)

    def _load_mail_file(self, path: str):
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or ":" not in line:
                        continue
                    parts = line.split(":")
                    if len(parts) < 2:
                        continue
                    email = parts[0].strip()
                    password = parts[1].strip()
                    acct = {"password": password}

                    if len(parts) >= 4 and self._UUID_RE.match(parts[-1].strip()):
                        acct["client_id"] = parts[-1].strip()
                        acct["refresh_token"] = ":".join(parts[2:-1]).strip()
                    elif len(parts) >= 3:
                        rt = ":".join(parts[2:]).strip()
                        if rt:
                            acct["refresh_token"] = rt
                            acct["client_id"] = "9e5f94bc-e8a4-4e73-b8be-63364c29d753"

                    self._accounts[email] = acct
                    self._order.append(email)
        except FileNotFoundError:
            print(f"[mail] File not found: {path}")

    def _load_tokens_file(self, path: str):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, list):
                return
            loaded = 0
            for item in data:
                email = item.get("Email", "")
                if not email:
                    continue
                if email not in self._accounts:
                    self._accounts[email] = {"password": item.get("Password", "")}
                    self._order.append(email)
                rt = item.get("RefreshToken")
                cid = item.get("ClientId")
                if rt:
                    self._accounts[email]["refresh_token"] = rt
                if cid:
                    self._accounts[email]["client_id"] = cid
                if item.get("Password"):
                    self._accounts[email]["password"] = item["Password"]
                loaded += 1
            print(f"[mail] Loaded OAuth tokens for {loaded} accounts from JSON")
        except FileNotFoundError:
            print(f"[mail] Tokens file not found: {path}")
        except Exception as e:
            print(f"[mail] Failed to load tokens: {e}")

    def create_email(self, username: str) -> str:
        with self._lock:
            if self._index >= len(self._order):
                raise RuntimeError("HotmailProvider: no more email accounts available")
            email = self._order[self._index]
            self._index += 1
        return email

    def recycle_email(self, email: str):
        with self._lock:
            self._order.append(email)

    _CLIENT_IDS = [
        "9e5f94bc-e8a4-4e73-b8be-63364c29d753",
        "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
        "08162f7c-0fd2-4200-a84a-f25a4db0b584",
        "00000002-0000-0ff1-ce00-000000000000",
    ]

    _SCOPES = [
        "https://graph.microsoft.com/Mail.Read offline_access",
        "https://graph.microsoft.com/.default offline_access",
        "https://outlook.office365.com/IMAP.AccessAsUser.All offline_access",
        "https://outlook.office.com/IMAP.AccessAsUser.All offline_access",
        "https://outlook.office365.com/.default offline_access",
        "offline_access",
    ]

    def _get_oauth_access_token(self, email: str, for_graph: bool = False) -> Optional[str]:
        acct = self._accounts.get(email, {})
        rt = acct.get("refresh_token")
        if not rt:
            return None

        cached_cid = acct.get("_working_client_id")
        cached_scope = acct.get("_working_scope")
        if cached_cid and cached_scope:
            return self._try_oauth(email, rt, cached_cid, cached_scope)

        explicit_cid = acct.get("client_id")
        preferred_scopes = self._SCOPES

        combos = []
        if explicit_cid:
            for scope in preferred_scopes:
                combos.append((explicit_cid, scope))
        for cid in self._CLIENT_IDS:
            if cid == explicit_cid:
                continue
            for scope in preferred_scopes:
                combos.append((cid, scope))

        for cid, scope in combos:
            token = self._try_oauth(email, rt, cid, scope)
            if token:
                acct["_working_client_id"] = cid
                acct["_working_scope"] = scope
                return token

        print(f"[mail] OAuth failed for {email}: no working client_id/scope combo found")
        return None

    def _try_oauth(self, email: str, refresh_token: str, client_id: str, scope: str) -> Optional[str]:
        try:
            r = requests.post(self.OAUTH_URL, data={
                "client_id": client_id,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
                "scope": scope,
            }, timeout=15)
            if r.ok:
                rj = r.json()
                token = rj.get("access_token")
                new_rt = rj.get("refresh_token")
                if new_rt:
                    self._accounts[email]["refresh_token"] = new_rt
                return token
            else:
                err = r.json().get("error_description", r.text[:100]) if r.text else str(r.status_code)
                if self._verbose:
                    print(f"[mail] OAuth try cid={client_id[:8]}... scope={scope.split('/')[2][:20] if '/' in scope else scope[:20]}... → {err[:80]}")
        except Exception as e:
            print(f"[mail] OAuth exception: {e}")
        return None

    def _imap_connect(self, email: str):
        import imaplib

        access_token = self._get_oauth_access_token(email)
        if access_token:
            conn = imaplib.IMAP4_SSL(self.IMAP_HOST, self.IMAP_PORT)
            auth_string = f"user={email}\x01auth=Bearer {access_token}\x01\x01"
            try:
                conn.authenticate("XOAUTH2", lambda x: auth_string.encode())
                return conn
            except imaplib.IMAP4.error as e:
                print(f"[mail] OAuth2 IMAP failed for {email}: {e}")
                try:
                    conn.logout()
                except Exception:
                    pass

        password = self._accounts.get(email, {}).get("password")
        if password:
            conn = imaplib.IMAP4_SSL(self.IMAP_HOST, self.IMAP_PORT)
            try:
                conn.login(email, password)
                return conn
            except imaplib.IMAP4.error as e:
                print(f"[mail] Basic IMAP auth failed for {email}: {e}")
                raise
        raise RuntimeError(f"No auth method available for {email}")

    def _graph_poll(self, email: str, access_token: str, debug: bool = False,
                    min_timestamp: float = 0) -> Optional[str]:
        hdrs = {
            "Authorization": f"Bearer {access_token}",
        }
        try:
            r = requests.get(
                "https://graph.microsoft.com/v1.0/me/messages",
                headers=hdrs,
                params={
                    "$orderby": "receivedDateTime desc",
                    "$top": 15,
                    "$select": "body,subject,receivedDateTime,from",
                },
                timeout=15,
            )
            if r.status_code == 401:
                return "__AUTH_FAILED__"
            if not r.ok:
                if debug:
                    if self._verbose:
                        print(f"[mail] Graph: HTTP {r.status_code}")
                return None
            msgs = r.json().get("value", [])
            if debug:
                print(f"[mail] Graph: {len(msgs)} recent msgs")
            for msg in msgs:
                from_addr = msg.get("from", {}).get("emailAddress", {}).get("address", "").lower()
                subject = msg.get("subject", "")
                if "discord" not in from_addr and "discord" not in subject.lower():
                    continue

                if min_timestamp > 0:
                    received = msg.get("receivedDateTime", "")
                    if received:
                        from datetime import datetime, timezone
                        try:
                            dt = datetime.fromisoformat(received.replace("Z", "+00:00"))
                            msg_ts = dt.timestamp()
                            if msg_ts < min_timestamp:
                                if debug:
                                    print(f"[mail] Graph: skipping old Discord email — \"{subject}\" (received {received})")
                                continue
                        except Exception:
                            pass

                subj_lower = subject.lower()
                # Discord sends the verify email in whatever locale the client
                # declared at register time (our x-discord-locale). Since the
                # locale pool covers EU languages, we need to match the verify
                # subject across all of them. Also guard against look-alikes
                # ("disabled for suspicious activity" emails) by checking for
                # known anti-patterns.
                _VERIFY_KW = (
                    "verify", "vérif",          # en, fr
                    "confirm", "confirme",      # en, fr, pt-BR, ro
                    "verific",                  # es, pt (verificar/verificación)
                    "verifica",                 # it (verifica)
                    "bestätig",                 # de (bestätigen/-t)
                    "bekräft", "bekreft", "bekræft",  # sv / nb / da
                    "vahvist",                  # fi (vahvista)
                    "ověř",                     # cs (ověřit)
                    "zweryfik", "potwierdź",    # pl (zweryfikuj/potwierdź)
                    "verifieer", "bevestig",    # nl (verifieer/bevestig)
                    "verifică",                 # ro (verifică)
                )
                _DISABLED_KW = (
                    "disabled", "désactivé", "deshabilitada", "disattivato",
                    "zablokován", "deaktiviert", "inaktiverat", "inaktivert",
                    "deaktiveret", "gedeactiveerd", "wyłączon",
                )
                is_disabled_notice = any(kw in subj_lower for kw in _DISABLED_KW)
                is_verify = (not is_disabled_notice) and any(kw in subj_lower for kw in _VERIFY_KW)
                if not is_verify:
                    if debug:
                        print(f"[mail] Graph: skipping non-verify Discord email — \"{subject}\"")
                    continue

                msg_id = msg.get("id")
                if debug:
                    print(f"[mail] Graph: verification email found — \"{subject}\" (id={msg_id})")

                raw_body = None
                if msg_id:
                    try:
                        r2 = requests.get(
                            f"https://graph.microsoft.com/v1.0/me/messages/{msg_id}/$value",
                            headers={"Authorization": f"Bearer {access_token}"},
                            timeout=15,
                        )
                        if r2.ok:
                            raw_body = r2.content
                    except Exception:
                        pass

                if raw_body:
                    import email as email_lib
                    mime_msg = email_lib.message_from_bytes(raw_body)
                    all_text = ""
                    for part in mime_msg.walk():
                        ct = part.get_content_type()
                        if ct in ("text/plain", "text/html"):
                            payload = part.get_payload(decode=True)
                            if payload:
                                text = payload.decode("utf-8", errors="ignore")
                                match = re.search(r"upn=([^\s&\"'<>]+)", text)
                                if match:
                                    upn_val = match.group(1)
                                    if debug:
                                        if self._verbose:
                                            print(f"[mail] Graph: UPN from MIME {ct} ({len(upn_val)} chars): {upn_val[:60]}...")
                                    return upn_val
                                all_text += text
                    if debug and not all_text:
                        if self._verbose:
                            print(f"[mail] Graph: no text found in MIME parts")
                else:
                    body = msg.get("body", {}).get("content", "")
                    import html as _html_mod
                    body_clean = _html_mod.unescape(body)
                    match = re.search(r"upn=([^\s&\"'<>]+)", body_clean)
                    if match:
                        return match.group(1)
                    if debug:
                        if self._verbose:
                            print(f"[mail] Graph: raw MIME failed, HTML body has no UPN")
                match2 = re.search(r"https://click\.discord\.com/ls/click\?upn=([^\s&\"'<]+)", body)
                if match2:
                    return match2.group(1)
                match3 = re.search(r"discord\.com/verify#/([^\s&\"'<]+)", body)
                if match3:
                    return match3.group(1)
                if debug:
                    print(f"[mail] Graph: no verify link found in body, snippet: {body[500:700]}")
        except Exception as e:
            if debug:
                print(f"[mail] Graph error: {e}")
        return None

    def wait_for_verification(self, email: str, timeout: int = 90) -> Optional[str]:
        import imaplib
        import email as email_lib

        acct = self._accounts.get(email, {})
        has_rt = bool(acct.get("refresh_token"))

        search_start = time.time() - 30

        if has_rt:
            graph_token = self._get_oauth_access_token(email, for_graph=True)
            if graph_token:
                if self._verbose:
                    print(f"[mail] Graph API connected for {email}")
                start = time.time()
                poll = 0
                while time.time() - start < timeout:
                    poll += 1
                    result = self._graph_poll(email, graph_token, debug=(poll <= 3),
                                              min_timestamp=search_start)
                    if result == "__AUTH_FAILED__":
                        print(f"[mail] Graph token expired for {email}, falling back to IMAP")
                        break
                    if result:
                        print(f"[mail] Found verification UPN for {email} (Graph API)")
                        return result
                    if poll <= 3:
                        elapsed = int(time.time() - start)
                        print(f"[mail] {email}: Graph poll #{poll} ({elapsed}s) — no Discord verify yet")
                    time.sleep(5)
                else:
                    print(f"[mail] Timeout ({timeout}s) for {email} — no Discord verification email found")
                    return None

        start = time.time()
        poll = 0
        while time.time() - start < timeout:
            poll += 1
            conn = None
            try:
                conn = self._imap_connect(email)
                if poll == 1:
                    print(f"[mail] IMAP connected for {email}")

                folders_to_check = ["INBOX", "Junk"]
                if poll == 1:
                    try:
                        _, folder_list = conn.list()
                        if folder_list:
                            print(f"[mail] Available folders for {email}:")
                            for f in folder_list:
                                if f:
                                    decoded = f.decode() if isinstance(f, bytes) else str(f)
                                    print(f"[mail]   {decoded}")
                                    parts = decoded.rsplit('"', 2)
                                    if len(parts) >= 2:
                                        fname = parts[-1].strip()
                                        if fname and fname not in folders_to_check:
                                            folders_to_check.append(fname)
                    except Exception as e:
                        print(f"[mail] Failed to list folders: {e}")
                    print(f"[mail] Checking folders: {folders_to_check}")

                total_msgs = 0
                for folder in folders_to_check:
                    try:
                        status, data = conn.select(folder)
                        if status != "OK":
                            if poll == 1:
                                print(f"[mail] Folder {folder}: select failed ({status})")
                            continue
                        if poll == 1:
                            msg_count = int(data[0]) if data and data[0] else 0
                            print(f"[mail] Folder {folder}: {msg_count} messages")
                    except Exception as e:
                        if poll == 1:
                            print(f"[mail] Folder {folder}: error ({e})")
                        continue

                    _, all_msg_ids = conn.search(None, "ALL")
                    if not all_msg_ids[0]:
                        continue
                    ids = all_msg_ids[0].split()
                    total_msgs += len(ids)
                    recent_ids = ids[-10:]

                    for mid in reversed(recent_ids):
                        try:
                            _, msg_data = conn.fetch(mid, "(BODY.PEEK[])")
                            if not msg_data or not msg_data[0]:
                                continue
                            raw = msg_data[0][1] if isinstance(msg_data[0], tuple) else msg_data[0]
                            if isinstance(raw, int) or not raw:
                                continue
                            raw_str = raw.decode("utf-8", errors="ignore") if isinstance(raw, bytes) else str(raw)

                            subj_match = re.search(r"Subject:\s*(.+?)(?:\r?\n\S|\r?\n\r?\n)", raw_str)
                            imap_subject = subj_match.group(1).strip() if subj_match else ""
                            subj_lower = imap_subject.lower()
                            # Same multi-locale keyword set as the Graph path.
                            _VERIFY_KW = (
                                "verify", "vérif",
                                "confirm", "confirme",
                                "verific", "verifica",
                                "bestätig",
                                "bekräft", "bekreft", "bekræft",
                                "vahvist",
                                "ověř",
                                "zweryfik", "potwierdź",
                                "verifieer", "bevestig",
                                "verifică",
                            )
                            _DISABLED_KW = (
                                "disabled", "désactivé", "deshabilitada",
                                "disattivato", "zablokován", "deaktiviert",
                                "inaktiverat", "inaktivert", "deaktiveret",
                                "gedeactiveerd", "wyłączon",
                            )
                            is_disabled = any(kw in subj_lower for kw in _DISABLED_KW)
                            is_verify = (not is_disabled) and any(kw in subj_lower for kw in _VERIFY_KW)
                            if not is_verify:
                                if "discord" in raw_str.lower()[:2000] and poll == 1:
                                    print(f"[mail] IMAP: skipping non-verify Discord email — \"{imap_subject[:60]}\"")
                                continue

                            match = re.search(r"upn=([^\s&\"'<>]+)", raw_str)
                            if match:
                                print(f"[mail] Found verification UPN for {email} in {folder} — \"{imap_subject[:60]}\"")
                                try:
                                    conn.logout()
                                except Exception:
                                    pass
                                return match.group(1)

                            match2 = re.search(r"click\.discord\.com/ls/click\?upn=([^\s&\"'<>]+)", raw_str)
                            if match2:
                                print(f"[mail] Found verification URL for {email} in {folder} — \"{imap_subject[:60]}\"")
                                try:
                                    conn.logout()
                                except Exception:
                                    pass
                                return "__FULLURL__https://click.discord.com/ls/click?upn=" + match2.group(1)
                        except Exception:
                            continue

                if poll <= 3:
                    elapsed = int(time.time() - start)
                    print(f"[mail] {email}: poll #{poll} ({elapsed}s) — {total_msgs} total msgs, no Discord verify yet")

                conn.logout()
            except Exception as e:
                err_str = str(e)
                if "AUTHENTICATE" in err_str or "LOGIN" in err_str or "AuthFailed" in err_str or "BasicAuthBlocked" in err_str:
                    print(f"[mail] Auth failed for {email}: {e}")
                    return None
                if poll <= 2:
                    print(f"[mail] IMAP error for {email}: {e}")
            finally:
                if conn:
                    try:
                        conn.logout()
                    except Exception:
                        pass
            time.sleep(5)
        print(f"[mail] Timeout ({timeout}s) for {email} — no Discord verification email found")
        return None

    def delete_mailbox(self, email: str):
        pass


class ZeusProvider(HotmailProvider):
    ZEUS_API = "https://api.zeus-x.ru"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self._lock = threading.Lock()
        self._verbose = False
        self._accounts: Dict[str, Dict] = {}
        self._order: List[str] = []
        self._index = 0
        stock = self._check_stock()
        if stock:
            print(f"[mail] Zeus: HOTMAIL={stock.get('HOTMAIL', 0)}, OUTLOOK={stock.get('OUTLOOK', 0)}")
        else:
            print("[mail] Zeus: connected (stock check failed, will retry on purchase)")

    def _check_stock(self) -> Optional[Dict[str, int]]:
        try:
            r = requests.get(f"{self.ZEUS_API}/instock", timeout=10)
            if r.status_code != 200:
                return None
            data = r.json()
            if data.get("Code") != 0:
                return None
            items = data.get("Data", [])
            result = {}
            for item in items:
                code = item.get("AccountCode", "")
                if code in ("HOTMAIL", "OUTLOOK"):
                    result[code] = item.get("Instock", 0)
            return result
        except Exception:
            return None

    def _buy_account(self) -> Tuple[str, Dict]:
        stock = self._check_stock()
        if not stock:
            raise RuntimeError("Zeus: failed to check stock")
        hotmail_stock = stock.get("HOTMAIL", 0)
        outlook_stock = stock.get("OUTLOOK", 0)
        if hotmail_stock == 0 and outlook_stock == 0:
            raise RuntimeError("Zeus: no HOTMAIL or OUTLOOK in stock")
        accountcode = "HOTMAIL" if hotmail_stock >= outlook_stock else "OUTLOOK"

        r = requests.get(
            f"{self.ZEUS_API}/purchase",
            params={"apikey": self.api_key, "accountcode": accountcode, "quantity": 1},
            timeout=15,
        )
        if r.status_code != 200:
            raise RuntimeError(f"Zeus: purchase API error {r.status_code}")
        data = r.json()
        if data.get("Code") != 0:
            raise RuntimeError(f"Zeus: {data.get('Message', 'unknown error')}")

        acc = data["Data"]["Accounts"][0]
        email = acc.get("Email")
        password = acc.get("Password")
        refresh_token = acc.get("RefreshToken")
        client_id = acc.get("ClientId")
        if not all([email, password, refresh_token, client_id]):
            raise RuntimeError("Zeus: missing fields in purchased account")

        return email, {
            "password": password,
            "refresh_token": refresh_token,
            "client_id": client_id,
        }

    def create_email(self, username: str) -> str:
        email, acct = self._buy_account()
        with self._lock:
            self._accounts[email] = acct
            self._order.append(email)
        print(f"[mail] Zeus: bought {email}")
        return email

    def recycle_email(self, email: str):
        pass


class HeroSMS:
    BASE = "https://hero-sms.com/stubs/handler_api.php"

    def __init__(self, api_key: str, service: str = "ds", country: int = 6):
        self.api_key = api_key
        self.service = service
        self.country = country

    def _get(self, params: dict) -> str:
        params["api_key"] = self.api_key
        r = requests.get(self.BASE, params=params, timeout=30)
        r.raise_for_status()
        return r.text

    def request_number(self) -> Tuple[int, str]:
        text = self._get({"action": "getNumber", "service": self.service, "country": self.country})
        if not text.startswith("ACCESS_NUMBER:"):
            raise RuntimeError(f"HeroSMS getNumber failed: {text}")
        _, act_id, phone = text.split(":", 2)
        return int(act_id), phone

    def set_status(self, act_id: int, status: int) -> str:
        return self._get({"action": "setStatus", "id": act_id, "status": status})

    def wait_for_code(self, act_id: int, timeout: int = 180) -> str:
        start = time.time()
        while time.time() - start < timeout:
            text = self._get({"action": "getStatus", "id": act_id})
            if text.startswith("STATUS_OK:"):
                return text.split(":", 1)[1]
            if text.startswith("STATUS_CANCEL"):
                raise RuntimeError(f"HeroSMS cancelled: {text}")
            time.sleep(5)
        raise TimeoutError("HeroSMS: timeout waiting for SMS")


class GatewayKeepalive:

    URL_ZSTD = "wss://gateway.discord.gg/?encoding=json&v=9&compress=zstd-stream"
    URL_ZLIB = "wss://gateway.discord.gg/?encoding=json&v=9&compress=zlib-stream"
    URL_NOCOMPRESS = "wss://gateway.discord.gg/?encoding=json&v=9"

    def __init__(self, token: str, device_name: str, device_vendor_id: str,
                 client_launch_id: str, launch_signature: str,
                 heartbeat_session_id: str = None, client_launch_id_for_hb: str = None,
                 proxy_raw: str = None, fingerprint_mode: str = "android",
                 use_okhttp: bool = False):
        self.token = token
        self.device_name = device_name
        self.device_vendor_id = device_vendor_id
        self.client_launch_id = client_launch_id
        self.launch_signature = launch_signature
        self.heartbeat_session_id = heartbeat_session_id or str(uuid.uuid4())
        self.client_launch_id_for_hb = client_launch_id_for_hb or client_launch_id
        self.fingerprint_mode = fingerprint_mode
        self._use_okhttp = use_okhttp
        self._proxy_raw = proxy_raw
        self._ws = None
        self._ws_id = None
        self._mgr = None
        self._stop = threading.Event()
        self._seq = None
        self._identified = False
        self._resuming = False
        self._resume_gateway_url = None
        self._use_zstd = _HAS_ZSTD
        if self._use_zstd:
            self._zstd_decompressor = zstandard.ZstdDecompressor().decompressobj()
        elif not use_okhttp:
            self._inflator = zlib.decompressobj()
        self._session_id = None
        self._analytics_token = None
        self._ws_headers = {"User-Agent": "okhttp/4.11.0", "Origin": "discord.com"}
        self._run_kwargs = {}
        if proxy_raw and not use_okhttp:
            self._setup_proxy(proxy_raw)

    def _setup_proxy(self, proxy_raw: str):
        try:
            if "@" in proxy_raw:
                auth_part, host_part = proxy_raw.rsplit("@", 1)
                host, port = host_part.split(":")
                self._run_kwargs["http_proxy_host"] = host
                self._run_kwargs["http_proxy_port"] = int(port)
                self._run_kwargs["http_proxy_auth"] = (auth_part.split(":")[0], ":".join(auth_part.split(":")[1:]))
            else:
                parts = proxy_raw.replace("http://", "").replace("https://", "").split(":")
                if len(parts) >= 2:
                    self._run_kwargs["http_proxy_host"] = parts[0]
                    self._run_kwargs["http_proxy_port"] = int(parts[1])
                if len(parts) == 4:
                    self._run_kwargs["http_proxy_auth"] = (parts[2], parts[3])
        except Exception:
            pass

    @property
    def session_id(self):
        return self._session_id

    @property
    def analytics_token(self):
        return self._analytics_token

    def _okhttp_send(self, text: str):
        if not self._ws_id or not self._mgr:
            return
        import urllib.request as _ur
        payload = _json_module.dumps({"id": self._ws_id, "text": text},
                                     separators=(",", ":")).encode()
        req = _ur.Request(
            f"http://127.0.0.1:{self._port}/ws/send",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with _ur.urlopen(req, timeout=5) as r:
                pass
        except Exception:
            pass

    def _okhttp_recv(self, timeout: int = 10) -> Optional[str]:
        if not self._ws_id or not self._mgr:
            return None
        import urllib.request as _ur
        payload = _json_module.dumps({"id": self._ws_id, "timeout": timeout},
                                     separators=(",", ":")).encode()
        req = _ur.Request(
            f"http://127.0.0.1:{self._port}/ws/recv",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with _ur.urlopen(req, timeout=timeout + 5) as r:
                result = _json_module.loads(r.read().decode())
                if "text" in result:
                    return result["text"]
                return None
        except Exception:
            return None

    def _okhttp_close(self):
        if not self._ws_id or not self._mgr:
            return
        import urllib.request as _ur
        try:
            payload = _json_module.dumps({"id": self._ws_id, "code": 1000, "reason": ""},
                                         separators=(",", ":")).encode()
            req = _ur.Request(
                f"http://127.0.0.1:{self._port}/ws/close",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with _ur.urlopen(req, timeout=5) as r:
                pass
        except Exception:
            pass
        self._ws_id = None

    def _okhttp_open(self, url: str = None) -> bool:
        import urllib.request as _ur
        self._mgr = _OkHttpProxyManager.get()
        self._port = self._mgr.get_dedicated_port()

        ws_url = url or self.URL_NOCOMPRESS
        headers = [["User-Agent", "okhttp/4.11.0"]]

        proxy_obj = None
        if self._proxy_raw:
            proxy_url = AccountGenerator._normalize_proxy(self._proxy_raw)
            parsed = urlparse(proxy_url)
            proxy_obj = {
                "type": (parsed.scheme or "http").replace("https", "http"),
                "host": parsed.hostname,
                "port": parsed.port,
            }
            if parsed.username:
                proxy_obj["user"] = parsed.username
                proxy_obj["pass"] = parsed.password or ""

        spec = {"url": ws_url, "headers": headers, "timeout": 30}
        if proxy_obj:
            spec["proxy"] = proxy_obj

        payload = _json_module.dumps(spec, separators=(",", ":")).encode()
        req = _ur.Request(
            f"http://127.0.0.1:{self._port}/ws/open",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with _ur.urlopen(req, timeout=35) as r:
                result = _json_module.loads(r.read().decode())
                if "error" in result:
                    return False
                self._ws_id = result["id"]
                return True
        except Exception:
            return False

    def _gw_send(self, payload_dict: dict):
        text = json.dumps(payload_dict)
        if self._use_okhttp and self._ws_id:
            self._okhttp_send(text)
        elif self._ws:
            try:
                self._ws.send(text)
            except Exception:
                pass

    def _decompress(self, data: bytes) -> str:
        if self._use_zstd:
            try:
                buf = self._zstd_decompressor.decompress(data)
                return buf.decode("utf-8") if buf else ""
            except Exception:
                return ""
        else:
            buf = self._inflator.decompress(data)
            if len(data) < 4 or data[-4:] != b'\x00\x00\xff\xff':
                return ""
            return buf.decode("utf-8")

    def _on_message(self, ws, message):
        try:
            text = self._decompress(message) if isinstance(message, bytes) else message
            if not text:
                return
            payload = json.loads(text)
            op, d, s = payload.get("op"), payload.get("d"), payload.get("s")
            if s is not None:
                self._seq = s
            if op == 10:
                self._heartbeat_interval = d["heartbeat_interval"] / 1000.0
                if self._resuming:
                    self._gw_send(json.loads(self._resume_payload))
                else:
                    self._send_identify()
                self._start_heartbeat()
            elif op == 0 and payload.get("t") == "READY":
                self._identified = True
                self._session_id = d.get("session_id")
                self._resume_gateway_url = d.get("resume_gateway_url")
                self._analytics_token = d.get("analytics_token")
                self._send_post_ready_ops()
                # HAR cadence: op=3 online fires ~immediately after READY, then
                # op=3 idle ~211 ms later (the app backgrounds itself while the
                # user is on the post-register landing). Previous 3-5s / 10-14s
                # delays made the client look idle-from-the-start.
                threading.Timer(random.uniform(0.10, 0.30), self._send_presence_online).start()
                threading.Timer(random.uniform(0.35, 0.65), self._send_presence_idle).start()
            elif op == 0 and payload.get("t") == "RESUMED":
                self._identified = True
                # Same pattern as READY — online first, idle ~211 ms later.
                self._send_presence_online()
                threading.Timer(random.uniform(0.18, 0.32), self._send_presence_idle).start()
            elif op == 9:
                self._stop.set()
        except Exception:
            pass

    def _send_identify(self):
        props = {
            "os": "Android",
            "browser": "Discord Android",
            "device": self.device_name,
            "system_locale": _ctx_system_locale(),
            "has_client_mods": False,
            "client_version": CLIENT_VERSION,
            "release_channel": "googleRelease",
            "device_vendor_id": self.device_vendor_id,
            "design_id": DESIGN_ID,
            "browser_user_agent": "",
            "browser_version": "",
            "os_version": OS_VERSION,
            "client_build_number": CLIENT_BUILD,
            "client_event_source": None,
            "client_launch_id": self.client_launch_id,
            "launch_signature": self.launch_signature,
            "client_app_state": "active",
            "is_fast_connect": False,
            "gateway_connect_reasons": "AppContainer:main",
        }
        identify = {
            "op": 2,
            "d": {
                "token": self.token,
                "capabilities": GATEWAY_CAPABILITIES,
                "properties": props,
                "presence": {"status": "unknown", "since": 0, "activities": [], "afk": False},
                "compress": False,
                "client_state": {
                    "guild_versions": {},
                },
            },
        }
        self._gw_send(identify)
        self._gw_send({"op": 40, "d": {"seq": 0, "qos": {"active": True, "ver": 27, "reasons": ["foregrounded"]}}})

    def _send_post_ready_ops(self):
        self._gw_send({
            "op": 4,
            "d": {
                "guild_id": None,
                "channel_id": None,
                "self_mute": True,
                "self_deaf": False,
                "self_video": False,
                "flags": 2,
            },
        })
        self._gw_send({
            "op": 3,
            "d": {
                "status": "idle",
                "since": int(time.time() * 1000),
                "activities": [],
                "afk": True,
            },
        })
        self._gw_send({
            "op": 41,
            "d": {
                "initialization_timestamp": int(time.time() * 1000),
                "session_id": self.heartbeat_session_id,
                "client_launch_id": self.client_launch_id_for_hb,
            },
        })
        self._gw_send({
            "op": 40,
            "d": {
                "seq": 1,
                "qos": {
                    "active": True,
                    "ver": 27,
                    "reasons": ["foregrounded"],
                },
            },
        })

    def _send_presence_idle(self):
        self._gw_send({
            "op": 3,
            "d": {
                "status": "idle",
                "since": int(time.time() * 1000),
                "activities": [],
                "afk": True,
            },
        })

    def _send_presence_online(self):
        self._gw_send({
            "op": 3,
            "d": {
                "status": "online",
                "since": 0,
                "activities": [],
                "afk": False,
            },
        })

    def _start_heartbeat(self):
        def loop():
            self._stop.wait(self._heartbeat_interval * 0.5)
            while not self._stop.is_set():
                self._gw_send({"op": 1, "d": self._seq})
                if self._stop.wait(self._heartbeat_interval):
                    break
        threading.Thread(target=loop, daemon=True).start()

    def _on_close(self, ws, close_code, close_msg):
        if self._stop.is_set():
            return
        if not self._session_id:
            self._stop.set()
            return
        threading.Thread(target=self._auto_resume, daemon=True).start()

    def _auto_resume(self):
        time.sleep(random.uniform(1.0, 3.0))
        if self._stop.is_set():
            return
        try:
            self._resuming = True
            self._identified = False

            self._resume_payload = json.dumps({
                "op": 6,
                "d": {
                    "token": self.token,
                    "session_id": self._session_id,
                    "seq": self._seq,
                },
            })

            if self._use_okhttp:
                if self._use_zstd:
                    self._zstd_decompressor = zstandard.ZstdDecompressor().decompressobj()
                compress_suffix = "&compress=zstd-stream" if self._use_zstd else "&compress=zlib-stream"
                resume_url = getattr(self, '_resume_gateway_url', None)
                if resume_url:
                    resume_url = resume_url + "?encoding=json&v=9" + compress_suffix
                else:
                    resume_url = self.URL_ZSTD if self._use_zstd else self.URL_ZLIB
                if self._okhttp_open(url=resume_url):
                    threading.Thread(target=self._okhttp_recv_loop, daemon=True).start()
            else:
                if self._use_zstd:
                    self._zstd_decompressor = zstandard.ZstdDecompressor().decompressobj()
                else:
                    self._inflator = zlib.decompressobj()

                url = getattr(self, '_resume_gateway_url', None)
                if url:
                    suffix = "?encoding=json&v=9&compress=zstd-stream" if self._use_zstd else "?encoding=json&v=9&compress=zlib-stream"
                    url = url + suffix
                else:
                    url = self.URL_ZSTD if self._use_zstd else self.URL_ZLIB

                self._ws = websocket.WebSocketApp(
                    url,
                    on_message=self._on_message,
                    on_error=lambda ws, e: None,
                    on_close=self._on_close,
                    header=self._ws_headers,
                )
                threading.Thread(target=self._ws.run_forever, daemon=True, kwargs=self._run_kwargs).start()
        except Exception:
            pass

    def _okhttp_recv_loop(self):
        while not self._stop.is_set():
            msg = self._okhttp_recv(timeout=60)
            if msg is None:
                if self._stop.is_set():
                    break
                if self._session_id and not self._stop.is_set():
                    threading.Thread(target=self._auto_resume, daemon=True).start()
                break
            if msg.startswith("__BIN__"):
                try:
                    raw = base64.b64decode(msg[7:])
                    if self._use_zstd:
                        text = self._zstd_decompressor.decompress(raw)
                        text = text.decode("utf-8") if isinstance(text, bytes) else text
                    else:
                        text = self._decompress(raw)
                except Exception:
                    continue
                if text:
                    self._on_message(None, text)
            else:
                self._on_message(None, msg)

    def start(self) -> bool:
        self._stop.clear()
        self._resuming = False
        self._resume_gateway_url = None

        if self._use_okhttp:
            if self._use_zstd:
                self._zstd_decompressor = zstandard.ZstdDecompressor().decompressobj()
            ws_url = self.URL_ZSTD if self._use_zstd else self.URL_ZLIB
            if not self._okhttp_open(url=ws_url):
                return False
            threading.Thread(target=self._okhttp_recv_loop, daemon=True).start()
        else:
            if self._use_zstd:
                self._zstd_decompressor = zstandard.ZstdDecompressor().decompressobj()
            else:
                self._inflator = zlib.decompressobj()
            url = self.URL_ZSTD if self._use_zstd else self.URL_ZLIB
            self._ws = websocket.WebSocketApp(
                url,
                on_message=self._on_message,
                on_error=lambda ws, e: None,
                on_close=self._on_close,
                header=self._ws_headers,
            )
            threading.Thread(target=self._ws.run_forever, daemon=True, kwargs=self._run_kwargs).start()

        for _ in range(100):
            if self._identified:
                return True
            if self._stop.is_set():
                return False
            time.sleep(0.1)
        return False

    def resume(self) -> bool:
        if not self._session_id:
            return False
        old_session = self._session_id
        old_seq = self._seq

        self._stop.set()
        if self._use_okhttp:
            self._okhttp_close()
        else:
            try:
                if self._ws:
                    self._ws.close()
            except Exception:
                pass
        time.sleep(0.5)

        self._stop.clear()
        self._resuming = True
        self._identified = False

        self._resume_payload = json.dumps({
            "op": 6,
            "d": {
                "token": self.token,
                "session_id": old_session,
                "seq": old_seq,
            },
        })

        if self._use_okhttp:
            if self._use_zstd:
                self._zstd_decompressor = zstandard.ZstdDecompressor().decompressobj()
            resume_url = getattr(self, '_resume_gateway_url', None)
            compress_suffix = "&compress=zstd-stream" if self._use_zstd else "&compress=zlib-stream"
            if resume_url:
                resume_url = resume_url + "?encoding=json&v=9" + compress_suffix
            else:
                resume_url = self.URL_ZSTD if self._use_zstd else self.URL_ZLIB
            if not self._okhttp_open(url=resume_url):
                return False
            threading.Thread(target=self._okhttp_recv_loop, daemon=True).start()
        else:
            if self._use_zstd:
                self._zstd_decompressor = zstandard.ZstdDecompressor().decompressobj()
            else:
                self._inflator = zlib.decompressobj()

            url = getattr(self, '_resume_gateway_url', None)
            if url:
                suffix = "?encoding=json&v=9&compress=zstd-stream" if self._use_zstd else "?encoding=json&v=9&compress=zlib-stream"
                url = url + suffix
            else:
                url = self.URL_ZSTD if self._use_zstd else self.URL_ZLIB

            self._ws = websocket.WebSocketApp(
                url,
                on_message=self._on_message,
                on_error=lambda ws, e: None,
                on_close=self._on_close,
                header=self._ws_headers,
            )
            threading.Thread(target=self._ws.run_forever, daemon=True, kwargs=self._run_kwargs).start()

        for _ in range(100):
            if self._identified:
                return True
            if self._stop.is_set():
                return False
            time.sleep(0.1)
        return False

    def stop(self, graceful=True):
        if graceful:
            self._send_presence_idle()
            self._stop.set()
        else:
            self._stop.set()
            if self._use_okhttp:
                self._okhttp_close()
            else:
                try:
                    if self._ws:
                        self._ws.close()
                except Exception:
                    pass


class _PreAuthGateway:

    URL_NOCOMPRESS = "wss://gateway.discord.gg/?encoding=json&v=9"

    def __init__(self, proxy_raw: str = None, fingerprint_mode: str = "android",
                 use_okhttp: bool = False):
        self._stop = threading.Event()
        self._ws_id = None
        self._ws = None
        self._hb_interval = 41.25
        self.fingerprint_mode = fingerprint_mode
        self._use_okhttp = use_okhttp
        self._proxy_raw = proxy_raw
        self._mgr = None
        self._use_zstd = _HAS_ZSTD
        if not use_okhttp:
            if self._use_zstd:
                self._decompressor = zstandard.ZstdDecompressor().decompressobj()
            else:
                self._inflator = zlib.decompressobj()
        self._run_kwargs: dict = {}
        if proxy_raw and not use_okhttp:
            self._setup_proxy(proxy_raw)

    def _setup_proxy(self, proxy_raw: str):
        try:
            norm = AccountGenerator._normalize_proxy(proxy_raw)
            parsed = urlparse(norm)
            if parsed.hostname:
                self._run_kwargs["http_proxy_host"] = parsed.hostname
                self._run_kwargs["http_proxy_port"] = parsed.port
                if parsed.username:
                    self._run_kwargs["http_proxy_auth"] = (
                        parsed.username, parsed.password or "")
        except Exception:
            pass

    def _decompress(self, data: bytes) -> str:
        if self._use_zstd:
            try:
                return self._decompressor.decompress(data).decode("utf-8")
            except Exception:
                return ""
        else:
            buf = self._inflator.decompress(data)
            if len(data) < 4 or data[-4:] != b'\x00\x00\xff\xff':
                return ""
            return buf.decode("utf-8")

    def _on_message(self, ws, message):
        try:
            text = self._decompress(message) if isinstance(message, bytes) else message
            if not text:
                return
            payload = json.loads(text)
            if payload.get("op") == 10:
                self._hb_interval = payload["d"]["heartbeat_interval"] / 1000.0
                self._start_heartbeat_python()
        except Exception:
            pass

    def _start_heartbeat_python(self):
        def loop():
            self._stop.wait(self._hb_interval * random.uniform(0.3, 0.6))
            while not self._stop.is_set():
                try:
                    self._ws.send(json.dumps({"op": 1, "d": None}))
                except Exception:
                    break
                if self._stop.wait(self._hb_interval):
                    break
        threading.Thread(target=loop, daemon=True).start()

    def _start_heartbeat_okhttp(self):
        def loop():
            self._stop.wait(self._hb_interval * random.uniform(0.3, 0.6))
            while not self._stop.is_set():
                try:
                    self._ws_send(json.dumps({"op": 1, "d": None}))
                except Exception:
                    break
                if self._stop.wait(self._hb_interval):
                    break
        threading.Thread(target=loop, daemon=True).start()

    def _ws_send(self, text: str):
        if not self._ws_id or not self._mgr:
            return
        import urllib.request as _ur
        payload = _json_module.dumps({"id": self._ws_id, "text": text},
                                     separators=(",", ":")).encode()
        req = _ur.Request(
            f"http://127.0.0.1:{self._port}/ws/send",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with _ur.urlopen(req, timeout=5) as r:
                pass
        except Exception:
            pass

    def _ws_recv(self, timeout: int = 10) -> Optional[str]:
        if not self._ws_id or not self._mgr:
            return None
        import urllib.request as _ur
        payload = _json_module.dumps({"id": self._ws_id, "timeout": timeout},
                                     separators=(",", ":")).encode()
        req = _ur.Request(
            f"http://127.0.0.1:{self._port}/ws/recv",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with _ur.urlopen(req, timeout=timeout + 5) as r:
                result = _json_module.loads(r.read().decode())
                if "text" in result:
                    return result["text"]
                return None
        except Exception:
            return None

    def start(self):
        if self._use_okhttp:
            self._start_okhttp()
        else:
            self._start_python()

    def _start_okhttp(self):
        import urllib.request as _ur
        self._mgr = _OkHttpProxyManager.get()
        self._port = self._mgr.get_dedicated_port()

        url = GatewayKeepalive.URL_ZSTD if self._use_zstd else GatewayKeepalive.URL_ZLIB
        if self._use_zstd:
            self._decompressor = zstandard.ZstdDecompressor().decompressobj()
        else:
            self._decompressor_zlib = zlib.decompressobj()
        headers = [["User-Agent", "okhttp/4.11.0"]]

        proxy_obj = None
        if self._proxy_raw:
            proxy_url = AccountGenerator._normalize_proxy(self._proxy_raw)
            parsed = urlparse(proxy_url)
            proxy_obj = {
                "type": (parsed.scheme or "http").replace("https", "http"),
                "host": parsed.hostname,
                "port": parsed.port,
            }
            if parsed.username:
                proxy_obj["user"] = parsed.username
                proxy_obj["pass"] = parsed.password or ""

        spec = {"url": url, "headers": headers, "timeout": 30}
        if proxy_obj:
            spec["proxy"] = proxy_obj

        payload = _json_module.dumps(spec, separators=(",", ":")).encode()
        req = _ur.Request(
            f"http://127.0.0.1:{self._port}/ws/open",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with _ur.urlopen(req, timeout=35) as r:
                result = _json_module.loads(r.read().decode())
                if "error" in result:
                    # Silenced: pre-auth gateway is a warmup; a failure here is
                    # handled by falling through to the auth'd Gateway IDENTIFY.
                    return
                self._ws_id = result["id"]
        except Exception:
            # Same rationale — don't spam on pre-auth WS errors.
            return

        def recv_loop():
            msg = self._ws_recv(timeout=10)
            if msg:
                try:
                    if msg.startswith("__BIN__"):
                        raw = base64.b64decode(msg[7:])
                        if self._use_zstd:
                            text = self._decompressor.decompress(raw)
                            text = text.decode("utf-8") if isinstance(text, bytes) else text
                        else:
                            buf = self._decompressor_zlib.decompress(raw)
                            if len(raw) >= 4 and raw[-4:] == b'\x00\x00\xff\xff':
                                text = buf.decode("utf-8")
                            else:
                                text = ""
                        msg = text
                    if msg:
                        payload = json.loads(msg)
                        if payload.get("op") == 10:
                            self._hb_interval = payload["d"]["heartbeat_interval"] / 1000.0
                            self._start_heartbeat_okhttp()
                except Exception:
                    pass
        threading.Thread(target=recv_loop, daemon=True).start()
        time.sleep(random.uniform(0.5, 1.0))

    def _start_python(self):
        url = GatewayKeepalive.URL_ZSTD if self._use_zstd else GatewayKeepalive.URL_ZLIB
        ws_headers = {"User-Agent": "okhttp/4.11.0", "Origin": "discord.com"}
        self._ws = websocket.WebSocketApp(
            url,
            on_message=self._on_message,
            on_error=lambda ws, e: None,
            on_close=lambda ws, cc, cm: None,
            header=ws_headers,
        )
        threading.Thread(
            target=self._ws.run_forever, daemon=True,
            kwargs=self._run_kwargs,
        ).start()
        time.sleep(random.uniform(0.5, 1.0))

    def close(self):
        self._stop.set()
        if self._ws_id and self._mgr:
            import urllib.request as _ur
            try:
                payload = _json_module.dumps({"id": self._ws_id, "code": 1000, "reason": ""},
                                             separators=(",", ":")).encode()
                req = _ur.Request(
                    f"http://127.0.0.1:{self._port}/ws/close",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with _ur.urlopen(req, timeout=5) as r:
                    pass
            except Exception:
                pass
            self._ws_id = None
        elif self._ws:
            try:
                self._ws.close()
            except Exception:
                pass


class AccountGenerator:

    SUPPORTED_SOLVERS = ("aiclientz", "anysolver", "onyx")

    def __init__(
            self,
            mail_provider=None,
            mail_api_key: str = None,
            phone_config: Optional[Dict] = None,
            proxy_file: str = "config/proxies.txt",
            output_dir: str = "io/output",
            api_key_aiclientz: str = None,
            api_key_anysolver: str = None,
            api_key_onyx: str = None,
            anysolver_provider: str = None,
            solver_priority: Optional[List[str]] = None,
            http_backend: str = "okhttp",
            enable_logs: bool = False,
            humanize: bool = False,
            science: bool = True,
            region: str = "eu",
            isolated_proxy: bool = False,
            solve_verify_captcha: bool = False,
            debug: bool = False,
    ):
        self.humanize = humanize
        self.science = science
        self.region = region
        self.isolated_proxy = isolated_proxy
        self.solve_verify_captcha = solve_verify_captcha
        self.enable_logs = enable_logs
        self.fingerprint_mode = "android"

        global _DISCORD_TIMEZONE, _DISCORD_WEB_TIMEZONE
        if region == "us":
            _DISCORD_TIMEZONE = "America/New_York"
            _DISCORD_WEB_TIMEZONE = "-05:00"
            self._default_phone_country = 187
        else:
            _DISCORD_TIMEZONE = "GMT"
            _DISCORD_WEB_TIMEZONE = "+00:00"
            self._default_phone_country = 78

        if phone_config and phone_config.get("country") is None:
            phone_config["country"] = self._default_phone_country
            self._log("INFO", f"HeroSMS country auto-set to {self._default_phone_country} ({region.upper()})")
        self.debug = debug
        if enable_logs:
            self._log("INFO", "Detailed per-token logging: ENABLED (io/output/gen_logs/)")
        self._log("INFO", "Fingerprint mode: Android (Discord 324.16)")

        self.use_okhttp = False
        if http_backend == "custom_tls":
            self.use_okhttp = True
            _OkHttpProxyManager.set_backend("custom_tls")
            self._log("INFO", "HTTP backend: custom_tls (utls + fhttp direct — no azuretls)")
        elif http_backend == "okhttp":
            self.use_okhttp = True
            _OkHttpProxyManager.set_backend("azuretls")
            self._log("INFO", "HTTP backend: okhttp (Go uTLS proxy — exact Android TLS fingerprint)")
        elif http_backend == "okhttp_java":
            self.use_okhttp = True
            _OkHttpProxyManager.set_backend("okhttp_java")
            self._log("INFO", "HTTP backend: okhttp_java (Java OkHttp+Conscrypt)")
        else:
            self.use_okhttp = True
            _OkHttpProxyManager.set_backend("azuretls")
            self._log("INFO", "HTTP backend: okhttp (Go uTLS proxy — exact Android TLS fingerprint)")

        self.api_key_aiclientz = api_key_aiclientz
        self.api_key_anysolver = api_key_anysolver
        self.api_key_onyx = api_key_onyx
        self.anysolver_provider = anysolver_provider
        self.solver_priority = solver_priority or ["aiclientz", "anysolver", "onyx"]
        if mail_provider is not None:
            self.mail = mail_provider
        elif mail_api_key:
            self.mail = CyberTempMail(mail_api_key)
        else:
            raise ValueError("Either mail_provider or mail_api_key must be provided")
        self.phone_config = phone_config
        self.proxy_file = proxy_file
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

        self.stats_lock = threading.Lock()
        self.stats = {"generated": 0, "email_verified": 0, "phone_verified": 0, "failed": 0}

        self._batch_size = 25
        self._batch_pause_seconds = 120
        self._batch_pause_event = threading.Event()
        self._batch_pause_event.set()
        self._last_batch_count = 0
        self._batch_lock = threading.Lock()

        self._kept_gateways: List[tuple] = []
        self._kept_gateways_lock = threading.Lock()

        self._used_proxies: set = set()
        self._used_proxies_lock = threading.Lock()
        self._all_proxies: List[str] = []
        self._proxy_index = 0
        self._proxy_index_lock = threading.Lock()

    _COLORS = {
        "SUCCESS": "\033[92m",
        "CAPTCHA": "\033[96m",
        "ERROR":   "\033[91m",
        "WARN":    "\033[93m",
        "INFO":    "\033[97m",
        "DEBUG":   "\033[90m",
    }
    _RESET = "\033[0m"

    def _log(self, level: str, msg: str):
        if level == "DEBUG" and not self.debug:
            return
        color = self._COLORS.get(level, "")
        tag = getattr(getattr(self, '_tls', None), 'log_tag', None)
        prefix = f"[{tag}]" if tag else "[gen]"
        print(f"{color}{prefix} {msg}{self._RESET}")

    GATEWAY_KEEP_ALIVE_SECONDS = 300
    MAX_KEPT_GATEWAYS = 15

    def _check_batch_pause(self, ev_count: int):
        with self._batch_lock:
            current_batch = ev_count // self._batch_size
            if current_batch > self._last_batch_count and ev_count > 0:
                self._last_batch_count = current_batch
                pause_secs = self._batch_pause_seconds
                self._log("WARN", f"=== BATCH PAUSE: {ev_count} email-verified — cooling down {pause_secs}s to avoid velocity detection ===")
                self._batch_pause_event.clear()
                def _resume():
                    time.sleep(pause_secs)
                    self._batch_pause_event.set()
                    self._log("INFO", "=== BATCH RESUME: continuing generation ===")
                threading.Thread(target=_resume, daemon=True).start()

    def _wait_batch_pause(self):
        if not self._batch_pause_event.is_set():
            self._batch_pause_event.wait()

    def _keep_gateway_alive(self, gateway, username: str):
        expiry = time.time() + self.GATEWAY_KEEP_ALIVE_SECONDS
        with self._kept_gateways_lock:
            while len(self._kept_gateways) >= self.MAX_KEPT_GATEWAYS:
                old_gw, _, old_user = self._kept_gateways.pop(0)
                try:
                    old_gw.stop()
                    self._log("DEBUG", f"Evicted oldest gateway ({old_user}) — {len(self._kept_gateways)} active")
                except Exception:
                    pass
            self._kept_gateways.append((gateway, expiry, username))
        self._log("DEBUG", f"Keeping gateway alive for {self.GATEWAY_KEEP_ALIVE_SECONDS}s ({username})")
        threading.Thread(target=self._presence_cycle, args=(gateway, expiry, username), daemon=True).start()

    def _presence_cycle(self, gateway, expiry: float, username: str):
        is_online = True
        gateway._send_presence_online()
        while time.time() < expiry and not gateway._stop.is_set():
            time.sleep(random.uniform(30.0, 90.0))
            if time.time() >= expiry or gateway._stop.is_set():
                break
            if is_online:
                gateway._send_presence_idle()
            else:
                gateway._send_presence_online()
            is_online = not is_online
        try:
            gateway._send_presence_idle()
        except Exception:
            pass

    def _drain_expired_gateways(self):
        now = time.time()
        with self._kept_gateways_lock:
            still_alive = []
            for gw, expiry, username in self._kept_gateways:
                if now >= expiry:
                    try:
                        gw.stop()
                        self._log("DEBUG", f"Gateway keep-alive expired, closed ({username})")
                    except Exception:
                        pass
                else:
                    still_alive.append((gw, expiry, username))
            self._kept_gateways = still_alive

    def _close_all_kept_gateways(self):
        with self._kept_gateways_lock:
            for gw, _, username in self._kept_gateways:
                try:
                    gw.stop()
                    self._log("DEBUG", f"Closing kept gateway ({username})")
                except Exception:
                    pass
            self._kept_gateways = []

    def _get_proxy(self) -> Optional[str]:
        if not self._all_proxies:
            try:
                with open(self.proxy_file, "r", encoding="utf-8") as f:
                    self._all_proxies = [l.strip() for l in f if l.strip()]
                random.shuffle(self._all_proxies)
            except FileNotFoundError:
                return None

        if not self._all_proxies:
            return None

        with self._proxy_index_lock:
            if self._proxy_index >= len(self._all_proxies):
                self._proxy_index = 0
                random.shuffle(self._all_proxies)
                self._log("WARN", f"All {len(self._all_proxies)} proxies used, recycling (IPs should have rotated)")
            proxy = self._all_proxies[self._proxy_index]
            self._proxy_index += 1
        return proxy

    @staticmethod
    def _normalize_proxy(raw: str) -> str:
        if not raw:
            return ""
        if "@" in raw:
            return f"http://{raw}"
        parts = raw.split(":")
        if len(parts) == 4:
            host, port, user, pwd = parts
            return f"http://{user}:{pwd}@{host}:{port}"
        if len(parts) == 2:
            return f"http://{raw}"
        return f"http://{raw}"

    @staticmethod
    def _setup_cloudflare_cookies(sess) -> str:
        return ""

    def _create_session(self, proxy_raw: str, isolated_port: int = None):
        proxy_url = self._normalize_proxy(proxy_raw) if proxy_raw else None
        return _OkHttpSession(proxy_url, port_override=isolated_port)

    def _create_web_session(self, proxy_raw: str):
        proxy_url = self._normalize_proxy(proxy_raw) if proxy_raw else None
        return _OkHttpSession(proxy_url, tls_profile="chrome")

    def _science_event(self, event_type: str, extra_props: dict = None,
                       heartbeat_sid: str = None, seq: int = 0,
                       device_name: str = None,
                       launch_signature: str = None,
                       include_hw: bool = False) -> dict:
        ts = int(time.time() * 1000)
        if not hasattr(self, '_tls'):
            self._tls = threading.local()
        if not hasattr(self._tls, 'event_seq'):
            self._tls.event_seq = 0
        if not getattr(self._tls, 'app_start_ts', None):
            self._tls.app_start_ts = ts
        self._tls.event_seq += 1

        uptime_app = (ts - self._tls.app_start_ts) // 1000

        props = {
            "client_track_timestamp": ts,
            "event_sequence_number": self._tls.event_seq,
        }
        if include_hw and device_name and device_name in DEVICE_HARDWARE:
            hw = DEVICE_HARDWARE[device_name]
            props["device_model"] = hw["device_model"]
            props["device_brand"] = hw["device_brand"]
            props["device_product"] = hw["device_product"]
            props["device_manufacturer"] = hw["device_manufacturer"]
            props["smallest_screen_width"] = hw["smallest_screen_width"]
            props["device_performance_class"] = 0
            props["soc_name"] = hw["soc_name"]
            props["ram_size"] = hw["ram_size"]
            props["max_cpu_freq"] = hw["max_cpu_freq"]
        if self._tls.event_seq >= 10:
            if self._tls.event_seq == 10:
                props["client_performance_cpu"] = 0
                props["client_performance_memory"] = 0
            else:
                base_cpu = min(uptime_app * random.uniform(0.3, 0.5), 35.0)
                props["client_performance_cpu"] = round(base_cpu, 6)
                props["client_performance_memory"] = 370000 + int(min(uptime_app, 80) * random.uniform(500, 1500))
        if self._tls.event_seq > 1:
            props["cpu_core_count"] = 4
        props["accessibility_features"] = 128 if self._tls.event_seq >= 9 else 0
        props["rendered_locale"] = _ctx_system_locale()
        props["uptime_app"] = uptime_app
        if launch_signature:
            props["launch_signature"] = launch_signature
        props["client_rtc_state"] = "DISCONNECTED"
        props["client_app_state"] = "active"
        if self._tls.event_seq >= 4:
            if not hasattr(self._tls, 'uuid_base'):
                self._tls.uuid_base = _make_uuid_base()
                self._tls.uuid_seq = 0
            self._tls.uuid_seq += 1
            props["client_uuid"] = _generate_client_uuid(self._tls.uuid_base, self._tls.uuid_seq)
        props["client_send_timestamp"] = ts + random.randint(50, 200)
        if heartbeat_sid:
            props["client_heartbeat_session_id"] = heartbeat_sid
        if extra_props:
            props.update(extra_props)
        return {"type": event_type, "properties": props}

    def _send_science(
            self, sess, events: list,
            device_name: str, device_vendor_id: str,
            client_launch_id: str, launch_signature: str,
            proxy_raw: str,
            token: str = None,
            analytics_token: str = None,
            fingerprint: str = None,
            heartbeat_sid: str = None,
            client_app_state: str = None,
    ):
        xp_extras = {}
        if heartbeat_sid:
            xp_extras["client_heartbeat_session_id"] = heartbeat_sid
        if client_app_state:
            xp_extras["client_app_state"] = client_app_state
        xp = _super_properties(device_name, device_vendor_id,
                               client_launch_id, launch_signature, **xp_extras)
        proxy_url = self._normalize_proxy(proxy_raw) if proxy_raw else None

        parts: List[Tuple[str, str]] = []
        if not hasattr(self, '_tls'):
            self._tls = threading.local()
        science_count = getattr(self._tls, 'science_call_count', 0)
        self._tls.science_call_count = science_count + 1
        # Only echo x-science-test back if the server issued one on a previous
        # response (HAR: server sets x-science-test: O0dupkD9... on the first
        # response body; client echoes that exact value on subsequent calls).
        captured_test_id = getattr(self._tls, 'science_test_id', None)
        if not token and science_count >= 1 and captured_test_id:
            parts.append(("x-science-test", captured_test_id))
        if token:
            parts.append(("authorization", token))
        parts.append(("x-super-properties", xp))
        if fingerprint and not token:
            parts.append(("x-fingerprint", fingerprint))
        parts.extend([
            ("accept-language", _ctx_accept_language()),
            ("x-discord-locale", _ctx_discord_locale()),
            ("x-discord-timezone", _ctx_timezone()),
            ("x-debug-options", "bugReporterEnabled"),
            ("User-Agent", UA),
            ("Content-Type", "application/json"),
            # Don't set Accept-Encoding — OkHttp auto-adds "gzip" and auto-
        # decompresses. If we set it, OkHttp treats the response body as raw
        # and the Java proxy returns mangled UTF-8 bytes.
        ])

        body_token = (analytics_token or token) if token else None
        payload = {"events": events}
        if body_token is not None:
            payload["token"] = body_token

        try:
            resp = sess.post(
                "https://discord.com/api/v9/science",
                headers=dict(collections.OrderedDict(parts)),
                json=payload,
                proxy=proxy_url,
                timeout_seconds=10,
            )
            # Capture the server-issued x-science-test token from the first
            # response that carries it; echo it on subsequent pre-auth calls.
            if not getattr(self._tls, 'science_test_id', None):
                try:
                    rh = getattr(resp, 'headers', None) or {}
                    new_id = rh.get('x-science-test') or rh.get('X-Science-Test')
                    if new_id:
                        self._tls.science_test_id = new_id
                except Exception:
                    pass
        except Exception:
            pass

    def _send_metrics(self, sess, token, device_name, device_vendor_id,
                      client_launch_id, launch_signature, proxy_raw,
                      heartbeat_sid=None):
        xp_extras = {}
        if heartbeat_sid:
            xp_extras["client_heartbeat_session_id"] = heartbeat_sid
        headers = _build_headers(device_name, device_vendor_id,
                                 client_launch_id, launch_signature,
                                 token=token, **xp_extras)
        proxy_url = self._normalize_proxy(proxy_raw) if proxy_raw else None
        payload = {
            "metrics": [
                {"name": "captcha_event", "type": "count",
                 "tags": ["design_id:2", "event_name:initial-load",
                          "captcha_service:hcaptcha", "platform:android",
                          "release_channel:googleRelease"]},
                {"name": "captcha_event", "type": "count",
                 "tags": ["design_id:2", "event_name:verify",
                          "captcha_service:hcaptcha", "platform:android",
                          "release_channel:googleRelease"]},
            ],
            "client_info": {
                "built_at": "1772733919751",
                "build_number": str(CLIENT_BUILD),
            },
        }
        try:
            sess.post(
                "https://discord.com/api/v9/metrics/v2",
                headers=dict(headers),
                json=payload,
                proxy=proxy_url,
                timeout_seconds=10,
            )
        except Exception:
            pass

    def _get_fingerprint(self, sess, device_name, device_vendor_id,
                         client_launch_id, launch_signature, proxy_raw) -> str:
        xcontext = base64.b64encode(
            json.dumps({"location": "/"}, separators=(",", ":")).encode()
        ).decode()
        proxy_url = self._normalize_proxy(proxy_raw) if proxy_raw else None

        headers_apex = _build_headers(device_name, device_vendor_id,
                                       client_launch_id, launch_signature)
        headers_apex.pop("Content-Type", None)
        try:
            sess.get(
                "https://discord.com/api/v9/apex/experiments?surface=2",
                headers=dict(headers_apex),
                proxy=proxy_url,
                timeout_seconds=10,
            )
        except Exception:
            pass

        headers = _build_headers(device_name, device_vendor_id,
                                 client_launch_id, launch_signature,
                                 xcontext=xcontext)
        headers.pop("Content-Type", None)
        fingerprint = ""
        try:
            r = sess.get(
                "https://discord.com/api/v9/experiments?with_guild_experiments=true",
                headers=dict(headers),
                proxy=proxy_url,
                timeout_seconds=15,
            )
            self._log("DEBUG", f"experiments resp: status={r.status_code} body_len={len(r.text or '')} first100={r.text[:100] if r.text else '<empty>'}")
            if r.status_code == 200 and r.text:
                try:
                    fingerprint = r.json().get("fingerprint", "")
                    if fingerprint:
                        self._log("DEBUG", f"Fingerprint: {fingerprint[:30]}...")
                except Exception as je:
                    self._log("DEBUG", f"experiments json parse failed: {je}")
                if hasattr(sess, '_cookie_str'):
                    cf_cookies = sess._cookie_str
                    has_cfuvid = "_cfuvid" in cf_cookies
                    self._log("DEBUG", f"CF cookies after fingerprint: _cfuvid={'yes' if has_cfuvid else 'NO'}, total={len(cf_cookies)} chars")
        except Exception as e:
            self._log("DEBUG", f"experiments fetch failed: {type(e).__name__}: {e}")

        if not fingerprint:
            self._log("WARN", f"WARNING: No fingerprint obtained")

        # HAR entry 6: the real Android client polls /auth/location-metadata
        # between the first experiments batch and the account-creation flow.
        # It's used server-side to decide login promotions and geo-routing.
        try:
            lm_headers = _build_headers(device_name, device_vendor_id,
                                        client_launch_id, launch_signature,
                                        fingerprint=fingerprint or None)
            lm_headers.pop("Content-Type", None)
            sess.get(
                "https://discord.com/api/v9/auth/location-metadata",
                headers=dict(lm_headers),
                proxy=proxy_url,
                timeout_seconds=10,
            )
        except Exception:
            pass

        return fingerprint

    def _solve_captcha(self, sitekey: str, rqdata: str, proxy_raw: str,
                       web: bool = False, site_url: str = None,
                       device_name: str = None) -> Optional[Tuple[str, str]]:
        for solver_name in self.solver_priority:
            result = self._try_solver(solver_name, sitekey, rqdata, proxy_raw, web=web, site_url=site_url, device_name=device_name)
            if result:
                return result
            self._log("WARN", f"{solver_name} failed, trying next solver...")
        return None

    def _try_solver(self, name, sitekey, rqdata, proxy_raw, web=False, site_url=None, device_name=None):
        pageurl = "https://discord.com" if web else HCAPTCHA_HOST
        captcha_user_agent = _captcha_ua(device_name) if device_name else CAPTCHA_UA
        if name == "hsj":
            token = solve_hsj_local(sitekey, rqdata, proxy_raw, user_agent=captcha_user_agent)
            return (token, "") if token else None
        if name == "aiclientz" and self.api_key_aiclientz:
            token = solve_aiclientz(self.api_key_aiclientz, sitekey, rqdata, proxy_raw)
            return (token, "") if token else None
        elif name == "anysolver" and self.api_key_anysolver:
            token = solve_anysolver(self.api_key_anysolver, sitekey, rqdata, proxy_raw, sub_solver=self.anysolver_provider, user_agent=captcha_user_agent)
            return (token, "") if token else None
        elif name == "onyx" and self.api_key_onyx:
            return solve_onyx(self.api_key_onyx, sitekey, rqdata, proxy_raw, web=web)
        return None

    def _report_onyx(self, task_id, is_success):
        report_onyx(self.api_key_onyx or "", task_id, is_success)

    def _send_boot_science(
            self, sess, fingerprint, device_name, device_vendor_id,
            client_launch_id, launch_signature, proxy_raw,
    ):
        """Fire the 5 cold-boot science batches a real Discord Android client
        sends BEFORE the user even taps Register. HAR deltas:
            batch 1 [  0ms]  app_opened + permissions_acked×2
            batch 2 [ 33ms]  libdiscore_loaded, app_user_deauthenticated
            batch 3 [482ms]  app_launch_completed, app_landing_viewed,
                             impression_user_welcome, activity_device_thermal_state_changed
            batch 4 [1438ms] app_ui_viewed{screen:"unknownn"}
            batch 5 [1468ms] app_ui_viewed2{screen:"redesign-auth"}
        Without these, the first `/science` call from the generator is a
        register_transition — which itself is a tell (real clients would have
        already sent ~10 events before that one).
        """
        sc = lambda etype, extra=None: self._science_event(
            etype, extra, device_name=device_name,
            launch_signature=launch_signature, include_hw=True,
        )
        kw = dict(device_name=device_name, device_vendor_id=device_vendor_id,
                  client_launch_id=client_launch_id, launch_signature=launch_signature,
                  proxy_raw=proxy_raw, fingerprint=fingerprint)

        # Batch 1 — app launched, permissions checked
        self._send_science(sess, [
            sc("app_opened", {"app_open_method": "cold"}),
            sc("permissions_acked", {"permission_type": "notifications", "is_granted": True}),
            sc("permissions_acked", {"permission_type": "contacts", "is_granted": False}),
        ], **kw)
        time.sleep(random.uniform(0.025, 0.055))

        # Batch 2 — native lib loaded + no auth state
        self._send_science(sess, [
            sc("libdiscore_loaded", {"platform": "Android", "duration_ms": round(random.uniform(80.0, 220.0), 3)}),
            sc("app_user_deauthenticated", {"reason": "no_token_found"}),
        ], **kw)
        time.sleep(random.uniform(0.4, 0.6))

        # Batch 3 — launch completed, auth landing viewed
        self._send_science(sess, [
            sc("app_launch_completed", {"launch_type": "cold",
                                        "time_to_interactive_ms": random.randint(550, 1100)}),
            sc("app_landing_viewed", {"landing": "auth"}),
            sc("impression_user_welcome", {"impression_type": "page",
                                            "location": "impression_user_welcome",
                                            "location_page": "impression_user_welcome"}),
            sc("activity_device_thermal_state_changed", {"thermal_state": "nominal"}),
        ], **kw)
        time.sleep(random.uniform(0.9, 1.1))

        # Batch 4 — UI viewed (HAR quirk: typo "unknownn")
        self._send_science(sess, [
            sc("app_ui_viewed", {"screen": "unknownn"}),
        ], **kw)
        time.sleep(random.uniform(0.020, 0.045))

        # Batch 5 — redesign-auth screen
        self._send_science(sess, [
            sc("app_ui_viewed2", {"screen": "redesign-auth"}),
        ], **kw)

    def _warmup_pre_register(
            self, sess, fingerprint, device_name, device_vendor_id,
            client_launch_id, launch_signature, proxy_raw, username, password,
    ):
        proxy_url = self._normalize_proxy(proxy_raw) if proxy_raw else None
        _bh = lambda **kw: dict(_build_headers(
            device_name, device_vendor_id, client_launch_id, launch_signature, **kw))
        _bh_get = lambda **kw: {k: v for k, v in _bh(**kw).items() if k != "Content-Type"}
        sc = lambda etype, extra=None: self._science_event(etype, extra, device_name=device_name, launch_signature=launch_signature)

        ota_headers = collections.OrderedDict([
            ("User-Agent", "okhttp/4.11.0"),
            # Don't set Accept-Encoding — OkHttp auto-adds "gzip" and auto-
        # decompresses. If we set it, OkHttp treats the response body as raw
        # and the Java proxy returns mangled UTF-8 bytes.
        ])
        try:
            sess.get(
                "https://discord.com/android/324.16/manifest.json",
                headers=dict(ota_headers),
                proxy=proxy_url, timeout_seconds=10,
            )
        except Exception:
            pass
        time.sleep(random.uniform(0.5, 1.5))

        # HAR entry 6 (@ +9384 ms from boot): the FIRST science batch after
        # the user taps "Register" on the landing page. Real clients send
        # register_viewed + register_transition(Identity, viewed) +
        # impression_user_registration(identity) together, THEN emit the
        # submitted/success events in a later batch. Absence of this first
        # batch is a bot tell — we jump straight to "submitted" which no
        # real client ever does.
        self._send_science(
            sess,
            [
                sc("register_viewed"),
                sc("register_transition", {
                    "step": "Account Identity",
                    "identity_type": None,
                    "action_type": "viewed",
                    "registration_source": None,
                }),
                sc("impression_user_registration", {
                    "impression_type": "page",
                    "impression_group": "user_registration_flow",
                    "step": "identity",
                    "location": "impression_user_registration",
                    "location_page": "impression_user_registration",
                }),
                sc("mobile_ota_check_attempt", {
                    "result": "noop",
                    "client_build_number": CLIENT_BUILD,
                }),
            ],
            device_name, device_vendor_id, client_launch_id, launch_signature,
            proxy_raw, fingerprint=fingerprint,
        )
        # Real client sits ~10s here while user types email/password.
        time.sleep(random.uniform(8.0, 12.0))

        self._send_science(
            sess,
            [
                sc("register_transition", {
                    "step": "Account Identity",
                    "identity_type": None,
                    "action_type": "submitted",
                    "registration_source": None,
                }),
                sc("register_transition", {
                    "step": "Account Identity",
                    "identity_type": "email",
                    "action_type": "success",
                    "to_step": "Account Display Name",
                    "registration_source": None,
                }),
                sc("register_transition", {
                    "step": "Account Display Name",
                    "identity_type": "email",
                    "action_type": "viewed",
                    "from_step": "Account Identity",
                    "registration_source": None,
                }),
                sc("impression_user_registration", {
                    "impression_type": "page",
                    "impression_group": "user_registration_flow",
                    "step": "display_name",
                    "location": "impression_user_registration",
                    "location_page": "impression_user_registration",
                }),
            ],
            device_name, device_vendor_id, client_launch_id, launch_signature,
            proxy_raw, fingerprint=fingerprint,
        )
        time.sleep(random.uniform(0.3, 0.8))

        try:
            sess.get(
                f"https://discord.com/api/v9/unique-username/username-suggestions-unauthed?global_name={username}",
                headers=_bh_get(fingerprint=fingerprint),
                proxy=proxy_url, timeout_seconds=10,
            )
        except Exception:
            pass
        time.sleep(random.uniform(0.3, 0.8))

        # Real HAR sends one validate per keystroke + occasional backspaces +
        # duplicated final value. See _human_password_typing_sequence().
        partials = _human_password_typing_sequence(password)
        keystroke_count = len(partials)

        for partial in partials:
            try:
                sess.post(
                    "https://discord.com/api/v9/auth/password/validate",
                    headers=_bh(fingerprint=fingerprint),
                    json={"password": partial},
                    proxy=proxy_url, timeout_seconds=10,
                )
            except Exception:
                pass
            time.sleep(random.uniform(0.1, 0.3))

        self._send_science(
            sess,
            [
                sc("register_transition", {
                    "step": "Account Display Name",
                    "identity_type": "email",
                    "action_type": "submitted",
                    "registration_source": None,
                }),
            ],
            device_name, device_vendor_id, client_launch_id, launch_signature,
            proxy_raw, fingerprint=fingerprint,
        )
        time.sleep(random.uniform(0.1, 0.3))

        self._send_science(
            sess,
            [
                sc("register_transition", {
                    "step": "Account Display Name",
                    "identity_type": "email",
                    "action_type": "success",
                    "to_step": "Account Information",
                    "registration_source": None,
                }),
                sc("register_transition", {
                    "step": "Account Information",
                    "identity_type": "email",
                    "action_type": "viewed",
                    "from_step": "Account Display Name",
                    "registration_source": None,
                }),
                sc("impression_user_registration", {
                    "impression_type": "page",
                    "impression_group": "user_registration_flow",
                    "step": "account_information",
                    "location": "impression_user_registration",
                    "location_page": "impression_user_registration",
                }),
            ],
            device_name, device_vendor_id, client_launch_id, launch_signature,
            proxy_raw, fingerprint=fingerprint,
        )
        time.sleep(random.uniform(0.3, 0.8))

        # One network_action_password_validate science event per validate POST
        # we actually sent (including the typo/backspace + duplicated final).
        for _ in range(keystroke_count):
            self._send_science(
                sess,
                [sc("network_action_password_validate", {
                    "status_code": 200,
                    "url": "/auth/password/validate",
                    "request_method": "post",
                    "location": "impression_user_registration",
                    "location_page": "impression_user_registration",
                })],
                device_name, device_vendor_id, client_launch_id, launch_signature,
                proxy_raw, fingerprint=fingerprint,
            )
            time.sleep(random.uniform(0.05, 0.15))

        self._send_science(
            sess,
            [
                sc("register_transition", {
                    "step": "Account Information",
                    "identity_type": "email",
                    "action_type": "submitted",
                    "registration_source": None,
                }),
            ],
            device_name, device_vendor_id, client_launch_id, launch_signature,
            proxy_raw, fingerprint=fingerprint,
        )
        time.sleep(random.uniform(0.1, 0.3))

        self._send_science(
            sess,
            [
                sc("network_action_password_validate", {
                    "status_code": 200,
                    "url": "/auth/password/validate",
                    "request_method": "post",
                    "location": "impression_user_registration",
                    "location_page": "impression_user_registration",
                }),
                sc("register_transition", {
                    "step": "Account Information",
                    "identity_type": "email",
                    "action_type": "success",
                    "to_step": "Age Gate",
                    "registration_source": None,
                }),
                sc("register_transition", {
                    "step": "Age Gate",
                    "identity_type": "email",
                    "action_type": "viewed",
                    "from_step": "Account Information",
                    "registration_source": None,
                }),
                sc("impression_user_age_gate", {
                    "impression_type": "page",
                    "location": "impression_user_age_gate",
                    "location_page": "impression_user_age_gate",
                }),
            ],
            device_name, device_vendor_id, client_launch_id, launch_signature,
            proxy_raw, fingerprint=fingerprint,
        )
        time.sleep(random.uniform(0.3, 0.8))

        self._send_science(
            sess,
            [
                sc("android_jank_stats", {
                    "version": 1,
                    "total_frame_count": random.randint(300, 600),
                    "jank_frame_count": random.randint(1, 5),
                    "trigger": "background",
                }),
            ],
            device_name, device_vendor_id, client_launch_id, launch_signature,
            proxy_raw, fingerprint=fingerprint,
        )

    def _register(
            self, sess, email, username, password, birthday,
            fingerprint, device_name, device_vendor_id,
            client_launch_id, launch_signature, proxy_raw,
    ) -> Optional[str]:
        y, m, d = birthday
        promo_opt_in = getattr(getattr(self, '_tls', None), 'promo_opt_in_prechecked', False)
        payload = {
            "fingerprint": fingerprint,
            "email": email,
            "username": username,
            "global_name": username,
            "password": password,
            "invite": None,
            "consent": True,
            "date_of_birth": f"{y}-{m:02d}-{d:02d}",
            "gift_code_sku_id": None,
            "promotional_email_opt_in": promo_opt_in,
        }

        proxy_url = self._normalize_proxy(proxy_raw) if proxy_raw else None

        sc = lambda etype, extra=None: self._science_event(etype, extra, device_name=device_name, launch_signature=launch_signature)

        time.sleep(random.uniform(1.0, 2.0))

        headers = _build_headers(
            device_name, device_vendor_id, client_launch_id, launch_signature,
            fingerprint=fingerprint,
        )
        self._log("INFO", f"Registering {username}...")
        if hasattr(sess, '_cookie_str'):
            cstr = sess._cookie_str
            has_cfbm = "__cf_bm" in cstr
            has_cfuvid = "_cfuvid" in cstr
            self._log("DEBUG", f"Cookies: __cf_bm={'YES' if has_cfbm else 'NO'}, _cfuvid={'YES' if has_cfuvid else 'NO'}, total={len(cstr)} chars")
        try:
            r = sess.post(
                "https://discord.com/api/v9/auth/register",
                headers=dict(headers),
                json=payload,
                proxy=proxy_url,
                timeout_seconds=30,
            )
        except Exception as e:
            self._log("ERROR", f"Register request failed: {e}")
            return None

        data = r.json()

        if hasattr(sess, '_cookie_str'):
            cstr = sess._cookie_str
            has_cfbm = "__cf_bm" in cstr
            self._log("DEBUG", f"Cookies after register: __cf_bm={'YES' if has_cfbm else 'NO'}, total={len(cstr)} chars")

        if r.status_code in (200, 201) and data.get("token"):
            self._log("SUCCESS", f"Account created (no captcha needed)")
            return data["token"]

        if r.status_code != 400 or "captcha_key" not in r.text:
            self._log("ERROR", f"Register unexpected: {r.status_code} - {r.text[:200]}")
            return None

        self._send_science(
            sess, [
                sc("register_transition", {
                    "step": "Age Gate", "identity_type": "email", "action_type": "submitted",
                    "registration_source": None,
                }),
                sc("age_gate_submitted", {
                    "dob": None, "dob_day": d, "dob_month": m, "dob_year": y, "source_section": "Register"
                }),
                sc("age_gate_action", {
                    "action": "AGE_GATE_SUBMITTED", "source": "Register"
                }),
                sc("user_age_submitted", {
                    "age_bucket": "18-22" if 2026-y <= 22 else "23+"
                }),
            ],
            device_name, device_vendor_id, client_launch_id, launch_signature,
            proxy_raw, fingerprint=fingerprint,
        )
        time.sleep(random.uniform(0.3, 0.6))

        self._send_science(
            sess, [
                sc("open_modal", {"type": "User Registration Captcha"}),
                sc("open_modal", {"type": "CAPTCHA"}),
            ],
            device_name, device_vendor_id, client_launch_id, launch_signature,
            proxy_raw, fingerprint=fingerprint,
        )
        time.sleep(random.uniform(0.5, 1.0))

        attempt = 0
        while True:
            attempt += 1
            sitekey = data.get("captcha_sitekey", HCAPTCHA_SITEKEY)
            rqdata = data.get("captcha_rqdata")
            rqtoken = data.get("captcha_rqtoken")
            captcha_session = data.get("captcha_session_id")

            self._log("CAPTCHA", f"Captcha required, solving [{' > '.join(self.solver_priority)}] (attempt {attempt})...")

            captcha_flow_key = str(uuid.uuid4())
            self._send_science(
                sess, [
                    sc("captcha_event", {
                        "captcha_event_name": "initial-load",
                        "captcha_service": "hcaptcha",
                        "sitekey": sitekey,
                        "captcha_flow_key": captcha_flow_key,
                    }),
                ],
                device_name, device_vendor_id, client_launch_id, launch_signature,
                proxy_raw, fingerprint=fingerprint,
            )
            solve_result = self._solve_captcha(sitekey, rqdata, proxy_raw,
                                               site_url="https://discord.com/api/v9/auth/register",
                                               device_name=device_name)
            if not solve_result:
                self._log("CAPTCHA", f"Captcha solve failed, retrying...")
                time.sleep(random.uniform(2.0, 4.0))
                continue

            captcha_key, captcha_task_id = solve_result
            self._log("CAPTCHA", f"Captcha solved, submitting registration...")

            headers2 = _build_headers(
                device_name, device_vendor_id, client_launch_id, launch_signature,
                fingerprint=fingerprint,
                captcha_key=captcha_key,
                captcha_rqtoken=rqtoken,
                captcha_session_id=captcha_session,
            )

            try:
                r2 = sess.post(
                    "https://discord.com/api/v9/auth/register",
                    headers=dict(headers2),
                    json=payload,
                    proxy=proxy_url,
                    timeout_seconds=30,
                )
            except Exception as e:
                self._log("ERROR", f"Register (captcha) request failed: {e}")
                self._report_onyx(captcha_task_id, False)
                return None

            if r2.status_code in (200, 201):
                token = r2.json().get("token")
                if token:
                    self._report_onyx(captcha_task_id, True)
                    self._log("SUCCESS", f"Account created successfully!")
                    self._send_science(
                        sess,
                        [
                            sc("captcha_event", {"captcha_event_name": "verify", "captcha_service": "hcaptcha", "sitekey": sitekey, "captcha_flow_key": captcha_flow_key}),
                            sc("register_transition", {
                                "step": "Age Gate", "identity_type": "email",
                                "action_type": "success", "to_step": "Captcha",
                                "registration_source": None,
                            }),
                            sc("register_transition", {
                                "step": "Captcha", "identity_type": "email",
                                "action_type": "viewed", "from_step": "Age Gate",
                                "registration_source": None,
                            }),
                            sc("register_transition", {
                                "step": "Captcha", "identity_type": "email",
                                "action_type": "submitted",
                                "registration_source": None,
                            }),
                            sc("register_transition", {
                                "step": "Captcha", "identity_type": "email",
                                "action_type": "success",
                                "registration_source": None,
                            }),
                            sc("register_transition", {
                                "step": "Register", "identity_type": "email",
                                "action_type": "success",
                                "registration_source": None,
                            }),
                        ],
                        device_name, device_vendor_id, client_launch_id, launch_signature,
                        proxy_raw, fingerprint=fingerprint,
                    )
                    return token

            try:
                data2 = r2.json()
            except Exception:
                self._log("ERROR", f"Register failed (non-JSON): {r2.status_code} - {r2.text[:200]}")
                return None

            captcha_keys = data2.get("captcha_key", [])
            is_invalid = isinstance(captcha_keys, list) and "invalid-response" in captcha_keys
            is_required = isinstance(captcha_keys, list) and "captcha-required" in captcha_keys
            self._log("DEBUG", f"Discord captcha response: {json.dumps(data2)[:300]}")
            if is_invalid:
                self._report_onyx(captcha_task_id, False)
                self._log("CAPTCHA", f"Captcha invalid-response (attempt {attempt}), token prefix: {captcha_key[:3] if captcha_key else 'NONE'}")
                if attempt <= 3:
                    self._log("DEBUG", f"Retrying captcha on same proxy (attempt {attempt})...")
                    data = data2
                    time.sleep(random.uniform(1.0, 2.0))
                    continue
                return "INVALID_PROXY"
            if is_required:
                self._log("CAPTCHA", f"Captcha captcha-required (attempt {attempt}), retrying...")
                data = data2
                time.sleep(random.uniform(1.0, 2.0))
                continue

            self._log("ERROR", f"Register with captcha failed: {r2.status_code} - {r2.text[:200]}")
            return None

    def _warmup_post_register(
            self, sess, token, analytics_token,
            device_name, device_vendor_id,
            client_launch_id, launch_signature,
            heartbeat_sid, ad_session_id, proxy_raw,
    ):
        proxy_url = self._normalize_proxy(proxy_raw) if proxy_raw else None
        _bh = lambda **kw: dict(_build_headers(
            device_name, device_vendor_id, client_launch_id, launch_signature,
            token=token, client_heartbeat_session_id=heartbeat_sid, **kw))
        _bh_get = lambda **kw: {k: v for k, v in _bh(**kw).items() if k != "Content-Type"}

        got_401 = False
        early_phone_lock = False

        def _get(url):
            nonlocal got_401, early_phone_lock
            try:
                h = _bh_get()
                r = sess.get(url, headers=h, proxy=proxy_url, timeout_seconds=10)
                if r.status_code == 401:
                    got_401 = True
                    self._log("ERROR", f"WARNING: 401 on {url.split('/api/v9/')[-1]} — token banned")
                elif r.status_code == 403 and not early_phone_lock:
                    body = r.text[:300] if hasattr(r, 'text') else ""
                    if "verify your account" in body.lower():
                        early_phone_lock = True
                        self._log("ERROR", f"EARLY PHONE-LOCK detected during warmup (403 'verify your account')")
            except Exception:
                pass

        # HAR +52.7..+55.0s: cluster of GETs that fire right after the
        # register 201, before the first science batch and before POST
        # /users/@me/devices. Ordering matches HAR entries 30-64.
        _get("https://discord.com/api/v9/users/@me/affinities/guilds")
        time.sleep(random.uniform(0.1, 0.4))
        _get("https://discord.com/api/v9/users/@me/survey?disable_auto_seen=true")
        time.sleep(random.uniform(0.1, 0.3))
        _get(f"https://discord.com/api/v9/promotions?locale={_ctx_discord_locale()}&platform=1")
        time.sleep(random.uniform(0.1, 0.3))
        _get("https://discord.com/api/v9/users/@me/collectibles-marketing?platform=1")
        time.sleep(random.uniform(0.1, 0.3))
        _get("https://discord.com/api/v9/users/@me/applications/521842831262875670/entitlements?exclude_consumed=false")
        time.sleep(random.uniform(0.1, 0.3))
        # quests/@me + quests/decision BEFORE POST /devices (HAR entries 59-60
        # fire at +54.9s, entry 65 /devices fires at +55.1s).
        _get("https://discord.com/api/v9/quests/@me")
        time.sleep(random.uniform(0.05, 0.15))
        _get(f"https://discord.com/api/v9/quests/decision?placement=2&client_heartbeat_session_id={heartbeat_sid}&client_ad_session_id={ad_session_id}")
        time.sleep(random.uniform(0.05, 0.15))
        _get("https://discord.com/api/v9/users/@me/join-request-guilds")
        time.sleep(random.uniform(0.05, 0.15))

        # HAR entry 61 (+54.9s): first post-register PATCH of the user
        # settings proto. The real client always fires this as part of the
        # post-register onboarding. Absence is a "fresh client never synced
        # defaults" tell. Body is a ~22KB base64-encoded proto captured from
        # a real client (locked down to fr-FR defaults).
        try:
            _proto_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "config", "settings_proto_1_template.b64",
            )
            if os.path.isfile(_proto_path):
                with open(_proto_path, "r", encoding="utf-8") as _pf:
                    _proto_body = _pf.read().strip()
                sess.patch(
                    "https://discord.com/api/v9/users/@me/settings-proto/1",
                    headers=_bh(),
                    json={"settings": _proto_body},
                    proxy=proxy_url,
                    timeout_seconds=10,
                )
        except Exception:
            pass
        time.sleep(random.uniform(0.1, 0.3))

        sc = lambda etype, extra=None: self._science_event(etype, extra, heartbeat_sid=heartbeat_sid, device_name=device_name, launch_signature=launch_signature)

        self._send_science(
            sess, [
                sc("network_action_user_register", {
                    "status_code": 201, "url": "/auth/register",
                    "request_method": "post",
                    "invite_code": None,
                    "used_username_suggestion": True,
                    "promotional_email_opt_in": False,
                    "promotional_email_pre_checked": False,
                }),
                sc("client_ad_heartbeat", {
                    "client_ad_session_id": ad_session_id,
                    "client_heartbeat_initialization_timestamp": int(time.time() * 1000),
                    "client_heartbeat_version": 3,
                }),
                sc("age_gate_action", {"action": "AGE_GATE_SUCCESS", "source": "Register"}),
                sc("register_transition", {
                    "step": "Age Gate", "identity_type": "email", "action_type": "success",
                    "registration_source": None,
                }),
                sc("register_transition", {
                    "step": "Register", "identity_type": "email", "action_type": "success",
                    "registration_source": None,
                }),
                sc("client_heartbeat", {
                    "client_heartbeat_initialization_timestamp": int(time.time() * 1000),
                    "client_heartbeat_version": 27,
                    "is_idle": False, "idle_duration_ms": int(time.time() * 1000),
                    "is_afk": False,
                    "is_system_suspended": False, "is_system_locked": False,
                }),
                sc("session_start_client"),
                sc("experiment_user_evaluation_exposed", {
                    "evaluation_id": str(uuid.uuid4())[:8],
                    "exposure_location": "app open", "unit_type": "user",
                }),
                sc("experiment_user_evaluation_exposed", {
                    "evaluation_id": str(uuid.uuid4())[:8],
                    "exposure_location": "app open", "unit_type": "user",
                }),
                sc("experiment_user_evaluation_exposed", {
                    "evaluation_id": str(uuid.uuid4())[:8],
                    "exposure_location": "app open mobile", "unit_type": "user",
                }),
                sc("experiment_user_evaluation_exposed", {
                    "evaluation_id": str(uuid.uuid4())[:8],
                    "exposure_location": "app open mobile", "unit_type": "user",
                }),
                sc("review_request_eligibility_checked", {
                    "is_hfu": True, "is_install_old_enough": False,
                    "is_in_large_enough_guild": False, "is_account_verified": False,
                }),
                sc("ready_payload_received", {
                    "compressed_byte_size": random.randint(15000, 25000),
                    "uncompressed_byte_size": random.randint(15000, 25000),
                    "compression_algorithm": "zstd-stream" if _HAS_ZSTD else "zlib-stream",
                    "packing_algorithm": "json",
                    "unpack_duration_ms": random.randint(1, 3),
                    "identify_total_server_duration_ms": random.randint(150, 300),
                    "identify_api_duration_ms": random.randint(50, 150),
                    "identify_guilds_duration_ms": 0,
                    "num_guilds": 0, "num_guild_channels": 0, "num_guild_category_channels": 0,
                    "is_reconnect": False, "is_fast_connect": False,
                    "duration_ms_since_identify_start": random.randint(200, 500),
                    "duration_ms_since_connection_start": random.randint(300, 700),
                    "duration_ms_since_emit_start": random.randint(200, 500),
                    "did_force_clear_guild_hashes": False,
                    "identify_uncompressed_byte_size": random.randint(15000, 25000),
                    "identify_compressed_byte_size": random.randint(15000, 25000),
                    "had_cache_at_startup": False,
                    "used_cache_at_startup": False,
                }),
                sc("experiment_user_triggered", {
                    "name": "2025-07_camera_toggle_sound",
                    "revision": 3, "population": 0, "bucket": 1,
                    "location_stack": [], "hash_result": random.randint(1000, 9999),
                    "excluded": False, "exposure_type": "auto",
                    "assignment_source": "ready_payload",
                }),
                sc("nuo_transition", {
                    "skip": False,
                    "flow_type": "Mobile NUX Post Reg",
                    "from_step": "registration", "to_step": "contact-sync",
                    "seconds_on_from_step": round(time.time(), 3),
                }),
                sc("impression_contact_sync_start", {
                    "impression_type": "page",
                    "impression_group": "contact_sync_flow",
                    "location": "impression_contact_sync_start",
                    "location_page": "impression_contact_sync_start",
                }),
                sc("experiment_user_evaluation_exposed", {
                    "evaluation_id": str(uuid.uuid4())[:8],
                    "experiment": "2026-02-mobile-referral-program-xp-3",
                    "exposure_location": "MainViewTooltipActionSheets",
                    "unit_type": "user", "tracked_variation_id": 2,
                }),
                sc("android_jank_stats", {
                    "version": 1,
                    "total_frame_count": random.randint(1000, 2000),
                    "jank_frame_count": random.randint(5, 15),
                    "trigger": "startup",
                }),
            ],
            device_name, device_vendor_id, client_launch_id, launch_signature,
            proxy_raw, token=token, analytics_token=analytics_token,
            heartbeat_sid=heartbeat_sid,
        )
        time.sleep(random.uniform(0.03, 0.06))

        self._send_science(
            sess, [
                sc("network_action_user_survey_fetch", {
                    "status_code": 200, "url": "/users/@me/survey",
                    "request_method": "get",
                    "location": "impression_user_registration",
                    "location_page": "impression_user_registration",
                }),
            ],
            device_name, device_vendor_id, client_launch_id, launch_signature,
            proxy_raw, token=token, analytics_token=analytics_token,
            heartbeat_sid=heartbeat_sid,
        )
        time.sleep(random.uniform(0.03, 0.06))

        time.sleep(random.uniform(0.8, 1.2))

        self._send_science(
            sess, [
                sc("relationship_sync_flow", {
                    "flow_type": "Contact Sync", "from_step": None, "to_step": "Complete",
                    "skip": True, "back": False,
                    "seconds_on_from_step": round(time.time(), 3),
                    "location": "Onboarding",
                }),
                sc("nuo_transition", {
                    "skip": True,
                    "flow_type": "Mobile NUX Post Reg",
                    "from_step": "contact-sync", "to_step": "discoverability",
                    "seconds_on_from_step": round(random.uniform(1.0, 2.0), 3),
                }),
                sc("impression_discoverability", {
                    "impression_type": "page",
                    "location": "impression_discoverability",
                    "location_page": "impression_discoverability",
                }),
            ],
            device_name, device_vendor_id, client_launch_id, launch_signature,
            proxy_raw, token=token, analytics_token=analytics_token,
            heartbeat_sid=heartbeat_sid,
        )
        time.sleep(random.uniform(0.02, 0.06))

        try:
            sess.post(
                "https://discord.com/api/v9/users/@me/devices",
                headers=_bh(),
                json={
                    "provider": "gcm",
                    "token": base64.b64encode(os.urandom(16)).decode().rstrip("=")[:22] + ":APA91b" + base64.b64encode(os.urandom(85)).decode().rstrip("=")[:119],
                    "bypass_server_throttling_supported": True,
                    "bundle_id": "com.discord",
                },
                proxy=proxy_url,
                timeout_seconds=10,
            )
        except Exception:
            pass
        time.sleep(random.uniform(0.1, 0.3))

        self._send_science(
            sess, [
                sc("experiment_user_evaluation_exposed", {
                    "evaluation_id": str(uuid.uuid4())[:8],
                    "experiment": "2025-11-defer-load-late-lazy-cache",
                    "exposure_location": "default", "unit_type": "user",
                    "tracked_variation_id": 1,
                }),
                sc("experiment_user_evaluation_exposed", {
                    "evaluation_id": str(uuid.uuid4())[:8],
                    "experiment": "2026-02-android-fresco-cache",
                    "exposure_location": "default", "unit_type": "user",
                    "tracked_variation_id": 2,
                }),
                sc("experiment_user_evaluation_exposed", {
                    "evaluation_id": str(uuid.uuid4())[:8],
                    "experiment": "2026-02-android-chat-mosaic-shared-pool",
                    "exposure_location": "default", "unit_type": "user",
                    "tracked_variation_id": 1,
                }),
                sc("voice_activity_threshold_changed", {
                    "input_device_name": "Default", "audio_subsystem": "standard",
                    "audio_layer": "androidOpenSLESAudio", "old_threshold": -60,
                    "old_auto_threshold": True, "new_auto_threshold": False,
                }),
                sc("notification_permission_status", {
                    "os_enabled": True, "foreground_app_enabled": True,
                    "background_app_enabled": True, "notification_authorization_status": None,
                }),
            ],
            device_name, device_vendor_id, client_launch_id, launch_signature,
            proxy_raw, token=token, analytics_token=analytics_token,
            heartbeat_sid=heartbeat_sid,
        )
        time.sleep(random.uniform(0.1, 0.3))

        self._send_science(
            sess, [
                sc("ad_user_fetch_duration", {
                    "platform": "Android", "success": True, "duration_ms": round(random.uniform(20.0, 50.0), 6),
                    "has_advertising_id": True, "is_limit_ad_tracking_enabled": False,
                }),
                sc("ad_identifier_fetched", {
                    "has_advertising_id": True,
                    "android_advertising_id": str(uuid.uuid4()),
                    "success": True, "location": "post_connection_open",
                }),
            ],
            device_name, device_vendor_id, client_launch_id, launch_signature,
            proxy_raw, token=token, analytics_token=analytics_token,
            heartbeat_sid=heartbeat_sid,
        )
        time.sleep(random.uniform(0.1, 0.3))

        self._send_science(
            sess, [
                sc("nuo_transition", {
                    "skip": True,
                    "flow_type": "Mobile NUX Post Reg",
                    "from_step": "contact-sync", "to_step": "discoverability",
                    "seconds_on_from_step": round(random.uniform(0.8, 1.5), 3),
                }),
                sc("network_action_user_register_device_token", {
                    "status_code": 204, "url": "/users/@me/devices", "request_method": "post",
                    "location": "impression_discoverability", "location_page": "impression_discoverability",
                }),
                sc("voice_activity_threshold_changed", {
                    "input_device_name": "Default", "audio_subsystem": "standard",
                    "audio_layer": "androidOpenSLESAudio", "old_threshold": -60,
                    "old_auto_threshold": False, "new_auto_threshold": True,
                }),
            ],
            device_name, device_vendor_id, client_launch_id, launch_signature,
            proxy_raw, token=token, analytics_token=analytics_token,
            heartbeat_sid=heartbeat_sid,
        )
        time.sleep(random.uniform(0.1, 0.3))

        self._send_science(
            sess, [
                sc("nuo_transition", {
                    "skip": True,
                    "flow_type": "Mobile NUX Post Reg",
                    "from_step": "discoverability", "to_step": "choose-avatar",
                    "seconds_on_from_step": round(random.uniform(0.1, 0.4), 3),
                }),
            ],
            device_name, device_vendor_id, client_launch_id, launch_signature,
            proxy_raw, token=token, analytics_token=analytics_token,
            heartbeat_sid=heartbeat_sid,
        )
        time.sleep(random.uniform(0.3, 0.5))

        # quests/@me, quests/decision, join-request-guilds moved to the
        # early pre-devices cluster above (HAR ordering). The remaining late
        # entitlements GET matches HAR entry 81 at +112.9s.
        _get("https://discord.com/api/v9/users/@me/entitlements?with_sku=false&with_application=false&entitlement_type=11&exclude_ended=true")
        time.sleep(random.uniform(0.3, 0.7))

        self._send_science(
            sess, [
                sc("nuo_transition", {
                    "flow_type": "Mobile NUX Post Reg",
                    "from_step": "choose-avatar", "to_step": "NUF Complete",
                    "seconds_on_from_step": round(random.uniform(2.0, 3.0), 3),
                }),
                sc("impression_messages_empty_nux", {
                    "impression_type": "view",
                    "location_section": "impression_messages_empty_nux",
                }),
                sc("experiment_user_evaluation_exposed", {
                    "evaluation_id": str(uuid.uuid4())[:8],
                    "exposure_location": "dm/gdm list rendered", "unit_type": "user",
                }),
                sc("experiment_user_evaluation_exposed", {
                    "evaluation_id": str(uuid.uuid4())[:8],
                    "exposure_location": "dm/gdm list rendered", "unit_type": "user",
                }),
                sc("permissions_requested", {"type": "notification"}),
                sc("permissions_acked", {"type": "notification", "action": "denied"}),
            ],
            device_name, device_vendor_id, client_launch_id, launch_signature,
            proxy_raw, token=token, analytics_token=analytics_token,
            heartbeat_sid=heartbeat_sid,
        )
        time.sleep(random.uniform(0.3, 0.7))

        if early_phone_lock:
            return "PHONE_LOCKED"
        return got_401

    def _verify_email(
            self, sess, token, email,
            device_name, device_vendor_id,
            client_launch_id, launch_signature,
            proxy_raw, heartbeat_sid=None,
    ):
        self._log("INFO", f"Waiting for verification email for {email}...")
        upn = self.mail.wait_for_verification(email, timeout=120)
        if not upn:
            self._log("ERROR", f"No verification email received")
            return None

        self._log("INFO", f"Got verification UPN, starting web verify flow...")
        proxy_url = self._normalize_proxy(proxy_raw) if proxy_raw else None

        web_sess = self._create_web_session(proxy_raw)
        self._setup_cloudflare_cookies(web_sess)
        web_launch_id = str(uuid.uuid4())
        web_launch_sig = str(uuid.uuid4())
        self._log("DEBUG", f"Created separate Chrome session for verify")

        email_domain = email.split("@")[-1] if "@" in email else ""
        is_hotmail = any(d in email_domain for d in ("hotmail", "outlook", "live"))

        if isinstance(self.mail, CyberTempMail):
            mail_gif_referer = "https://www.cybertemp.xyz/"
            mail_nav_referer = "https://www.cybertemp.xyz/"
        elif is_hotmail:
            mail_gif_referer = "https://outlook.live.com/"
            mail_nav_referer = ""
        else:
            parts = email_domain.split(".")
            base_domain = parts[-2] + "." + parts[-1] if len(parts) >= 2 else email_domain
            mail_gif_referer = f"https://www.{base_domain}/"
            mail_nav_referer = f"https://www.{base_domain}/"

        if is_hotmail:
            web_referrer = "android-app://com.google.android.gm/"
            web_referring_domain = "com.google.android.gm"
        elif isinstance(self.mail, CyberTempMail):
            web_referrer = ""
            web_referring_domain = ""
        else:
            web_referrer = ""
            web_referring_domain = ""
        web_referrer_current = ""
        web_referring_domain_current = ""
        if isinstance(self.mail, CyberTempMail) and mail_nav_referer:
            from urllib.parse import urlparse as _up
            web_referrer_current = mail_nav_referer
            web_referring_domain_current = _up(mail_nav_referer).hostname or ""

        try:
            token_user_id = token.split(".")[0]
            try:
                padded = token_user_id + "=" * (4 - len(token_user_id) % 4)
                token_user_id = base64.b64decode(padded).decode()
            except Exception:
                pass
            tracking_uuid = str(uuid.uuid4())
            props_b64 = base64.b64encode(
                json.dumps({"email_type": "user_verify_email"}).encode()
            ).decode()
            img_headers = collections.OrderedDict([
                ("sec-ch-ua-platform", '"Android"'),
                ("User-Agent", WEB_UA),
                ("sec-ch-ua", WEB_SEC_CH_UA),
                ("sec-ch-ua-mobile", "?1"),
                ("Accept", "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"),
                ("Sec-Fetch-Site", "cross-site"),
                ("Sec-Fetch-Mode", "no-cors"),
                ("Sec-Fetch-Dest", "image"),
            ])
            if mail_gif_referer:
                img_headers["Referer"] = mail_gif_referer
            img_headers["Accept-Language"] = "en-US,en;q=0.9"
            web_sess.get(
                f"https://discord.com/api/science/{token_user_id}/{tracking_uuid}.gif?properties={props_b64}",
                headers=dict(img_headers),
                timeout_seconds=10,
            )
            self._log("DEBUG", f"Science GIF tracking done (CF cookies seeded)")
        except Exception as e:
            self._log("WARN", f"Science GIF failed (non-fatal): {e}")

        nav_headers = collections.OrderedDict([
            ("sec-ch-ua", WEB_SEC_CH_UA),
            ("sec-ch-ua-mobile", "?1"),
            ("sec-ch-ua-platform", '"Android"'),
            ("Upgrade-Insecure-Requests", "1"),
            ("User-Agent", WEB_UA),
            ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
            ("Sec-Fetch-Site", "cross-site"),
            ("Sec-Fetch-Mode", "navigate"),
            ("Sec-Fetch-User", "?1"),
            ("Sec-Fetch-Dest", "document"),
        ])
        if mail_nav_referer:
            nav_headers["Referer"] = mail_nav_referer
        nav_headers["Accept-Language"] = "en-US,en;q=0.9"

        upn = upn.strip()

        if upn.startswith("__TOKEN__"):
            verify_token = upn[len("__TOKEN__"):]
            self._log("INFO", f"Got direct verify token from email ({len(verify_token)} chars)")
            try:
                page_headers = collections.OrderedDict([
                    ("sec-ch-ua", WEB_SEC_CH_UA),
                    ("sec-ch-ua-mobile", "?1"),
                    ("sec-ch-ua-platform", '"Android"'),
                    ("Upgrade-Insecure-Requests", "1"),
                    ("User-Agent", WEB_UA),
                    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
                    ("Sec-Fetch-Site", "none"),
                    ("Sec-Fetch-Mode", "navigate"),
                    ("Sec-Fetch-Dest", "document"),
                    ("Accept-Language", "en-US,en;q=0.9"),
                ])
                web_sess.get(f"https://discord.com/verify#token={verify_token}",
                             headers=dict(page_headers), timeout_seconds=10)
            except Exception:
                pass
        elif upn.startswith("__FULLURL__"):
            click_url = upn[len("__FULLURL__"):]
            self._log("DEBUG", f"Using full click URL ({len(click_url)} chars): {click_url[:100]}...")
            verify_token = None
        else:
            click_url = None
            verify_token = None
            self._log("DEBUG", f"UPN for verify ({len(upn)} chars): {upn[:60]}...{upn[-20:] if len(upn) > 60 else ''}")

        if not verify_token:
            try:
                if click_url:
                    r = web_sess.get(click_url, headers=dict(nav_headers), timeout_seconds=15, max_redirects=0)
                else:
                    r = web_sess.get("https://click.discord.com/ls/click", params={"upn": upn},
                                     headers=dict(nav_headers), timeout_seconds=15, max_redirects=0)
                location = r.headers.get("Location", "")
                self._log("DEBUG", f"Click response: status={r.status_code}, Location={location[:200]}")

                for _ in range(5):
                    if not location or "token=" in location:
                        break
                    r = web_sess.get(location, headers=dict(nav_headers), timeout_seconds=15, max_redirects=0)
                    location = r.headers.get("Location", "")
                    self._log("DEBUG", f"  Redirect hop: status={r.status_code}, Location={location[:200]}")

                if location and "token=" in location:
                    fragment = urlparse(location).fragment
                    if fragment and "token=" in fragment:
                        verify_token = fragment.split("token=")[-1]
                    if not verify_token:
                        from urllib.parse import parse_qs
                        parsed = urlparse(location)
                        qs = parse_qs(parsed.query)
                        if "token" in qs:
                            verify_token = qs["token"][0]
                if not verify_token:
                    body = r.text if hasattr(r, "text") else ""
                    self._log("DEBUG", f"Click body ({len(body)} chars): {body[:300]}")
                    import re as _re
                    match = _re.search(r'href="([^"]*token=[^"]*)"', body)
                    if match:
                        loc2 = match.group(1)
                        fragment = urlparse(loc2).fragment
                        if fragment and "token=" in fragment:
                            verify_token = fragment.split("token=")[-1]
            except Exception as e:
                self._log("ERROR", f"Failed to follow verify link: {e}")
                return None

        if not verify_token:
            self._log("ERROR", f"Could not extract verify token from redirect")
            return None

        self._log("INFO", f"Got verify token from redirect, posting to Discord...")

        try:
            page_headers = collections.OrderedDict([
                ("sec-ch-ua", WEB_SEC_CH_UA),
                ("sec-ch-ua-mobile", "?1"),
                ("sec-ch-ua-platform", '"Android"'),
                ("Upgrade-Insecure-Requests", "1"),
                ("User-Agent", WEB_UA),
                ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
                ("Sec-Fetch-Site", "cross-site"),
                ("Sec-Fetch-Mode", "navigate"),
                ("Sec-Fetch-User", "?1"),
                ("Sec-Fetch-Dest", "document"),
                ("Accept-Language", "en-US,en;q=0.9"),
            ])
            if mail_nav_referer:
                page_headers["Referer"] = mail_nav_referer
            web_sess.get("https://discord.com/verify", headers=dict(page_headers), timeout_seconds=15)
        except Exception as e:
            self._log("WARN", f"Verify page GET failed (non-fatal): {e}")

        verify_headers = _build_web_headers(
            web_launch_id, web_launch_sig,
            fingerprint=None,
            referer="https://discord.com/verify",
            token=token,
            referrer_url=web_referrer,
            referring_domain=web_referring_domain,
            referrer_current=web_referrer_current,
            referring_domain_current=web_referring_domain_current,
            heartbeat_sid=heartbeat_sid,
        )
        verify_payload = {"token": verify_token}

        try:
            r2 = web_sess.post("https://discord.com/api/v9/auth/verify",
                               headers=dict(verify_headers), json=verify_payload, timeout_seconds=15)
        except Exception as e:
            self._log("ERROR", f"Email verify request failed: {e}")
            return None

        attempt = 0
        while r2.status_code == 400 and "captcha_key" in r2.text:
            phone_enabled = self.phone_config and self.phone_config.get("enabled")
            if not phone_enabled and not getattr(self, 'solve_verify_captcha', False):
                self._log("WARN", f"Email verify captcha — proxy flagged, need rotation")
                return "CAPTCHA_FLAGGED"

            attempt += 1
            data = r2.json()
            sitekey = data.get("captcha_sitekey", HCAPTCHA_SITEKEY)
            rqdata = data.get("captcha_rqdata")
            rqtoken_c = data.get("captcha_rqtoken")
            session_id_c = data.get("captcha_session_id")

            self._log("CAPTCHA", f"Email verify captcha required, solving (attempt {attempt})...")
            solve_result = self._solve_captcha(sitekey, rqdata, proxy_raw, web=True,
                                               site_url="https://discord.com/api/v9/auth/verify")
            if not solve_result:
                self._log("CAPTCHA", f"Captcha solve failed, retrying...")
                time.sleep(random.uniform(2.0, 4.0))
                continue

            captcha_key, captcha_task_id = solve_result

            cap_headers = _build_web_headers(
                web_launch_id, web_launch_sig,
                fingerprint=None,
                referer="https://discord.com/verify",
                token=token,
                referrer_url=web_referrer,
                referring_domain=web_referring_domain,
                referrer_current=web_referrer_current,
                referring_domain_current=web_referring_domain_current,
                heartbeat_sid=heartbeat_sid,
                captcha_key=captcha_key,
                captcha_rqtoken=rqtoken_c,
                captcha_session_id=session_id_c,
            )

            try:
                r2 = web_sess.post("https://discord.com/api/v9/auth/verify",
                                   headers=dict(cap_headers), json=verify_payload, timeout_seconds=15)
            except Exception as e:
                self._log("ERROR", f"Email verify (captcha) request failed: {e}")
                self._report_onyx(captcha_task_id, False)
                return None

            if 200 <= r2.status_code < 300:
                self._report_onyx(captcha_task_id, True)
                break

            if r2.status_code == 400 and "captcha_key" in r2.text:
                try:
                    data2 = r2.json()
                    captcha_keys = data2.get("captcha_key", [])
                    is_invalid = isinstance(captcha_keys, list) and "invalid-response" in captcha_keys
                    if is_invalid:
                        proxy_raw = self._get_proxy()
                        proxy_url = self._normalize_proxy(proxy_raw) if proxy_raw else None
                        self._log("CAPTCHA", f"Captcha invalid-response, rotated proxy (attempt {attempt})")
                except Exception:
                    pass
                time.sleep(random.uniform(1.0, 2.0))
                continue
            break

        if 200 <= r2.status_code < 300:
            self._log("SUCCESS", f"Email verified!")
            new_token = None
            try:
                new_token = r2.json().get("token")
                if new_token:
                    self._log("SUCCESS", f"Got NEW token from email verify response")
            except Exception:
                pass
            return new_token if new_token else token

        self._log("ERROR", f"Email verify failed: {r2.status_code} - {r2.text[:200]}")
        return None

    def _verify_phone(
            self, sess, token, password,
            device_name, device_vendor_id,
            client_launch_id, launch_signature,
            heartbeat_sid, proxy_raw,
            phone_locked: bool = False,
    ) -> bool:
        if not self.phone_config:
            return False

        hero = HeroSMS(
            api_key=self.phone_config["hero_sms_api_key"],
            service=self.phone_config.get("service", "ds"),
            country=int(self.phone_config.get("country", 6)),
        )
        proxy_url = self._normalize_proxy(proxy_raw) if proxy_raw else None
        _bh = lambda **kw: dict(_build_headers(
            device_name, device_vendor_id, client_launch_id, launch_signature,
            token=token, client_heartbeat_session_id=heartbeat_sid, **kw))

        self._log("INFO", f"Requesting phone number from HeroSMS...")
        try:
            act_id, raw_phone = hero.request_number()
        except Exception as e:
            self._log("ERROR", f"HeroSMS failed: {e}")
            return False

        phone = raw_phone if raw_phone.startswith("+") else f"+{raw_phone}"
        change_reason = "user_action_required"
        self._log("INFO", f"Got number: {phone} (activation {act_id})")

        phone_payload = {"phone": phone, "change_phone_reason": change_reason}
        try:
            r = sess.post("https://discord.com/api/v9/users/@me/phone",
                          headers=_bh(), json=phone_payload, proxy=proxy_url, timeout_seconds=30)
        except Exception as e:
            self._log("ERROR", f"Phone attach request failed: {e}")
            hero.set_status(act_id, 8)
            return False

        if r.status_code == 204:
            pass
        elif r.status_code == 400 and "captcha_key" in r.text:
            phone_attempt = 0
            phone_resp = r
            while True:
                phone_attempt += 1
                data = phone_resp.json()
                sitekey = data.get("captcha_sitekey", HCAPTCHA_SITEKEY)
                rqdata = data.get("captcha_rqdata")
                rqtoken = data.get("captcha_rqtoken")
                session_id = data.get("captcha_session_id")

                self._log("CAPTCHA", f"Phone captcha required, solving (attempt {phone_attempt})...")
                solve_result = self._solve_captcha(sitekey, rqdata, proxy_raw,
                                                   site_url="https://discord.com/api/v9/users/@me/phone",
                                                   device_name=device_name)
                if not solve_result:
                    self._log("CAPTCHA", f"Phone captcha solve failed, retrying...")
                    time.sleep(random.uniform(2.0, 4.0))
                    continue

                captcha_key, captcha_task_id = solve_result
                try:
                    r2 = sess.post("https://discord.com/api/v9/users/@me/phone",
                                   headers=_bh(captcha_key=captcha_key, captcha_rqtoken=rqtoken,
                                               captcha_session_id=session_id),
                                   json=phone_payload, proxy=proxy_url, timeout_seconds=30)
                except Exception as e:
                    self._log("INFO", f"Phone attach (captcha) request failed: {e}")
                    self._report_onyx(captcha_task_id, False)
                    hero.set_status(act_id, 8)
                    return False

                if r2.status_code == 204:
                    self._report_onyx(captcha_task_id, True)
                    break

                if r2.status_code == 400 and "captcha_key" in r2.text:
                    try:
                        data2 = r2.json()
                        captcha_keys = data2.get("captcha_key", [])
                        is_invalid = isinstance(captcha_keys, list) and "invalid-response" in captcha_keys
                        is_required = isinstance(captcha_keys, list) and "captcha-required" in captcha_keys
                        if is_invalid or is_required:
                            phone_resp = r2
                            time.sleep(random.uniform(1.0, 2.0))
                            continue
                    except Exception:
                        pass

                self._log("ERROR", f"Phone attach rejected: {r2.status_code} - {r2.text[:200]}")
                if r2.status_code == 401:
                    self._purge_token(token)
                hero.set_status(act_id, 8)
                return False
        else:
            self._log("ERROR", f"Phone attach unexpected: {r.status_code} - {r.text[:200]}")
            if r.status_code == 401:
                self._purge_token(token)
            hero.set_status(act_id, 8)
            return False

        self._log("INFO", f"Waiting for SMS...")
        hero.set_status(act_id, 1)
        try:
            code = hero.wait_for_code(act_id)
        except Exception as e:
            self._log("ERROR", f"SMS wait failed: {e}")
            return False

        self._log("SUCCESS", f"SMS received, code: {code}")

        try:
            r3 = sess.post("https://discord.com/api/v9/phone-verifications/verify",
                           headers=_bh(), json={"phone": phone, "code": code},
                           proxy=proxy_url, timeout_seconds=15)
        except Exception as e:
            self._log("ERROR", f"Phone verify request failed: {e}")
            return False

        if r3.status_code != 200:
            self._log("ERROR", f"Phone verify failed: {r3.status_code} - {r3.text[:200]}")
            return False

        phone_token = r3.json().get("token")
        if not phone_token:
            self._log("ERROR", f"No phone_token in verify response")
            return False

        try:
            r4 = sess.post("https://discord.com/api/v9/users/@me/phone",
                           headers=_bh(),
                           json={"phone_token": phone_token, "password": password,
                                 "change_phone_reason": change_reason},
                           proxy=proxy_url, timeout_seconds=15)
        except Exception as e:
            self._log("ERROR", f"Phone confirm failed: {e}")
            return False

        if r4.status_code == 204:
            self._log("SUCCESS", f"Phone verified!")
            hero.set_status(act_id, 6)
            return True

        self._log("ERROR", f"Phone confirm rejected: {r4.status_code} - {r4.text[:200]}")
        if r4.status_code == 401:
            self._purge_token(token)
        return False

    @staticmethod
    def _random_bio() -> str:
        fragments = [
            "just vibing", "music lover", "gamer", "anime fan", "art enthusiast",
            "chill person", "love meeting new people", "dm me", "be kind",
            "living my best life", "night owl", "coffee addict", "cat person",
            "dog lover", "peace and love", "good vibes only", "student",
            "dreamer", "creative soul", "adventurer", "bookworm", "movie buff",
            "sports fan", "photographer", "traveler", "foodie", "nature lover",
            "tech nerd", "fitness", "memes", "learning new things",
        ]
        emojis = [
            "\U0001f525", "\U00002728", "\U0001f31f", "\U0001f60e", "\U0001f3ae",
            "\U0001f3b5", "\U0001f4ab", "\U0001f680", "\U0001f308", "\U0001f4af",
            "\U00002764\ufe0f", "\U0001f44b", "\U0001f30d", "\U0001f3a8", "\U0001f4da",
            "\U0001f381", "\U0001f389", "\U0001f48e", "\U0001f33b", "\U00002615",
        ]
        parts = random.sample(fragments, random.randint(1, 3))
        bio = " | ".join(parts)
        for _ in range(random.randint(1, 2)):
            pos = random.choice(["start", "end"])
            emoji = random.choice(emojis)
            if pos == "start":
                bio = emoji + " " + bio
            else:
                bio = bio + " " + emoji
        return bio[:190]

    def _set_bio(self, sess, token, device_name, device_vendor_id,
                 client_launch_id, launch_signature, heartbeat_sid, proxy_raw):
        bio = self._random_bio()
        proxy_url = self._normalize_proxy(proxy_raw) if proxy_raw else None
        headers = dict(_build_headers(
            device_name, device_vendor_id, client_launch_id, launch_signature,
            token=token, client_heartbeat_session_id=heartbeat_sid))
        try:
            r = sess.patch("https://discord.com/api/v9/users/%40me/profile",
                           headers=headers, json={"bio": bio}, proxy=proxy_url, timeout_seconds=10)
            if r.status_code == 200:
                self._log("SUCCESS", f"Bio set: {bio[:50]}...")
            else:
                self._log("WARN", f"Bio failed: {r.status_code} - {r.text[:100]}")
        except Exception as e:
            self._log("WARN", f"Bio error: {e}")

    def _set_avatar(self, sess, token, device_name, device_vendor_id,
                    client_launch_id, launch_signature, heartbeat_sid, proxy_raw):
        avatar_dir = os.path.join("io", "input", "avatars")
        if not os.path.isdir(avatar_dir):
            self._log("WARN", f"No avatars directory found at {avatar_dir}")
            return
        images = [f for f in os.listdir(avatar_dir)
                  if f.lower().endswith(('.jpg', '.jpeg', '.png', '.webp', '.gif'))]
        if not images:
            self._log("WARN", f"No avatar images found in {avatar_dir}")
            return
        img_file = random.choice(images)
        img_path = os.path.join(avatar_dir, img_file)
        try:
            with open(img_path, "rb") as f:
                img_data = f.read()
        except Exception as e:
            self._log("WARN", f"Failed to read avatar {img_file}: {e}")
            return
        ext = img_file.rsplit(".", 1)[-1].lower()
        mime_map = {"jpg": "jpeg", "jpeg": "jpeg", "png": "png", "webp": "webp", "gif": "gif"}
        mime = mime_map.get(ext, "jpeg")
        b64 = base64.b64encode(img_data).decode()
        avatar_data_uri = f"data:image/{mime};base64,{b64}"
        proxy_url = self._normalize_proxy(proxy_raw) if proxy_raw else None
        headers = dict(_build_headers(
            device_name, device_vendor_id, client_launch_id, launch_signature,
            token=token, client_heartbeat_session_id=heartbeat_sid))
        payload = {"avatar": avatar_data_uri}
        try:
            r = sess.patch("https://discord.com/api/v9/users/@me",
                           headers=headers, json=payload, proxy=proxy_url, timeout_seconds=15)
            if r.status_code == 200:
                self._log("SUCCESS", f"Avatar set: {img_file}")
            elif r.status_code == 400 and "captcha_key" in r.text:
                data = r.json()
                sitekey = data.get("captcha_sitekey", HCAPTCHA_SITEKEY)
                rqdata = data.get("captcha_rqdata")
                rqtoken_c = data.get("captcha_rqtoken")
                session_id_c = data.get("captcha_session_id")
                self._log("CAPTCHA", f"Avatar captcha required, solving...")
                solve_result = self._solve_captcha(sitekey, rqdata, proxy_raw)
                if solve_result:
                    captcha_key, captcha_task_id = solve_result
                    headers["X-Captcha-Key"] = captcha_key
                    if rqtoken_c:
                        headers["X-Captcha-Rqtoken"] = rqtoken_c
                    if session_id_c:
                        headers["X-Captcha-Session-Id"] = session_id_c
                    r2 = sess.patch("https://discord.com/api/v9/users/@me",
                                    headers=headers, json=payload, proxy=proxy_url, timeout_seconds=15)
                    if r2.status_code == 200:
                        self._report_onyx(captcha_task_id, True)
                        self._log("SUCCESS", f"Avatar set (with captcha): {img_file}")
                    else:
                        self._report_onyx(captcha_task_id, False)
                        self._log("ERROR", f"Avatar failed after captcha: {r2.status_code}")
            else:
                self._log("WARN", f"Avatar failed: {r.status_code} - {r.text[:100]}")
        except Exception as e:
            self._log("WARN", f"Avatar error: {e}")

    def _humanize_account(self, sess, token, device_name, device_vendor_id,
                          client_launch_id, launch_signature, heartbeat_sid, proxy_raw):
        proxy_url = self._normalize_proxy(proxy_raw) if proxy_raw else None
        headers = dict(_build_headers(
            device_name, device_vendor_id, client_launch_id, launch_signature,
            token=token, client_heartbeat_session_id=heartbeat_sid))
        try:
            sess.patch("https://discord.com/api/v9/users/@me/settings-proto/1",
                       headers=headers, json={"settings": "agIIAQ=="},
                       proxy=proxy_url, timeout_seconds=10)
        except Exception:
            pass
        time.sleep(random.uniform(1.0, 2.0))
        self._set_bio(sess, token, device_name, device_vendor_id,
                      client_launch_id, launch_signature, heartbeat_sid, proxy_raw)
        time.sleep(random.uniform(2.0, 5.0))
        self._set_avatar(sess, token, device_name, device_vendor_id,
                         client_launch_id, launch_signature, heartbeat_sid, proxy_raw)

    def _save(self, email, password, token, filename):
        path = os.path.join(self.output_dir, filename)
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"{email}:{password}:{token}\n")

    def _purge_token(self, token):
        for fname in ("tokens.txt", "email_verified.txt", "phone_verified.txt"):
            fpath = os.path.join(self.output_dir, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                filtered = [l for l in lines if token not in l]
                if len(filtered) < len(lines):
                    with open(fpath, "w", encoding="utf-8") as f:
                        f.writelines(filtered)
                    self._log("WARN", f"Purged banned token from {fname}")
            except Exception:
                pass

    def _move_to_locked(self, token, email="", password=""):
        locked_path = os.path.join(self.output_dir, "locked.txt")
        line = f"{email}:{password}:{token}" if email else token
        with open(locked_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        for fname in ("tokens.txt", "email_verified.txt"):
            fpath = os.path.join(self.output_dir, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                filtered = [l for l in lines if token not in l]
                if len(filtered) < len(lines):
                    with open(fpath, "w", encoding="utf-8") as f:
                        f.writelines(filtered)
            except Exception:
                pass
        self._log("WARN", f"Moved locked token to locked.txt")

    def generate_one(self) -> bool:
        self._wait_batch_pause()

        gateway = None
        preauth_gw = None
        username = "unknown"
        proxy_raw = self._get_proxy()
        token_logger = _TokenLogger(self.output_dir, enabled=self.enable_logs)
        gen_result = "failed"

        device_name = random.choice(ANDROID_DEVICES)
        device_vendor_id = str(uuid.uuid4())
        client_launch_id = str(uuid.uuid4())
        launch_signature = str(time.time_ns())
        heartbeat_sid = str(uuid.uuid4())
        ad_session_id = str(uuid.uuid4())

        # Bind a coherent (system_locale, accept_language, x-discord-locale, tz)
        # tuple to this worker thread so every REST header + x-super-properties
        # stays internally consistent (HAR: fr-FR / fr / Europe/Paris, etc.).
        _pick_locale(self.region)

        token_logger.set_meta(
            device_name=device_name, device_vendor_id=device_vendor_id,
            client_launch_id=client_launch_id, launch_signature=launch_signature,
            heartbeat_sid=heartbeat_sid, proxy=proxy_raw or "none",
            fingerprint_mode="android",
            http_backend="okhttp" if self.use_okhttp else "tls_client",
        )

        if not hasattr(self, '_tls'):
            self._tls = threading.local()
        self._tls.log_tag = None
        self._tls.event_seq = 0
        self._tls.science_call_count = 0
        self._tls.science_test_id = None
        self._tls.app_start_ts = None
        self._tls.uuid_base = _make_uuid_base()
        self._tls.uuid_seq = 0

        _iso_proc = None
        _iso_port = None
        if self.isolated_proxy and self.use_okhttp:
            mgr = _OkHttpProxyManager.get()
            _iso_port, _iso_proc = mgr.spawn_isolated()
            if not _iso_port:
                self._log("ERROR", "Failed to spawn isolated Go proxy")
                return False

        try:
            sess = self._create_session(proxy_raw, isolated_port=_iso_port)
            _wrap_session_with_logger(sess, token_logger)
            self._setup_cloudflare_cookies(sess)
            proxy_url = self._normalize_proxy(proxy_raw) if proxy_raw else None

            token_logger.log_event("pre_auth_gateway", "starting")
            preauth_gw = _PreAuthGateway(proxy_raw, use_okhttp=self.use_okhttp)
            preauth_gw.start()
            token_logger.log_event("pre_auth_gateway", "connected")
            time.sleep(random.uniform(0.3, 0.8))

            self._log("DEBUG", f"Fetching fingerprint...")
            token_logger.log_event("fingerprint", "fetching")
            fingerprint = self._get_fingerprint(
                sess, device_name, device_vendor_id,
                client_launch_id, launch_signature, proxy_raw)
            if not fingerprint:
                self._log("WARN", f"Could not get fingerprint, using empty")
            token_logger.log_event("fingerprint", fingerprint or "empty")
            time.sleep(random.uniform(0.3, 0.8))

            username = _random_username()
            self._tls.log_tag = username
            password = _random_password()
            token_logger.set_meta(username=username, password="***")
            self._log("INFO", f"Username: {username}")
            try:
                email = self.mail.create_email(username)
                self._log("INFO", f"Email: {email}")
                token_logger.set_meta(email=email)
                token_logger.log_event("email_created", email)
            except Exception as e:
                self._log("ERROR", f"Email creation failed: {e}")
                token_logger.log_event("email_creation_failed", str(e))
                with self.stats_lock:
                    self.stats["failed"] += 1
                return False

            birthday = _random_birthday()
            token_logger.set_meta(birthday=birthday)

            self._tls.app_start_ts = int(time.time() * 1000)
            if self.science:
                # Fire the 5 cold-boot science batches a real Discord Android
                # client sends BEFORE the user interacts with the register flow
                # (app_opened, libdiscore_loaded, app_launch_completed, ...).
                token_logger.log_event("boot_science", "starting")
                self._send_boot_science(
                    sess, fingerprint, device_name, device_vendor_id,
                    client_launch_id, launch_signature, proxy_raw)

                token_logger.log_event("warmup_pre_register", "starting")
                self._warmup_pre_register(
                    sess, fingerprint, device_name, device_vendor_id,
                    client_launch_id, launch_signature, proxy_raw, username, password)

            token_logger.log_event("register", "starting")
            token = self._register(
                sess, email, username, password, birthday, fingerprint,
                device_name, device_vendor_id,
                client_launch_id, launch_signature, proxy_raw)
            if token == "INVALID_PROXY":
                self._log("INFO", f"Rotating proxy and restarting registration for {email}...")
                token_logger.log_event("proxy_rotation", f"old={proxy_raw}")
                proxy_raw = self._get_proxy()
                sess = self._create_session(proxy_raw)
                _wrap_session_with_logger(sess, token_logger)
                self._setup_cloudflare_cookies(sess)
                proxy_url = self._normalize_proxy(proxy_raw) if proxy_raw else None
                token_logger.set_meta(proxy=proxy_raw or "none")
                device_name = random.choice(ANDROID_DEVICES)
                device_vendor_id = str(uuid.uuid4())
                client_launch_id = str(uuid.uuid4())
                launch_signature = str(time.time_ns())
                self._tls.event_seq = 0
                self._tls.science_call_count = 0
                self._tls.science_test_id = None
                self._tls.app_start_ts = None
                if preauth_gw:
                    preauth_gw.close()
                preauth_gw = _PreAuthGateway(proxy_raw, use_okhttp=self.use_okhttp)
                preauth_gw.start()
                fingerprint = self._get_fingerprint(
                    sess, device_name, device_vendor_id,
                    client_launch_id, launch_signature, proxy_raw)
                self._tls.app_start_ts = int(time.time() * 1000)
                if self.science:
                    self._warmup_pre_register(
                        sess, fingerprint, device_name, device_vendor_id,
                        client_launch_id, launch_signature, proxy_raw, username, password)
                token_logger.log_event("register_retry", "after proxy rotation")
                token = self._register(
                    sess, email, username, password, birthday, fingerprint,
                    device_name, device_vendor_id,
                    client_launch_id, launch_signature, proxy_raw)
            if not token or token == "INVALID_PROXY":
                token_logger.log_event("register_failed", "no token returned")
                if hasattr(self.mail, 'recycle_email'):
                    self.mail.recycle_email(email)
                    self._log("INFO", f"Email {email} recycled back to pool")
                with self.stats_lock:
                    self.stats["failed"] += 1
                gen_result = "failed"
                return False

            token_logger.log_event("register_success", f"token={token[:30]}...")
            token_logger.set_meta(token_prefix=token[:30])
            with self.stats_lock:
                self.stats["generated"] += 1
            self._save(email, password, token, "tokens.txt")

            if preauth_gw:
                preauth_gw.close()
                preauth_gw = None

            token_logger.log_event("gateway_identify", "starting")
            gateway = None
            for _gw_attempt in range(2):
                try:
                    _gw = GatewayKeepalive(
                        token, device_name, device_vendor_id,
                        client_launch_id, launch_signature,
                        heartbeat_session_id=heartbeat_sid,
                        proxy_raw=proxy_raw, use_okhttp=self.use_okhttp)
                    if _gw.start():
                        token_logger.log_event("gateway_identify", "connected")
                        self._log("INFO", f"Gateway IDENTIFY connected")
                        gateway = _gw
                        break
                    else:
                        if _gw_attempt == 0:
                            self._log("WARN", f"Gateway IDENTIFY failed, retrying...")
                            time.sleep(1.0)
                        else:
                            token_logger.log_event("gateway_identify", "failed")
                            self._log("ERROR", f"Gateway IDENTIFY failed after retry")
                except Exception as e:
                    if _gw_attempt == 1:
                        token_logger.log_event("gateway_identify", f"error: {e}")
                        self._log("ERROR", f"Gateway error after retry: {e}")
                    else:
                        self._log("WARN", f"Gateway error: {e}, retrying...")
                        time.sleep(1.0)

            time.sleep(random.uniform(1.0, 2.0))

            token_logger.log_event("email_verify", "starting")
            email_ok = False
            for _ev_attempt in range(3):
                try:
                    verify_result = self._verify_email(
                        sess, token, email,
                        device_name, device_vendor_id,
                        client_launch_id, launch_signature, proxy_raw,
                        heartbeat_sid=heartbeat_sid)
                    if verify_result == "CAPTCHA_FLAGGED" and _ev_attempt < 2:
                        old_proxy = proxy_raw
                        proxy_raw = self._get_proxy()
                        self._log("WARN", f"Rotating proxy for email verify: {old_proxy[:20]}... → {proxy_raw[:20]}...")
                        sess = self._create_session(proxy_raw)
                        _wrap_session_with_logger(sess, token_logger)
                        self._setup_cloudflare_cookies(sess)
                        time.sleep(random.uniform(1.0, 3.0))
                        continue
                    if verify_result and verify_result != "CAPTCHA_FLAGGED":
                        email_ok = True
                        old_token = token
                        token = verify_result
                        if token != old_token:
                            self._log("SUCCESS", f"Switched to new post-verify token")
                        token_logger.log_event("email_verify", "success")
                        with self.stats_lock:
                            self.stats["email_verified"] += 1
                            ev_count = self.stats["email_verified"]
                        self._save(email, password, token, "email_verified.txt")
                        self._check_batch_pause(ev_count)
                    else:
                        token_logger.log_event("email_verify", "failed")
                    break
                except Exception as e:
                    self._log("ERROR", f"Email verification error: {e}")
                    token_logger.log_event("email_verify_error", str(e))
                    break

            phone_locked = False
            banned = False
            phone_enabled = self.phone_config and self.phone_config.get("enabled")
            has_phone_key = self.phone_config and self.phone_config.get("hero_sms_api_key")

            if email_ok:
                proxy_url = self._normalize_proxy(proxy_raw) if proxy_raw else None
                _bh_test = {k: v for k, v in _build_headers(
                    device_name, device_vendor_id, client_launch_id, launch_signature,
                    token=token, client_heartbeat_session_id=heartbeat_sid,
                ).items() if k != "Content-Type"}

                # Derive the self user_id from the token (standard discord
                # token layout: <user_id_b64>.<ts>.<hmac>). Needed because the
                # real client hits /users/{self_id}/profile?type=you_screen
                # (HAR entry 80) — no bare /users/@me or /settings-proto/2
                # GETs anywhere in the HAR. Using those is an insta-ban tell.
                try:
                    _self_id = base64.b64decode(
                        token.split(".")[0] + "=" * (-len(token.split(".")[0]) % 4)
                    ).decode("utf-8", errors="ignore")
                    if not _self_id.isdigit():
                        _self_id = "@me"
                except Exception:
                    _self_id = "@me"

                def _check_token_status():
                    try:
                        url = (
                            f"https://discord.com/api/v9/users/{_self_id}/profile"
                            "?type=you_screen"
                            "&with_mutual_guilds=false"
                            "&with_mutual_friends=false"
                            "&with_mutual_friends_count=false"
                        )
                        r = sess.get(url, headers=_bh_test,
                                     proxy=proxy_url, timeout_seconds=10)
                        if r.status_code == 200:
                            return "alive"
                        if r.status_code == 401:
                            return "banned"
                        if r.status_code == 403:
                            body = (r.text or "")[:500].lower()
                            if ("40002" in body or "phone" in body or
                                    "verify your account" in body):
                                return "locked"
                            return "locked"
                        return "error"
                    except Exception:
                        return "error"

                token_logger.log_event("status_check", "immediate check")
                status = _check_token_status()
                token_logger.log_event("status_check_result", status)
                if status == "banned":
                    banned = True
                    gen_result = "banned"
                    self._log("ERROR", f"Account is BANNED (401) after email verify")
                    self._purge_token(token)
                elif status == "locked":
                    phone_locked = True
                    gen_result = "phone_locked"
                    self._log("ERROR", f"Account is phone-locked immediately after email verify")
                elif status == "error":
                    phone_locked = True
                    gen_result = "phone_locked"
                elif status == "alive":
                    if phone_enabled:
                        gen_result = "success"
                    else:
                        wait1 = random.uniform(110, 130)
                        self._log("DEBUG", f"Token alive — check 1/2 in {wait1:.0f}s...")
                        time.sleep(wait1)
                        status2 = _check_token_status()
                        if status2 == "locked" or status2 == "error":
                            phone_locked = True
                            gen_result = "phone_locked"
                        elif status2 == "banned":
                            banned = True
                            gen_result = "banned"
                            self._purge_token(token)
                        else:
                            wait2 = random.uniform(170, 200)
                            self._log("SUCCESS", f"Still alive — check 2/2 in {wait2:.0f}s...")
                            time.sleep(wait2)
                            status3 = _check_token_status()
                            if status3 == "locked" or status3 == "error":
                                phone_locked = True
                                gen_result = "phone_locked"
                            elif status3 == "banned":
                                banned = True
                                gen_result = "banned"
                                self._purge_token(token)
                            else:
                                gen_result = "success"
                                self._log("SUCCESS", f"Account confirmed alive after 5min wait")

            if phone_locked and token:
                self._move_to_locked(token, email, password)

            if banned:
                try:
                    self.mail.delete_mailbox(email)
                except Exception:
                    pass
                return True

            needs_phone = phone_enabled or (phone_locked and has_phone_key)

            if self.humanize and email_ok and not phone_locked and not banned and gen_result == "success":
                _h_args = (sess, token, device_name, device_vendor_id,
                           client_launch_id, launch_signature, heartbeat_sid, proxy_raw)
                def _bg_humanize(args):
                    time.sleep(random.uniform(3.0, 8.0))
                    h_sess, h_token, h_dev, h_vid, h_lid, h_lsig, h_hbsid, h_proxy = args
                    self._log("SUCCESS", f"Humanizing account (bio + avatar)...")
                    self._humanize_account(h_sess, h_token, h_dev, h_vid,
                                           h_lid, h_lsig, h_hbsid, h_proxy)
                threading.Thread(target=_bg_humanize, args=(_h_args,), daemon=True).start()

            if needs_phone:
                time.sleep(random.uniform(2.0, 4.0))
                try:
                    phone_verified = self._verify_phone(
                        sess, token, password,
                        device_name, device_vendor_id,
                        client_launch_id, launch_signature,
                        heartbeat_sid, proxy_raw,
                        phone_locked=phone_locked)
                    if phone_verified:
                        with self.stats_lock:
                            self.stats["phone_verified"] += 1
                        self._save(email, password, token, "phone_verified.txt")
                except Exception as e:
                    self._log("ERROR", f"Phone verification error: {e}")

            try:
                self.mail.delete_mailbox(email)
            except Exception:
                pass

            return True

        except Exception as e:
            self._log("ERROR", f"Generation failed: {e}")
            token_logger.log_event("generation_exception", str(e))
            gen_result = "failed"
            with self.stats_lock:
                self.stats["failed"] += 1
            return False
        finally:
            try:
                token_logger.save(gen_result)
            except Exception:
                pass
            if preauth_gw:
                try:
                    preauth_gw.close()
                except Exception:
                    pass
            if gateway:
                if gen_result == "success":
                    try:
                        self._keep_gateway_alive(gateway, username)
                        self._drain_expired_gateways()
                    except Exception:
                        try: gateway.stop()
                        except Exception: pass
                else:
                    try: gateway.stop()
                    except Exception: pass
            if _iso_proc:
                _OkHttpProxyManager.kill_isolated(_iso_proc)

    def run(self, count: int = 1, threads: int = 1):
        if self.use_okhttp and not self.isolated_proxy:
            _OkHttpProxyManager.set_pool_size(threads)

        print(f"\n{'='*50}")
        print(f"  Account Generator - Discord Android 324.16")
        print(f"  Solver: {' > '.join(self.solver_priority)} | Threads: {threads} | Count: {count}")
        print(f"  Anti-ban: Science telemetry + OkHttp (exact Android fingerprint)")
        print(f"{'='*50}\n")

        from queue import Queue
        q = Queue()
        for _ in range(count):
            q.put(True)

        def worker():
            while not q.empty():
                try:
                    q.get_nowait()
                except Exception:
                    break
                self.generate_one()
                q.task_done()
                if not q.empty():
                    time.sleep(random.uniform(1.0, 3.0))

        workers = []
        actual_threads = min(threads, count)
        for i in range(actual_threads):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            workers.append(t)
            if i >= 4 and i < actual_threads - 1:
                time.sleep(random.uniform(0.5, 1.5))

        for t in workers:
            t.join()

        print(f"\n{'='*50}")
        print(f"  Results:")
        print(f"  Generated:      {self.stats['generated']}")
        print(f"  Email verified:  {self.stats['email_verified']}")
        print(f"  Phone verified:  {self.stats['phone_verified']}")
        print(f"  Failed:          {self.stats['failed']}")
        print(f"{'='*50}\n")

        with self._kept_gateways_lock:
            remaining = len(self._kept_gateways)
        if remaining > 0:
            self._log("INFO", f"Waiting for {remaining} gateway(s) to complete keep-alive ({self.GATEWAY_KEEP_ALIVE_SECONDS}s)...")
            while True:
                self._drain_expired_gateways()
                with self._kept_gateways_lock:
                    remaining = len(self._kept_gateways)
                if remaining == 0:
                    break
                time.sleep(10)
            self._log("SUCCESS", f"All gateway keep-alive periods completed.")
