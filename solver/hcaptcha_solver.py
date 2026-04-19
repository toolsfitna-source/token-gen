"""
hCaptcha HSJ solver — main API.

Flow: checksiteconfig → PoW → getcaptcha → silent pass OR image challenge (nopecha) → token.

Usage:
    from solver import HCaptchaSolver
    solver = HCaptchaSolver(proxy="http://user:pass@host:port")
    token = solver.solve(sitekey="a9b5fb07-...", host="discord.com", rqdata="...")
"""

import base64
import json
import os
import random
import sys
import time
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

from http_client import _OkHttpSession as _HttpSession

from .core.config import SolveConfig, Screen, PopularCaptcha_VERSION, REDUCED_UA
from .core.checkcaptcha_helper import (
    solve_and_encrypt_n,
    encrypt_n_value,
    solve_pow_answer,
    build_epic_cfg,
    apply_request_overrides,
    is_firefox_user_agent,
)
from .core.motion import generate_motion_data, generate_challenge_motion_data
from .core.hsj import random_widget_id


# ═════════════════════════════════════════════════════════════════
# OMOcaptcha image recognition API
# ═════════════════════════════════════════════════════════════════

_NOPECHA_API = "https://api.nopecha.com/v1"

def _load_nopecha_key() -> str:
    """Load nopecha key from env or config/api_keys.json."""
    env_key = os.environ.get("NOPECHA_API_KEY", "")
    if env_key:
        return env_key
    try:
        keys_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "api_keys.json")
        import json as _j
        with open(keys_path, "r", encoding="utf-8") as f:
            return _j.load(f).get("nopecha", "")
    except Exception:
        return ""

_NOPECHA_KEY = _load_nopecha_key()

_SOLVER_DEBUG = os.environ.get("HSJ_DEBUG", "0") == "1"


def _log_cap(msg: str):
    if _SOLVER_DEBUG:
        print(f"\033[96m{msg}\033[0m")


def _log_ok(msg: str):
    print(f"\033[92m{msg}\033[0m")


def _log_err(msg: str):
    print(f"\033[91m{msg}\033[0m")


def set_solver_debug(enabled: bool):
    global _SOLVER_DEBUG
    _SOLVER_DEBUG = enabled


class NopechaImageSolver:
    """Solve hCaptcha image challenges via nopecha.com recognition API.

    Sends the raw getcaptcha response (request_type, requester_question, tasklist)
    directly to nopecha — no need to download images ourselves.
    """

    def __init__(self, api_key: str = ""):
        self.api_key = api_key or _NOPECHA_KEY
        self._sess = _HttpSession()  # OkHttp for nopecha too

    def solve_challenge(self, gc_data: dict, timeout: int = 30) -> Optional[Any]:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Basic {self.api_key}",
        }
        payload = {
            "data": {
                "request_type": gc_data.get("request_type", ""),
                "requester_question": gc_data.get("requester_question", {}),
                "tasklist": gc_data.get("tasklist", []),
            }
        }
        examples = gc_data.get("requester_question_example")
        if examples:
            payload["data"]["requester_question_example"] = examples

        try:
            r = self._sess.post(
                f"{_NOPECHA_API}/recognition/hcaptcha",
                headers=headers, json=payload, timeout_seconds=15,
            )
            data = r.json()
        except Exception as e:
            _log_err(f"[nopecha] submit failed: {e}")
            return None

        if "error" in str(data.get("message", "")).lower() or data.get("code"):
            _log_err(f"[nopecha] submit error: {data}")
            return None

        job_id = data.get("data")
        if not job_id or not isinstance(job_id, str):
            _log_err(f"[nopecha] no job_id: {data}")
            return None

        _log_cap(f"[nopecha] job submitted: {job_id[:30]}...")

        deadline = time.time() + timeout
        time.sleep(1)
        while time.time() < deadline:
            try:
                r = self._sess.get(
                    f"{_NOPECHA_API}/recognition/hcaptcha",
                    params={"id": job_id},
                    headers=headers, timeout_seconds=15,
                )
                result = r.json()
            except Exception:
                time.sleep(1)
                continue

            if result.get("code") == 14:
                time.sleep(0.5)
                continue

            if result.get("code"):
                _log_err(f"[nopecha] error: code={result.get('code')} msg={result.get('message')}")
                return None

            solution = result.get("data")
            if solution is not None:
                _log_cap(f"[nopecha] solved!")
                return solution

            time.sleep(0.5)

        _log_err("[nopecha] timeout")
        return None


# ═════════════════════════════════════════════════════════════════
# Public solver class
# ═════════════════════════════════════════════════════════════════

class HCaptchaSolver:
    """Self-contained hCaptcha HSJ solver.

    Args:
        proxy: HTTP proxy URL (http://user:pass@host:port).
        user_agent: Browser UA for hCaptcha requests (default: Firefox).
        timeout: HTTP request timeout in seconds.
    """

    def __init__(
        self,
        proxy: str = "",
        user_agent: str = "",
        timeout: int = 20,
        omocaptcha_key: str = "",
    ):
        self.proxy = proxy
        self.ua = user_agent or REDUCED_UA
        self.timeout = timeout
        self.image_solver = NopechaImageSolver(api_key=omocaptcha_key)

    # ─── ADB HSW runner (phone generates real N tokens) ──────────

    _adb_runner = None
    _adb_lock = __import__("threading").Lock()

    @classmethod
    def _get_adb_runner(cls):
        """Lazy-init a shared AdbHSWRunner connected to the phone."""
        with cls._adb_lock:
            if cls._adb_runner is None:
                try:
                    import sys
                    # Add Raider path for imports
                    raider_path = os.path.join(os.path.dirname(os.path.dirname(
                        os.path.dirname(os.path.abspath(__file__)))), "")
                    if raider_path not in sys.path:
                        sys.path.insert(0, raider_path)
                    from hcap.captcha.adb_hsw import AdbHSWRunner
                    runner = AdbHSWRunner(cdp_port=9333)
                    runner.setup()
                    cls._adb_runner = runner
                    _log_ok("[hsj] ADB HSW runner connected to phone Chrome")
                except Exception as e:
                    _log_err(f"[hsj] ADB HSW runner failed: {e}")
                    cls._adb_runner = False  # Mark as failed, don't retry
            return cls._adb_runner if cls._adb_runner else None

    # ─── HTTP session ────────────────────────────────────────────

    def _make_session(self):
        """Use OkHttp+Conscrypt for identical TLS fingerprint as Discord."""
        return _HttpSession(self.proxy)

    # ─── Config builder ──────────────────────────────────────────

    def _build_cfg(
        self,
        sitekey: str,
        host: str,
        href: str = "",
    ) -> SolveConfig:
        """Build a SolveConfig for the target site.

        If self.context is set (friend/dm/register), the captured phone HSJ profile's
        navigator + screen + href are used as ground truth for the ENTIRE cfg —
        so HTTP headers, motion data timings, and the Node sandbox all share the
        same fingerprint.
        """
        # Load captured phone profile — ground truth for all fingerprint bits.
        # If caller passed mobile_device_override (per-token device lock), use
        # that specific entry; otherwise let load_profile pick at random.
        profile = None
        ctx = getattr(self, "context", None)
        override = getattr(self, "mobile_device_override", None)
        if ctx:
            try:
                if override:
                    from . import phone_profile as _pp
                    _orig = _pp.pick_mobile_device
                    _pp.pick_mobile_device = lambda: override
                    try:
                        profile = _pp.load_profile(ctx)
                    finally:
                        _pp.pick_mobile_device = _orig
                else:
                    from .phone_profile import load_profile
                    profile = load_profile(ctx)
            except Exception:
                profile = None

        pnav = {}
        pscr = {}
        pdpr = None
        phref = None
        if profile:
            comps = profile.get("components") or {}
            if isinstance(comps, dict):
                pnav = comps.get("navigator") or {}
                pscr = comps.get("screen") or {}
                pdpr = comps.get("device_pixel_ratio")
            phref = profile.get("href")

        device = getattr(self, 'device_info', None) or {}
        device_model = device.get("device_model", "ELI-NX9")
        device_brand = device.get("device_brand", "HONOR")

        # UA: profile wins if present, otherwise synthesize from device_info
        webview_ua = pnav.get("user_agent") or (
            f"Mozilla/5.0 (Linux; Android 16; {device_model} "
            f"Build/{device_brand}{device_model.replace('-', '')}; wv) "
            f"AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 "
            f"Chrome/146.0.7680.177 Mobile Safari/537.36"
        )

        # Screen: profile wins if present
        screen_w = pscr.get("width") or device.get("smallest_screen_width", 434)
        screen_h = pscr.get("height") or int(screen_w * 2.2)
        avail_w = pscr.get("avail_width") or screen_w
        avail_h = pscr.get("avail_height") or int(screen_w * 2.1)
        dpr = pdpr if pdpr else 2.5

        nav_platform = pnav.get("platform") or "Linux aarch64"
        nav_language = pnav.get("language") or "fr-FR"
        nav_languages = pnav.get("languages") or ["fr-FR", "fr", "en-US", "en"]
        nav_touch = pnav.get("max_touch_points") or 5

        # Use the profile's captured href only if caller didn't provide one
        eff_href = href or phref or f"https://{host}/"

        cfg = build_epic_cfg(
            user_agent_override=webview_ua,
            target_host=host,
            target_sitekey=sitekey,
            target_href=eff_href,
        )
        cfg = apply_request_overrides(
            cfg,
            host_override=host,
            sitekey_override=sitekey,
            href_override=eff_href,
            rqdata_required=False,
        )

        # Always apply cfg-level fingerprint overrides (outside the foox1_template block)
        try:
            cfg.platform = nav_platform
            cfg.max_touch_points = nav_touch
            cfg.device_pixel_ratio = dpr
            cfg.screen.width = screen_w
            cfg.screen.height = screen_h
            cfg.screen.avail_width = avail_w
            cfg.screen.avail_height = avail_h
            cfg.screen.color_depth = pscr.get("color_depth", 24)
            cfg.screen.pixel_depth = pscr.get("pixel_depth", 24)
            # language at cfg level (some hsj builders read from here)
            if hasattr(cfg, "language"):
                cfg.language = nav_language
            if hasattr(cfg, "languages"):
                cfg.languages = nav_languages
        except Exception:
            pass

        # Patch foox1 profile to match Discord Android WebView
        if isinstance(cfg.profile_data, dict):
            tmpl = cfg.profile_data.get("foox1_template")
            if isinstance(tmpl, dict):
                comps = tmpl.get("components", {})
                nav = comps.get("navigator", {})

                # Apply profile fingerprint (or fallback defaults)
                nav["user_agent"] = webview_ua
                nav["platform"] = nav_platform
                nav["language"] = nav_language
                nav["languages"] = nav_languages
                nav["max_touch_points"] = nav_touch
                if pnav.get("hardware_concurrency") is not None:
                    nav["hardware_concurrency"] = pnav["hardware_concurrency"]
                if pnav.get("device_memory") is not None:
                    nav["device_memory"] = pnav["device_memory"]
                if pnav.get("vendor") is not None:
                    nav["vendor"] = pnav["vendor"]

                comps["screen"] = {
                    "color_depth": pscr.get("color_depth", 24),
                    "pixel_depth": pscr.get("pixel_depth", 24),
                    "width": screen_w, "height": screen_h,
                    "avail_width": avail_w, "avail_height": avail_h,
                }
                comps["device_pixel_ratio"] = dpr
                comps["has_touch"] = True
                comps["chrome"] = True
                comps["navigator"] = nav
                tmpl["components"] = comps

                # Patch events (screen, GPU, timezone, navigator)
                try:
                    from .patch_hsj_events import patch_profile_events
                    tmpl = patch_profile_events(tmpl, device)
                except Exception:
                    pass

                cfg.profile_data["foox1_template"] = tmpl

        # Inject captured profile as static_fp_template so core/hsj.py
        # replays the authentic phone fingerprint (events, components, stack_data,
        # perf, rand, canvas_hash, webgl_hash, audio_hash, etc.) — only proof_spec
        # and stamp are refreshed per-challenge. This is what unlocks silent pass.
        if profile:
            if not isinstance(cfg.profile_data, dict):
                cfg.profile_data = {}
            # CRITICAL: refresh timestamp-bearing events in the static template
            # so hCaptcha doesn't see stale session data on every solve. Without
            # this, TIMESTAMP / TIMESTAMP2 events keep their capture-time values
            # and scoring degrades to image challenges.
            try:
                from .patch_hsj_events import patch_profile_events
                profile = patch_profile_events(profile, device)
            except Exception:
                pass
            cfg.profile_data["static_fp_template"] = profile
            cfg.profile_data["static_fp_enabled"] = True
            _log_cap(f"[hsj] cfg locked to phone profile (UA={webview_ua[:55]}... "
                     f"screen={screen_w}x{screen_h} dpr={dpr}) static_fp=ON")

        return cfg

    # ─── hCaptcha API helpers ────────────────────────────────────

    def _generate_n(self, c_payload: dict, cfg, label: str = "") -> str:
        """Generate N token.

        With a captured phone profile injected as static_fp_template in cfg:
            1. Python brux solve_and_encrypt_n → replays authentic phone
               fingerprint (events/components/hashes) with fresh proof_spec+stamp
               for this challenge. This is the silent-pass path.
        Without a profile:
            1. Node.js hsj.js (sandbox patched with what we have)
            2. Fallback to Python synthetic.
        """
        has_profile = False
        try:
            pd = getattr(cfg, "profile_data", None) or {}
            has_profile = isinstance(pd.get("static_fp_template"), dict)
        except Exception:
            pass

        if has_profile:
            try:
                n = solve_and_encrypt_n(c_payload, cfg)
                if n:
                    _log_cap(f"[hsj] {label} N from phone profile replay: {len(n)} chars")
                    return n
                _log_cap(f"[hsj] {label} profile replay returned empty, falling back to Node.js")
            except Exception as e:
                _log_cap(f"[hsj] {label} profile replay failed: {e}, falling back to Node.js")

        # Fallback: Node.js hsj.js with sandbox overrides
        jwt = c_payload.get("req", "") if isinstance(c_payload, dict) else ""
        if jwt:
            try:
                from .hsj_runner import get_n_token
                profile_path = None
                try:
                    from .phone_profile import profile_path_for
                    p = profile_path_for(getattr(self, "context", None))
                    profile_path = str(p) if p else None
                except ImportError:
                    pass
                n = get_n_token(jwt, timeout=25, profile_path=profile_path)
                if n:
                    _log_cap(f"[hsj] {label} N from Node.js hsj.js: {len(n)} chars")
                    return n
                _log_cap(f"[hsj] {label} Node.js hsj.js failed, falling back to Python synthetic")
            except ImportError:
                _log_cap(f"[hsj] {label} hsj_runner not found, using Python synthetic")
            except Exception as e:
                _log_cap(f"[hsj] {label} Node.js error: {e}, falling back to Python synthetic")
        return solve_and_encrypt_n(c_payload, cfg)

    def _build_headers(self, cfg: SolveConfig, cookie: str = "",
                       accept: str = "application/json",
                       content_type: str = None) -> dict:
        """Build hCaptcha request headers matching Discord Android SDK."""
        headers = {
            "accept": accept,
            "content-type": content_type or "text/plain",
            "sec-ch-ua-platform": '"Android"',
            "user-agent": cfg.ua,
            "sec-ch-ua": '"Not(A:Brand";v="99", "Android WebView";v="146", "Chromium";v="146"',
            "sec-ch-ua-mobile": "?1",
            "origin": "https://newassets.hcaptcha.com",
            "x-requested-with": "com.discord",
            "sec-fetch-site": "same-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "sec-fetch-storage-access": "active",
            "referer": "https://newassets.hcaptcha.com/",
            "accept-language": "en-US,en;q=0.9",
        }
        if cookie:
            headers["cookie"] = cookie
        if content_type is None:
            headers["content-type"] = "text/plain"
        return headers

    def _perf_now(self, ms: float) -> float:
        return round(ms + random.uniform(-0.5, 0.5), 13)

    def _compact_json(self, obj: Any) -> str:
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)

    # ─── Main solve flow ─────────────────────────────────────────

    def solve(
        self,
        sitekey: str,
        host: str,
        rqdata: str = "",
        href: str = "",
        max_retries: int = 2,
        context: str = None,
    ) -> Optional[str]:
        """Solve an hCaptcha challenge and return the pass token.

        Args:
            sitekey: hCaptcha site key (from Discord's captcha_sitekey).
            host: Target host (e.g. "discord.com").
            rqdata: Request data (from Discord's captcha_rqdata).
            href: Page URL where captcha appears.
            max_retries: Number of retry attempts.
            context: Usage context ("friend", "dm", "register") — selects the
                     matching captured phone HSJ profile. Defaults to "friend"
                     in phone_profile.DEFAULT_CONTEXT.

        Returns:
            Captcha pass token string, or None on failure.
        """
        self.context = context
        # Single attempt only — don't block with retries, let caller fallback
        try:
            token = self._solve_once(sitekey, host, rqdata, href)
            if token:
                return token
        except Exception as e:
            _log_err(f"[hsj] exception: {type(e).__name__}: {e}")
        return None

    def _prefetch_hcaptcha_assets(self, session, cfg):
        """Pre-fetch the assets the phone WebView loads when opening captcha.

        Order mirrors what chrome://inspect showed on the real phone:
            1. GET https://hcaptcha.com/1/api.js?render=explicit&onload=...
            2. GET https://newassets.hcaptcha.com/captcha/v1/<ver>/static/i18n/<lang>.json
            3. GET https://newassets.hcaptcha.com/captcha/v1/<ver>/static/hcaptcha.html

        Errors are non-fatal — these requests are optional fingerprint signals.
        """
        lang = getattr(cfg, "lang", "fr") or "fr"
        version = cfg.version
        host_param = cfg.host or f"{cfg.sitekey}.react-native.hcaptcha.com"
        asset_headers = {
            "user-agent": cfg.ua,
            "accept-language": "en-US,en;q=0.9",
            "sec-ch-ua-platform": '"Android"',
            "sec-ch-ua": '"Not(A:Brand";v="99", "Android WebView";v="146", "Chromium";v="146"',
            "sec-ch-ua-mobile": "?1",
            "x-requested-with": "com.discord",
        }

        targets = [
            (f"https://hcaptcha.com/1/api.js?render=explicit&onload=onloadCallback&host={host_param}&hl={lang}",
             {"accept": "*/*", "sec-fetch-dest": "script", "sec-fetch-mode": "no-cors", "sec-fetch-site": "cross-site"}),
            (f"https://newassets.hcaptcha.com/captcha/v1/{version}/static/i18n/{lang}.json",
             {"accept": "*/*", "sec-fetch-dest": "empty", "sec-fetch-mode": "cors", "sec-fetch-site": "same-site",
              "origin": "https://newassets.hcaptcha.com", "referer": f"https://newassets.hcaptcha.com/captcha/v1/{version}/static/hcaptcha.html"}),
            (f"https://newassets.hcaptcha.com/captcha/v1/{version}/static/hcaptcha.html",
             {"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
              "sec-fetch-dest": "iframe", "sec-fetch-mode": "navigate", "sec-fetch-site": "cross-site"}),
        ]
        fetched = 0
        for url, extra in targets:
            try:
                h = {**asset_headers, **extra}
                session.get(url, headers=h, timeout_seconds=self.timeout)
                fetched += 1
            except Exception:
                pass
        _log_cap(f"[hsj] step0 prefetched {fetched}/{len(targets)} hCaptcha assets")

    def _get_current_profile_path(self, cfg) -> Optional[str]:
        """Find the file path of the foox1 template currently loaded in cfg."""
        try:
            pd = getattr(cfg, "profile_data", None) or {}
            from pathlib import Path
            foox1_dir = Path(os.path.dirname(os.path.abspath(__file__))) / "profiles" / "foox1"

            # Method 1: foox1_template has "path" field
            tmpl = pd.get("foox1_template") or {}
            if isinstance(tmpl, dict):
                path = tmpl.get("path", "")
                if path and os.path.exists(path):
                    return path
                name = tmpl.get("name", "")
                if name:
                    f = foox1_dir / name
                    if f.exists():
                        return str(f)

            # Method 2: profile_data has "foox1_name"
            name = pd.get("foox1_name") or pd.get("profile_name") or ""
            if name:
                f = foox1_dir / name
                if f.exists():
                    return str(f)

            # Method 3: foox1_pool._LAST_TEMPLATE_NAME
            try:
                import foox1_pool
                last = foox1_pool._LAST_TEMPLATE_NAME
                if last:
                    f = foox1_dir / last
                    if f.exists():
                        return str(f)
            except Exception:
                pass

            return None
        except Exception:
            return None

    def _solve_once(
        self,
        sitekey: str,
        host: str,
        rqdata: str,
        href: str,
    ) -> Optional[str]:
        """Single solve attempt — uses phone for HSW N generation if available."""
        _log_cap(f"[hsj] solve_once sitekey={sitekey[:16]}... host={host} rqdata={'yes' if rqdata else 'no'}")

        # ADB phone disabled — use HSJ solver
        adb = None
        use_phone = False

        cfg = self._build_cfg(sitekey, host, href)
        # Force host to react-native for Android
        cfg.host = host
        cfg.sitekey = sitekey
        _log_cap(f"[hsj] cfg built: ua={cfg.ua[:40]}... host={cfg.host[:40]}")

        session = self._make_session()
        hmt_id = str(uuid.uuid4())
        wid = random_widget_id()

        # Step 1: checksiteconfig
        # ── Helper: build p_e (proof evidence of HSW loading failure) ──
        def _build_p_e(version, failed_types, worker_loc=""):
            worker_hash = worker_loc or version
            base_url = f"https://newassets.hcaptcha.com/captcha/v1/{version}/static/hcaptcha.html"
            errors = []
            for ts_ms, proof_type in failed_types:
                errors.append(
                    f"{ts_ms}:{proof_type}:[v]:Loading Error: "
                    f"https://newassets.hcaptcha.com/c/{worker_hash}/{proof_type}.js\n"
                    f"Error: Loading Error: https://newassets.hcaptcha.com/c/{worker_hash}/{proof_type}.js\n"
                    f"    at s.onerror ({base_url}:14:99760)"
                )
            return json.dumps(errors, separators=(",", ":"))

        def _extract_worker_location(c_pay):
            req_token = c_pay.get("req", "") if isinstance(c_pay, dict) else ""
            if not req_token:
                return ""
            try:
                from .core.hsj import parse_jwt
                jwt_p = parse_jwt(req_token)
                loc = jwt_p.get("l", "")
                if "/c/" in loc:
                    return loc.split("/c/")[-1].rstrip("/")
            except Exception:
                pass
            return ""

        ekeys = []

        # Step 0: Pre-fetch hCaptcha WebView assets (api.js, hcaptcha.html, i18n)
        # before checksiteconfig — mirrors what the real phone WebView does on
        # captcha open. hCaptcha tracks these fetches as part of "is this a real
        # browser session" scoring.
        if getattr(self, "context", None):
            try:
                self._prefetch_hcaptcha_assets(session, cfg)
            except Exception as e:
                _log_cap(f"[hsj] asset prefetch failed (non-fatal): {e}")

        # Step 1: checksiteconfig
        _log_cap(f"[hsj] step1: checksiteconfig...")
        csc_start = time.time()
        spst = 0
        url = (
            f"https://api.hcaptcha.com/checksiteconfig?"
            f"v={cfg.version}&host={cfg.host}&sitekey={cfg.sitekey}&sc=1&swa=1&spst={spst}"
        )
        headers = self._build_headers(cfg, cookie=f"hmt_id={hmt_id}")
        try:
            resp = session.post(url, headers=headers, timeout_seconds=self.timeout)
            csc_data = resp.json()
        except Exception as e:
            _log_err(f"[hsj] checksiteconfig failed: {e}")
            return None
        csc_time = (time.time() - csc_start) * 1000
        _log_cap(f"[hsj] checksiteconfig: status={getattr(resp, 'status_code', '?')} pass={csc_data.get('pass')} c_type={csc_data.get('c', {}).get('type')}")

        c_payload = csc_data.get("c", {})
        if not c_payload:
            _log_err(f"[hsj] no c_payload in checksiteconfig response: {str(csc_data)[:200]}")
            return None

        # Extract worker location for p_e error messages
        worker_location = _extract_worker_location(c_payload)

        # Build first p_e — tells hCaptcha "HSW loading failed, falling back"
        failure_ts = int(time.time() * 1000) - random.randint(50, 200)
        first_p_e = _build_p_e(cfg.version, [(failure_ts, "hsw")], worker_location)

        # Step 2: Generate motion data — replay phone template if context profile set
        _log_cap(f"[hsj] step2: generating motion data...")
        motion_data = None
        if getattr(self, "context", None):
            try:
                from .phone_motion import build_getcaptcha_fail_motion
                _dev = (cfg.profile_data or {}).get("static_fp_template", {}).get("_picked_device")
                motion_data = build_getcaptcha_fail_motion(widget_id=wid, href=cfg.href, device=_dev)
                if motion_data:
                    _log_cap(f"[hsj] step2 using phone motion template (fail)")
            except Exception as e:
                _log_cap(f"[hsj] step2 phone motion failed: {e}, falling back to brux")
        if motion_data is None:
            motion_data = generate_motion_data(cfg, prev_pass=False, ekeys=ekeys, wid=wid)

        # Step 3: getcaptcha#1 (n=fail, with p_e showing HSW load failure)
        _log_cap(f"[hsj] step3: getcaptcha (n=fail)...")
        gc_start = time.time()
        form = {
            "v": cfg.version,
            "sitekey": cfg.sitekey,
            "host": cfg.host,
            "hl": cfg.lang,
            "motionData": self._compact_json(motion_data),
            "pdc": self._compact_json({
                "s": int(time.time() * 1000),
                "n": 1,
                "p": random.randint(4, 8),
                "gcs": random.randint(1500, 4000),
            }),
            "pem": self._compact_json({
                "csc": self._perf_now(csc_time),
                "csch": "api.hcaptcha.com",
                "cscrt": 0,
                "cscft": self._perf_now(csc_time),
                "gc": self._perf_now(random.uniform(60, 150)),
                "gch": "api.hcaptcha.com",
                "gcrt": 0,
                "gcft": self._perf_now(random.uniform(60, 150)),
            }),
            "n": "fail",
            "c": self._compact_json(c_payload),
            "p_e": first_p_e,
        }
        if rqdata:
            form["rqdata"] = rqdata

        headers = self._build_headers(
            cfg,
            cookie=f"hmt_id={hmt_id}",
            content_type="application/x-www-form-urlencoded",
        )
        try:
            resp = session.post(
                f"https://api.hcaptcha.com/getcaptcha/{cfg.sitekey}",
                headers=headers,
                data=urlencode(form),
                timeout_seconds=self.timeout,
            )
            gc_data = resp.json()
        except Exception as e:
            _log_err(f"[hsj] getcaptcha (fail) failed: {e}")
            return None
        gc_time = (time.time() - gc_start) * 1000
        _log_cap(f"[hsj] getcaptcha1: status={getattr(resp, 'status_code', '?')} pass={gc_data.get('pass')} type={gc_data.get('request_type', 'none')} tasks={len(gc_data.get('tasklist', []))}")

        # Track ekeys like brux does
        fail_key = gc_data.get("key")
        if fail_key:
            ekeys.append([str(fail_key), wid])

        # Check if we got a silent pass
        if gc_data.get("pass"):
            token = gc_data.get("generated_pass_UUID")
            _log_ok(f"[hsj] solved (silent pass): {token[:40]}...")
            return token

        # Step 4: Got new PoW challenge — solve it properly
        c_payload_2 = gc_data.get("c", c_payload)
        _log_cap(f"[hsj] step4: solving PoW for second getcaptcha ({c_payload_2.get('type', '?')})...")
        n_value = self._generate_n(c_payload_2, cfg, "step4")

        # Build second p_e (different timestamp)
        second_failure_ts = int(time.time() * 1000) - random.randint(200, 600)
        second_p_e = _build_p_e(cfg.version, [(second_failure_ts, "hsw")], worker_location)

        # Step 5: getcaptcha#2 with solved PoW + p_e — replay phone template
        _log_cap(f"[hsj] step5: getcaptcha (n=solved)...")
        motion_data_2 = None
        if getattr(self, "context", None):
            try:
                from .phone_motion import build_getcaptcha_solved_motion
                _dev = (cfg.profile_data or {}).get("static_fp_template", {}).get("_picked_device")
                motion_data_2 = build_getcaptcha_solved_motion(widget_id=wid, href=cfg.href, device=_dev)
                if motion_data_2:
                    _log_cap(f"[hsj] step5 using phone motion template (solved)")
            except Exception as e:
                _log_cap(f"[hsj] step5 phone motion failed: {e}")
        if motion_data_2 is None:
            motion_data_2 = generate_motion_data(cfg, prev_pass=False, ekeys=ekeys, wid=wid)
        form2 = {
            "v": cfg.version,
            "sitekey": cfg.sitekey,
            "host": cfg.host,
            "hl": cfg.lang,
            "motionData": self._compact_json(motion_data_2),
            "pdc": self._compact_json({
                "s": int(time.time() * 1000),
                "n": 2,
                "p": random.randint(4, 8),
                "gcs": int(gc_time),
            }),
            "pem": self._compact_json({
                "csc": self._perf_now(csc_time),
                "csch": "api.hcaptcha.com",
                "cscrt": 0,
                "cscft": self._perf_now(csc_time),
                "gc": self._perf_now(gc_time),
                "gch": "api.hcaptcha.com",
                "gcrt": 0,
                "gcft": self._perf_now(gc_time),
            }),
            "n": n_value,
            "c": self._compact_json(c_payload_2),
            "p_e": second_p_e,
        }
        if rqdata:
            form2["rqdata"] = rqdata

        try:
            resp2 = session.post(
                f"https://api.hcaptcha.com/getcaptcha/{cfg.sitekey}",
                headers=headers,
                data=urlencode(form2),
                timeout_seconds=self.timeout,
            )
            gc_data_2 = resp2.json()
        except Exception as e:
            _log_err(f"[hsj] getcaptcha (solved) failed: {e}")
            return None
        _log_cap(f"[hsj] getcaptcha2: status={getattr(resp2, 'status_code', '?')} pass={gc_data_2.get('pass')} type={gc_data_2.get('request_type', 'none')} tasks={len(gc_data_2.get('tasklist', []))}")

        # Track second ekey
        challenge_key = gc_data_2.get("key")
        if challenge_key:
            ekeys.append([str(challenge_key), wid])

        if gc_data_2.get("pass"):
            token = gc_data_2.get("generated_pass_UUID")
            _log_ok(f"[hsj] solved (silent pass): {token[:40]}...")
            return token

        # ── Image challenge — solve with omocaptcha ──
        _log_cap(f"[hsj] step6: image challenge detected, sending to omocaptcha...")
        return self._solve_image_challenge(session, cfg, gc_data_2, hmt_id, wid, csc_time, rqdata, ekeys)


    def _solve_image_challenge(
        self,
        session,
        cfg: SolveConfig,
        gc_data: dict,
        hmt_id: str,
        wid: str,
        csc_time: float,
        rqdata: str,
        ekeys: list = None,
    ) -> Optional[str]:
        """Handle an image challenge using nopecha for recognition."""
        request_type = gc_data.get("request_type", "")
        tasklist = gc_data.get("tasklist", [])
        question = gc_data.get("requester_question", {}).get("en", "")
        ekey = gc_data.get("key", "")
        c_payload = gc_data.get("c", {})

        if not tasklist or not ekey:
            _log_err(f"[hsj] no tasklist or ekey in challenge response")
            return None

        _log_cap(f"[hsj] image challenge: type={request_type} tasks={len(tasklist)} q={question[:60]}")

        # Send raw getcaptcha data to nopecha — it handles image download + recognition
        solution = self.image_solver.solve_challenge(gc_data)
        if not solution:
            return None

        # Build answers from nopecha response based on challenge type
        answers = {}
        if request_type == "image_label_binary":
            # nopecha returns: [[true, false, true, ...]] (array of arrays of bools)
            for batch_idx, batch in enumerate(solution):
                for i, val in enumerate(batch):
                    task_idx = batch_idx * 9 + i
                    if task_idx < len(tasklist):
                        task_key = tasklist[task_idx].get("task_key", "")
                        answers[task_key] = "true" if val else "false"

        elif request_type == "image_label_area_select":
            # nopecha returns: [[{"x":45,"y":27.89,"w":17.71,"h":26.56}], ...]
            for i, task in enumerate(tasklist):
                task_key = task.get("task_key", "")
                if i < len(solution) and solution[i]:
                    box = solution[i][0]
                    # Convert percentages to pixel coords (image is typically 500x400)
                    img_w, img_h = 500, 400
                    px = int(box.get("x", 50) / 100 * img_w)
                    py = int(box.get("y", 50) / 100 * img_h)
                    answers[task_key] = [{"entity_name": "default", "entity_type": "default",
                                          "entity_coords": [px, py]}]

        elif request_type == "image_drag_drop":
            # nopecha returns: [[{"entity_id":"...","x":45,"y":27.89,"w":17.71,"h":26.56}], ...]
            for i, task in enumerate(tasklist):
                task_key = task.get("task_key", "")
                if i < len(solution):
                    answer_entities = []
                    for ent_result in solution[i]:
                        img_w, img_h = 500, 400
                        px = int(ent_result.get("x", 50) / 100 * img_w)
                        py = int(ent_result.get("y", 50) / 100 * img_h)
                        answer_entities.append({
                            "entity_name": ent_result.get("entity_id", ""),
                            "entity_type": "default",
                            "entity_coords": [px, py],
                        })
                    answers[task_key] = answer_entities
        else:
            _log_err(f"[hsj] unknown challenge type: {request_type}")
            return None

        # Submit checkcaptcha
        n_check = self._generate_n(c_payload, cfg, "checkcaptcha")
        motion_check = generate_challenge_motion_data(cfg, ekeys=ekeys or [], wid=wid)

        check_payload = {
            "v": cfg.version,
            "job_mode": request_type,
            "answers": answers,
            "serverdomain": cfg.host,
            "sitekey": cfg.sitekey,
            "motionData": self._compact_json(motion_check),
            "n": n_check,
            "c": self._compact_json(c_payload),
        }

        headers = self._build_headers(
            cfg,
            cookie=f"hmt_id={hmt_id}",
            content_type="application/json",
        )
        try:
            resp = session.post(
                f"https://api.hcaptcha.com/checkcaptcha/{cfg.sitekey}/{ekey}",
                headers=headers,
                json=check_payload,
                timeout_seconds=self.timeout,
            )
            check_data = resp.json()
        except Exception as e:
            _log_err(f"[hsj] checkcaptcha failed: {e}")
            return None

        if check_data.get("pass"):
            token = check_data.get("generated_pass_UUID", "")
            _log_ok(f"[hsj] solved (image challenge): {token[:40]}...")
            return token

        # Rejected — hCaptcha gives us a new `c` with a fresh challenge.
        # Nopecha is wrong ~40% of the time on drag-drop, so retry with the
        # new challenge up to N times before giving up.
        retry_count = getattr(self, "_checkcaptcha_retry_depth", 0)
        new_c = check_data.get("c")
        MAX_RETRIES = 4
        if isinstance(new_c, dict) and new_c.get("req") and retry_count < MAX_RETRIES:
            _log_cap(f"[hsj] checkcaptcha rejected (retry {retry_count + 1}/{MAX_RETRIES}) — "
                     f"retrying with fresh challenge from server")
            self._checkcaptcha_retry_depth = retry_count + 1
            try:
                time.sleep(0.8 + random.random() * 0.6)
                token = self._retry_with_new_challenge(session, cfg, new_c, hmt_id, wid,
                                                       csc_time, rqdata, ekeys)
                if token:
                    return token
            finally:
                self._checkcaptcha_retry_depth = retry_count

        # Final rejection — details only in debug (caller logs the generic failure)
        _log_cap(f"[hsj] checkcaptcha REJECTED: {json.dumps(check_data, ensure_ascii=False)[:300]}")
        return None

    def _retry_with_new_challenge(
        self,
        session,
        cfg: SolveConfig,
        new_c: dict,
        hmt_id: str,
        wid: str,
        csc_time: float,
        rqdata: str,
        ekeys: list,
    ) -> Optional[str]:
        """After a checkcaptcha rejection, redo a getcaptcha cycle with the
        new c payload the server handed back. Then solve the new image and
        submit checkcaptcha again."""
        # Solve PoW on the new challenge
        n_value = self._generate_n(new_c, cfg, "retry")

        # New getcaptcha with the refreshed n — replay phone template on retries too
        motion = None
        if getattr(self, "context", None):
            try:
                from .phone_motion import build_getcaptcha_solved_motion
                _dev = (cfg.profile_data or {}).get("static_fp_template", {}).get("_picked_device")
                motion = build_getcaptcha_solved_motion(widget_id=wid, href=cfg.href, device=_dev)
            except Exception:
                pass
        if motion is None:
            motion = generate_motion_data(cfg, prev_pass=False, ekeys=ekeys, wid=wid)
        form = {
            "v": cfg.version,
            "sitekey": cfg.sitekey,
            "host": cfg.host,
            "hl": cfg.lang,
            "motionData": self._compact_json(motion),
            "n": n_value,
            "c": self._compact_json(new_c),
        }
        if rqdata:
            form["rqdata"] = rqdata

        headers = self._build_headers(
            cfg,
            cookie=f"hmt_id={hmt_id}",
            content_type="application/x-www-form-urlencoded",
        )
        try:
            resp = session.post(
                f"https://api.hcaptcha.com/getcaptcha/{cfg.sitekey}",
                headers=headers,
                data=urlencode(form),
                timeout_seconds=self.timeout,
            )
            gc_data = resp.json()
        except Exception as e:
            _log_err(f"[hsj] retry getcaptcha failed: {e} status={getattr(resp,'status_code','?') if 'resp' in dir() else '?'}")
            return None

        _log_cap(f"[hsj] retry getcaptcha: pass={gc_data.get('pass')} "
                 f"type={gc_data.get('request_type','none')} tasks={len(gc_data.get('tasklist',[]))}")

        # Track new ekey
        new_ekey = gc_data.get("key")
        if new_ekey:
            ekeys.append([str(new_ekey), wid])

        if gc_data.get("pass"):
            token = gc_data.get("generated_pass_UUID")
            _log_ok(f"[hsj] solved (silent pass, retry): {token[:40]}...")
            return token

        # Another image challenge — delegate to _solve_image_challenge recursively
        return self._solve_image_challenge(session, cfg, gc_data, hmt_id, wid,
                                           csc_time, rqdata, ekeys)


# ═════════════════════════════════════════════════════════════════
# Convenience function for use in solvers.py
# ═════════════════════════════════════════════════════════════════

def solve_hcaptcha(
    sitekey: str,
    rqdata: str = "",
    proxy: str = "",
    host: str = "",
    href: str = "",
    omocaptcha_key: str = "",
    user_agent: str = "",
    device_info: dict = None,
    context: str = None,
    mobile_device: dict = None,
) -> Optional[str]:
    """Solve hCaptcha for Discord. Returns token or None.

    context: "friend" | "dm" | "register" — selects captured phone HSJ profile.
    mobile_device: optional override — a specific entry from mobile_fp_pool.json
                   to lock the UA/screen/hashes for this solve (e.g. to match
                   the calling token's Discord identity). If None, the solver
                   picks a random device per solve.
    """
    # Discord Android uses react-native hCaptcha host
    if not host:
        host = f"{sitekey}.react-native.hcaptcha.com"
    if not href:
        href = "data:text/html;charset=utf-8;base64,"
    solver = HCaptchaSolver(proxy=proxy, user_agent=user_agent, omocaptcha_key=omocaptcha_key)
    solver.device_info = device_info
    solver.mobile_device_override = mobile_device
    return solver.solve(sitekey=sitekey, host=host, rqdata=rqdata, href=href, context=context)
