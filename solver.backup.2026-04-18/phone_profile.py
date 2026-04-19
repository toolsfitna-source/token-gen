"""
Phone HSJ profile registry.

Maps a usage context (register / friend / dm) to a captured phone HSJ profile
JSON. Profiles were captured via wv_hsj_mock.py + chrome://inspect on the user's
real Android phone after forcing HSJ with the WebAssembly kill-switch.

Each profile contains the full decrypted 'n' payload:
    - components.navigator (real phone UA, platform, languages, etc.)
    - components.screen (width/height/avail/dpr)
    - href (the hCaptcha data: URL the WebView loaded)
    - events / proof_spec / stack_data (phone-authentic fingerprint traces)

Only the ENVIRONMENT bits (navigator/screen/href) are useful: hsj.js regenerates
proof_spec/events/stamp per-challenge, so we just need to pass the right env
into the sandbox for hsj.js to produce a phone-consistent N.
"""
import json
import os
import random
from pathlib import Path
from typing import Optional

_HERE = Path(__file__).resolve().parent
_PROFILES_DIR = _HERE / "profiles" / "captured"
_MOBILE_POOL_PATH = _HERE / "pools" / "mobile_fp_pool.json"

# Pool of FULL Android WebView device fingerprints (UA, screen, hashes,
# hardware). Extracted from real captured HSJ profiles. Used to rotate the
# apparent device identity across solves so hCaptcha sees a variety of real
# phones instead of thousands of sessions all claiming to be the same device.
_MOBILE_POOL: list | None = None


def _clean_webview_ua(ua: str) -> str:
    """Truncate app-specific suffixes from a WebView UA.

    Captured UAs sometimes include `tomas/...`, `NABar/1.0`, `bdapp/1.0`, etc.
    A Discord WebView UA is the clean Android WebView without app tags.
    """
    if not ua:
        return ua
    # Cut at 'Mobile Safari/XXX.XX' which is the last canonical WebView marker.
    import re
    m = re.search(r"Mobile Safari/\d+\.\d+", ua)
    if m:
        return ua[: m.end()]
    return ua


def _load_mobile_pool() -> list:
    """Load the real Android WebView device pool (cached)."""
    global _MOBILE_POOL
    if _MOBILE_POOL is None:
        try:
            raw = json.loads(_MOBILE_POOL_PATH.read_text(encoding="utf-8"))
            cleaned = []
            for e in raw if isinstance(raw, list) else []:
                if not isinstance(e, dict):
                    continue
                e = dict(e)
                e["ua"] = _clean_webview_ua(e.get("ua", ""))
                cleaned.append(e)
            _MOBILE_POOL = cleaned
        except Exception:
            _MOBILE_POOL = []
    return _MOBILE_POOL


def pick_mobile_device() -> Optional[dict]:
    """Return a random real Android WebView device entry from the pool, or None."""
    pool = _load_mobile_pool()
    if not pool:
        return None
    return random.choice(pool)

# Context -> captured profile filename.
# Captured on real phone (Honor ELI-NX9, Android 16 WebView) in silent-pass mode.
CONTEXT_PROFILES = {
    "friend": "phone_req_hsj_faab2de7d586.json",
    # DM send captured via wv_hsj_mock.py, verified silent-pass at source.
    "dm":     "phone_hsj_feca458989d8_0003.json",
    # Register flow captured via wv_hsj_mock.py during account creation.
    "register": "phone_hsj_dd235ecc93dc_0001.json",
    # Guild join (invite accept) captured via wv_hsj_mock.py, silent-pass.
    "join": "phone_hsj_0f2ce0e8584a_0001.json",
}

# Default when caller doesn't specify a context.
DEFAULT_CONTEXT = "friend"


def profile_path_for(context: Optional[str]) -> Optional[Path]:
    """Resolve a context name to an absolute .json path, or None if missing."""
    if not context:
        context = DEFAULT_CONTEXT
    filename = CONTEXT_PROFILES.get(context.lower())
    if not filename:
        # Fall back to default if unknown context
        filename = CONTEXT_PROFILES.get(DEFAULT_CONTEXT)
        if not filename:
            return None
    p = _PROFILES_DIR / filename
    return p if p.is_file() else None


def load_profile(context: Optional[str]) -> Optional[dict]:
    """Load profile for a context and overlay a random real Android WebView
    device identity (UA, screen, hashes, hardware) from the mobile_fp_pool.

    Rotating the FULL device fingerprint per solve — not just the hashes —
    means hCaptcha sees 100+ distinct real-device silhouettes instead of
    thousands of sessions all claiming to be the same phone. Each overlaid
    device was captured from a real WebView in the wild so the
    canvas/parent_win/performance/audio/webgl/webrtc hash tuple is coherent
    (came from one real phone).

    Returns the modified profile dict; caller should also patch motion data
    (via phone_motion.build_*_motion with the same device overrides) to keep
    UA/screen consistent across all request fields.
    """
    p = profile_path_for(context)
    if not p:
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None

    # Hash-only swap from the 2802-entry fingerprint_pool (real captured hashes
    # from many Android WebView devices). Without this, every solve uses the
    # SAME Honor hashes (canvas/parent_win/performance/common_keys) from the
    # base profile — hCaptcha sees that pattern instantly and force-challenges.
    # We only touch the 4 primary hashes (no UA/events/screen swap) so the rest
    # of the N stays coherent with the Honor phone motion/events.
    try:
        fp_path = _HERE / "pools" / "fingerprint_pool.json"
        if fp_path.is_file():
            import json as _j
            fp_pool = _j.loads(fp_path.read_text(encoding="utf-8"))
            if isinstance(fp_pool, list) and fp_pool:
                tup = random.choice(fp_pool)
                comps = data.get("components")
                if isinstance(comps, dict):
                    for k in ("canvas_hash", "parent_win_hash",
                              "performance_hash", "common_keys_hash"):
                        if k in tup:
                            comps[k] = tup[k]
    except Exception:
        pass

    return data


def available_contexts() -> list:
    """Return list of context keys whose profile file actually exists on disk."""
    return [ctx for ctx in CONTEXT_PROFILES if profile_path_for(ctx) is not None]
