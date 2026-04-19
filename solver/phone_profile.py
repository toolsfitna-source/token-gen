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
_COMPONENTS_POOL_PATH = _HERE / "pools" / "hsj_components_pool.json"

# Pool of FULL Android WebView device fingerprints (UA, screen, hashes,
# hardware). Extracted from real captured HSJ profiles. Used to rotate the
# apparent device identity across solves so hCaptcha sees a variety of real
# phones instead of thousands of sessions all claiming to be the same device.
_MOBILE_POOL: list | None = None

# The "big" pool — 1260 real mobile HSJ fingerprints (extracted + normalized
# from the 2802-entry hcap-hsj dump). Each entry carries a coherent hash-tuple
# (canvas / parent_win / performance / common_keys / web_gl / audio / webrtc)
# + browser feature bundle (unique_keys / extensions / features) + screen/DPR
# + GPU vendor/renderer — all from one real device. Combined with an Android
# UA/hw/memory synthesised from android_device_catalog, this gives us 1260 ×
# 41 ≈ 50k uniquely-shaped fingerprints per captured backbone profile.
_COMPONENTS_POOL: list | None = None


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


def _load_components_pool() -> list:
    """Load the 1260-entry normalised HSJ components pool (cached)."""
    global _COMPONENTS_POOL
    if _COMPONENTS_POOL is None:
        try:
            if _COMPONENTS_POOL_PATH.is_file():
                _COMPONENTS_POOL = json.loads(
                    _COMPONENTS_POOL_PATH.read_text(encoding="utf-8")
                )
                if not isinstance(_COMPONENTS_POOL, list):
                    _COMPONENTS_POOL = []
            else:
                _COMPONENTS_POOL = []
        except Exception:
            _COMPONENTS_POOL = []
    return _COMPONENTS_POOL


# Fields copied per-solve from a pool entry into profile["components"]. These
# are the "must remain coherent as a group" hashes + browser feature bundle.
_POOL_TO_COMPONENTS_KEYS = (
    "canvas_hash", "parent_win_hash", "performance_hash",
    "common_keys_hash", "common_keys_tail",
    "web_gl_hash", "audio_hash", "webrtc_hash",
    "device_pixel_ratio",
    "unique_keys", "inv_unique_keys",
    "extensions", "features",
    "r_bot_score", "r_bot_score_2", "r_bot_score_suspicious_keys",
    "to_string_length",
    "chrome", "err_firefox",
    "has_indexed_db", "has_local_storage", "has_session_storage", "has_touch",
    "notification_api_permission",
)


def _apply_aggressive_mutation(data: dict) -> dict:
    """Stronger per-solve fingerprint rotation. For each solve:

        (a) Pick ONE entry from the 1260-mobile components pool → copy its
            whole coherent fingerprint bundle (7 hashes, feature bundle,
            screen, DPR, GPU) into the base profile's components.
        (b) Pick ONE Android device from android_device_catalog biased by the
            pool entry's GPU family (so a Mali hash-tuple gets a Mali-device
            UA, not a Qualcomm one) → inject UA, platform, hardwareConcurrency,
            deviceMemory, maxTouchPoints into navigator.
        (c) Stash the merged identity on data["_picked_device"] so
            patch_hsj_events / phone_motion can re-encrypt EVENT_NAVIGATOR,
            EVENT_SCREEN, EVENT_GPU with matching values and so the motion
            data rewriter sees the same UA/screen.

    The captured backbone (events, stack_data, proof_spec, perf, rand, ardata)
    stays untouched — that's the execution-trace proof that hsj.js verifies.

    Set env RAIDER_AGGRESSIVE_FP_MUTATION=0 to skip this and keep the legacy
    hash-only-swap path (useful for A/B testing against a known-good baseline).
    """
    pool = _load_components_pool()
    if not pool:
        return data  # pool not present — caller falls back to hash-only path

    try:
        from .android_device_catalog import pick_device, gpu_family_from_renderer
    except Exception:
        return data

    entry = random.choice(pool)
    comps = data.setdefault("components", {})
    if not isinstance(comps, dict):
        comps = {}
        data["components"] = comps

    # (a) — copy pool entry's coherent bundle into components
    for k in _POOL_TO_COMPONENTS_KEYS:
        if k in entry and entry[k] is not None:
            comps[k] = entry[k]

    scr = comps.setdefault("screen", {})
    if entry.get("screen_width"):
        scr["width"] = entry["screen_width"]
    if entry.get("screen_height"):
        scr["height"] = entry["screen_height"]
    # Android WebView leaves availWidth/Height = width/height when status bar
    # is hidden; real captures vary. Use the pool's screen verbatim.
    if scr.get("width") and scr.get("height"):
        scr.setdefault("availWidth", scr["width"])
        scr.setdefault("availHeight", scr["height"])
        scr.setdefault("colorDepth", 24)
        scr.setdefault("pixelDepth", 24)

    # (b) — UA / HW / memory from catalog (biased by GPU)
    gpu_family = gpu_family_from_renderer(entry.get("renderer") or "")
    device = pick_device(bias_gpu=gpu_family)

    nav = comps.setdefault("navigator", {})
    nav["userAgent"] = device["user_agent"]
    nav["appVersion"] = device["user_agent"].replace("Mozilla/5.0 ", "", 1)
    nav["platform"] = entry.get("platform") or "Linux armv81"
    nav["hardwareConcurrency"] = device["hardware_concurrency"]
    nav["deviceMemory"] = device["device_memory"]
    nav["maxTouchPoints"] = device["max_touch_points"]
    nav.setdefault("vendor", "Google Inc.")
    nav.setdefault("cookieEnabled", True)
    nav.setdefault("doNotTrack", None)

    # Top-level vendor/renderer — referenced by EVENT_GPU re-encryption.
    if entry.get("vendor"):
        data["vendor"] = entry["vendor"]
    if entry.get("renderer"):
        data["renderer"] = entry["renderer"]

    # (c) — stash the picked identity so downstream consumers can replay it
    data["_picked_device"] = {
        "user_agent": device["user_agent"],
        "device_model": device["model"],
        "device_brand": device["model"].split()[0].split("-")[0],
        "android_version": device["android_version"],
        "build_tag": device["build_tag"],
        "smallest_screen_width": min(scr.get("width") or 400,
                                     scr.get("height") or 800),
        "screen_width": scr.get("width"),
        "screen_height": scr.get("height"),
        "hardware_concurrency": device["hardware_concurrency"],
        "device_memory": device["device_memory"],
        "max_touch_points": device["max_touch_points"],
        "gpu_vendor": entry.get("vendor") or "",
        "gpu_renderer": entry.get("renderer") or "",
        "gpu_family": gpu_family,
        "platform": nav["platform"],
    }
    return data


def _apply_hash_only_swap(data: dict) -> dict:
    """Legacy behaviour: swap only the 4 primary hashes from fingerprint_pool.json.
    Kept as an opt-out via RAIDER_AGGRESSIVE_FP_MUTATION=0 in case the richer
    path breaks silent-pass."""
    try:
        fp_path = _HERE / "pools" / "fingerprint_pool.json"
        if fp_path.is_file():
            fp_pool = json.loads(fp_path.read_text(encoding="utf-8"))
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

# Context -> list of captured backbone profile filenames.
# Each entry was captured on a real phone (Honor ELI-NX9, Android 16 WebView)
# during the corresponding flow and verified silent-pass at the source.
#
# Per solve, load_profile() picks ONE backbone at random from the context's
# list — combined with the 1260-entry components pool + 41-device catalog
# this yields ~N_backbones × 1260 × 41 unique silhouettes. With 25 register
# backbones that's ~1.3M silhouettes per context before any repetition.
CONTEXT_PROFILES = {
    "register": [
        "phone_hsj_1792a37a3433_0009.json",
        "phone_hsj_1a4f62271037_0011.json",
        "phone_hsj_449d0a9e0400_0012.json",
        "phone_hsj_45c1b5b61c64_0013.json",
        "phone_hsj_53ff30438302_0022.json",
        "phone_hsj_6440a84b5186_0021.json",
        "phone_hsj_80902c172546_0019.json",
        "phone_hsj_89d789059030_0014.json",
        "phone_hsj_9b7fc48fbb5d_0024.json",
        "phone_hsj_aaad2f7359e9_0015.json",
        "phone_hsj_b2950362ffb1_0025.json",
        "phone_hsj_b733f2288897_0023.json",
        "phone_hsj_b8d0e6cad0a9_0020.json",
        "phone_hsj_cac44db815cc_0017.json",
        "phone_hsj_cd9f48e792d9_0018.json",
        "phone_hsj_d11e84404e4c_0001.json",
        "phone_hsj_d11e84404e4c_0002.json",
        "phone_hsj_d11e84404e4c_0003.json",
        "phone_hsj_d11e84404e4c_0004.json",
        "phone_hsj_d11e84404e4c_0005.json",
        "phone_hsj_d11e84404e4c_0006.json",
        "phone_hsj_d11e84404e4c_0007.json",
        "phone_hsj_d11e84404e4c_0008.json",
        "phone_hsj_d57d2a53c155_0010.json",
        "phone_hsj_e0d760b0aef1_0016.json",
    ],
    "friend": [
        "phone_hsj_042b94694be3_0003.json",
        "phone_hsj_0a1650cc88ae_0014.json",
        "phone_hsj_26771cb6943e_0016.json",
        "phone_hsj_2c090f058dec_0012.json",
        "phone_hsj_3674af451594_0011.json",
        "phone_hsj_3838c2be895c_0013.json",
        "phone_hsj_3904fe18f476_0007.json",
        "phone_hsj_3c0621f79a2a_0004.json",
        "phone_hsj_61cdd4ebdbcf_0017.json",
        "phone_hsj_66c971969ee2_0009.json",
        "phone_hsj_686415eca24c_0018.json",
        "phone_hsj_70087b7b95af_0019.json",
        "phone_hsj_95e3f2528e64_0008.json",
        "phone_hsj_9892e5e70770_0001.json",
        "phone_hsj_9892e5e70770_0002.json",
        "phone_hsj_a866e8265c1b_0006.json",
        "phone_hsj_a9511eabcdba_0015.json",
        "phone_hsj_ae4d5b4576a8_0005.json",
        "phone_hsj_bc8c50d8fb74_0010.json",
    ],
    "dm": [
        "phone_hsj_1fbdeb77c866_0001.json",
        "phone_hsj_5d6b7dcb8884_0005.json",
        "phone_hsj_6036262d36cb_0003.json",
        "phone_hsj_9738934fe7eb_0002.json",
        "phone_hsj_c9303047d6d3_0006.json",
        "phone_hsj_ec20d306ba05_0004.json",
    ],
    # Guild join (invite accept) captured via wv_hsj_mock.py, silent-pass.
    "join": [
        "phone_hsj_0f2ce0e8584a_0001.json",
        "phone_hsj_0f2ce0e8584a_0002.json",
        "phone_hsj_21ef84a8647c_0004.json",
        "phone_hsj_983b71802787_0001.json",
        "phone_hsj_b50e02ec22ee_0003.json",
        "phone_hsj_f6cc34dea6c5_0002.json",
    ],
}

# Default when caller doesn't specify a context.
DEFAULT_CONTEXT = "friend"


def _context_list(context: Optional[str]) -> list:
    """Return the list of backbone filenames for a context (or default)."""
    key = (context or DEFAULT_CONTEXT).lower()
    lst = CONTEXT_PROFILES.get(key)
    if not lst:
        lst = CONTEXT_PROFILES.get(DEFAULT_CONTEXT) or []
    # Backwards-compat: older code had `CONTEXT_PROFILES[ctx] = "filename"`
    # as a plain string. Normalise to a list in-memory if needed.
    if isinstance(lst, str):
        lst = [lst]
    return lst


def profile_path_for(context: Optional[str]) -> Optional[Path]:
    """Resolve a context name to a .json path on disk. Picks ONE backbone at
    random from the context's pool — repeated calls in a session may return
    different files on purpose (that's how we rotate backbones per solve).
    Returns None if no filename in the pool actually exists on disk."""
    lst = _context_list(context)
    # Shuffle a local copy so we can try each file in a random order without
    # infinite-retrying the same missing one.
    order = list(lst)
    random.shuffle(order)
    for filename in order:
        p = _PROFILES_DIR / filename
        if p.is_file():
            return p
    return None


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

    # Two rotation strategies, selectable via RAIDER_AGGRESSIVE_FP_MUTATION:
    #   "1" (default): full component swap from the 1260-entry mobile pool
    #                  + UA/HW catalog injection — ~50k unique silhouettes
    #                  per captured backbone.
    #   "0": legacy hash-only swap (the 4 primary hashes rotated from
    #        fingerprint_pool.json). Keep in back-pocket in case silent-pass
    #        regresses and we need to A/B.
    mode = os.environ.get("RAIDER_AGGRESSIVE_FP_MUTATION", "1").strip().lower()
    if mode in ("raw", "none", "off"):
        # Zero mutation — return backbone exactly as captured from the phone.
        # Used to isolate whether our hash rotation itself breaks silent-pass.
        pass
    elif mode == "0":
        _apply_hash_only_swap(data)
    else:
        # Try aggressive path; if the components pool isn't present on disk
        # (fresh clone, or user deleted it), silently fall back to hash-only
        # so existing installations keep working.
        if _load_components_pool():
            _apply_aggressive_mutation(data)
        else:
            _apply_hash_only_swap(data)

    return data


def available_contexts() -> list:
    """Return list of context keys that have at least one backbone on disk."""
    out = []
    for ctx, lst in CONTEXT_PROFILES.items():
        filenames = [lst] if isinstance(lst, str) else list(lst)
        if any((_PROFILES_DIR / fn).is_file() for fn in filenames):
            out.append(ctx)
    return out


def backbone_pool_size(context: Optional[str]) -> int:
    """How many distinct backbones are on disk for a given context."""
    lst = _context_list(context)
    return sum(1 for fn in lst if (_PROFILES_DIR / fn).is_file())
