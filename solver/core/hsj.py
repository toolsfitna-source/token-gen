import base64
import hashlib
import json
import math
import os
import random
import string
import struct
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import quote as _uri_encode


EVENT_HASH_TIMESTAMP = 3663932439
EVENT_HASH_CSP_ERROR = 2797424280

# ── hCaptcha event value encryption (mirrors encrypt_event.js) ──────────

_ALPHA = "abcdefghijklmnopqrstuvwxyz"


def _eg_random_key() -> str:
    return "".join(random.choices(string.ascii_uppercase, k=13))


def _encrypt_event_value(plaintext: str) -> list:
    """Encrypt a single event value using hCaptcha's custom cipher.

    Returns [encoded_str, shift_hex, split_hex, key_word] matching the
    format observed in real browser proofs.
    """
    w = _eg_random_key()
    v = random.randint(1, 26)

    # step 1: reverse words then reverse chars with Caesar shift
    step1 = " ".join(plaintext.split(" ")[::-1])
    shifted = []
    for c in reversed(step1):
        if c.isalpha():
            up = c.isupper()
            idx = _ALPHA.index(c.lower())
            sh = _ALPHA[(idx + v) % 26]
            shifted.append(sh.upper() if up else sh)
        else:
            shifted.append(c)
    step2 = "".join(shifted)

    # step 2: URI encode -> base64 -> reverse
    b64 = base64.b64encode(_uri_encode(step2, safe="").encode()).decode()
    b_rev = b64[::-1]

    # step 3: rotate
    length = len(b_rev)
    e = random.randint(1, max(1, length - 1)) if length > 1 else 1
    rotated = b_rev[e:] + b_rev[:e]

    # step 4: case-swap chars that appear in key
    key_chars = w + w.lower()
    final = []
    for c in rotated:
        if c in key_chars:
            final.append(c.lower() if c.isupper() else c.upper())
        else:
            final.append(c)

    return [
        "".join(final),
        format(v, "x"),
        format(e, "x"),
        w,
    ]


def _build_encrypted_gpu_event(gpu_vendor: str, gpu_renderer: str) -> str:
    """Build event 3495389113 — encrypted [vendor, renderer]."""
    return _json_value([
        _encrypt_event_value(gpu_vendor),
        _encrypt_event_value(gpu_renderer),
    ])


def _build_encrypted_timezone_event(tz_name: str) -> str:
    """Build event 4009980312 — encrypted timezone string."""
    return _json_value(_encrypt_event_value(tz_name))


def _build_encrypted_memory_event(memory_value: str) -> str:
    """Build event 2795229317 — encrypted memory/perf value."""
    return _json_value(_encrypt_event_value(memory_value))
_PROFILES_PATH = Path(__file__).resolve().with_name("profiles.json")

_GPU_PROFILES = [
    (
        "Mozilla",
        "ANGLE (NVIDIA, NVIDIA GeForce GTX 980 Direct3D11 vs_5_0 ps_5_0), or similar",
    ),
]

_SCREEN_PROFILES = [
    {"width": 1536, "height": 864, "avail_width": 1536, "avail_height": 816, "device_pixel_ratio": 1.0},
    {"width": 1680, "height": 1050, "avail_width": 1680, "avail_height": 1050, "device_pixel_ratio": 1.25},
    {"width": 1920, "height": 1080, "avail_width": 1920, "avail_height": 1040, "device_pixel_ratio": 1.0},
]

_DEFAULT_STACK_DATA = [
    "Array.forEach (<anonymous>)",
    "new Promise (<anonymous>)",
    "Array.map (<anonymous>)\nnew Promise (<anonymous>)",
    "Generator.next (<anonymous>)",
]

_DEFAULT_EVENTS = {
    317671698: "2337666753322697468",
    359759834: "[2147483647,2147483647,4294967294]",
    4181015304: "13205868561824496197",
    2671296585: "12803201746039718934",
    2264528771: "[4,120,4]",
    462289253: "57",
    1145363943: "[16,1024,4096,7,12,120,[23,127,127]]",
    3865101243: "[1,1024,1,1,4]",
    2737207841: "[[64,[65,65,65,255,65,65,65,255,65,65,65,255,64,65,64,255]],[[11,0,0,95.96875,15,4,96.765625],[[12,0,-1,113.125,17,4,113],[11,0,0,111,12,4,111]]],[0,2,3,6,8,12,13,15,16,17,20,26,27,28,30,31,34,37,39,40,43,44,48,51,69,70,72,75,76,77,78,79,80,82],[0,0,0,0,14,3,0]]",
    580323850: "289.25",
    772896908: "[11]",
    1369899379: "702",
    559251292: "true",
    2972341029: "100.7",
    3405509837: "8022061930804573802",
    562823142: "16927405672252548354",
    58508894: "[2147483648,190690453094,null,null,2248146944,true,true,true,null]",
    1866465638: '["Mozilla","ANGLE (NVIDIA, NVIDIA GeForce GTX 980 Direct3D11 vs_5_0 ps_5_0), or similar"]',
    1267668072: "10920691432923340878",
    1728464210: "8473551219770411651",
    3114937725: "[0,2,3,4]",
    2075394470: "4932383211497360507",
    3554363111: "[1,4,5,7,9,12,20,21,24,25,29,31]",
    2408498452: "2619324630952705645",
    3923352168: "756874611071873095",
    3911512191: "[16,4095,30,16,16379,119,12,120,[23,127,127]]",
    2054986590: "1774568010717.3",
    2182569285: "400.4",
    1784476536: "[32767,32767,16384,8,8,8]",
    2935681427: "[4294967295,4294967295,4294967295,4294967295]",
    2402750047: "18437843324563249497",
    3055761315: "[24,24,65536,212987,200704]",
    4181739560: "[[277114314493,277114314500,277114314491,357114314496,277114314492],false]",
    2426461220: "1195",
    2387740133: "[16384,32,16384,2048,2,2048]",
    1075205395: '[["loadTimes","csi","app"],35,34,null,false,false,true,37,true,true,true,true,true,["Raven","_sharedLibs","8476431583","global","__wdata","hsj"],[],[2],true]',
    504458258: '["5.0 (Windows)","Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0",null,4,"en-US",["en-US"],"Win32","Windows NT 10.0; Win64; x64",[],null,null,2,5,true,false,null,false,false,false,false,false,false]',
    1181016567: '"Africa/Cairo"',
    2539159609: "16373752545305569922",
    3962939203: "[-6.172840118408203,-20.710678100585938,120.71067810058594,-20.710678100585938,141.42135620117188,120.71067810058594,-20.710678100585938,141.42135620117188,-20.710678100585938,-20.710678100585938,0,0,300,150,false]",
    3663932439: "35569252.8",
    3320102372: "16197116850200928320",
    3931073091: "9345374751420407194",
}

_DEFAULT_COMPONENTS = {
    "navigator": {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0",
        "language": "en-US",
        "languages": ["en-US"],
        "platform": "Win32",
        "max_touch_points": 0,
        "webdriver": False,
        "notification_query_permission": None,
        "plugins_undefined": False,
    },
    "screen": {
        "color_depth": 32,
        "pixel_depth": 32,
        "width": 1680,
        "height": 1050,
        "avail_width": 1680,
        "avail_height": 1050,
    },
    "device_pixel_ratio": 1.25,
    "has_session_storage": True,
    "has_local_storage": True,
    "has_indexed_db": True,
    "web_gl_hash": "-1",
    "canvas_hash": "17412851421643673202",
    "has_touch": False,
    "notification_api_permission": "Denied",
    "chrome": False,
    "to_string_length": 33,
    "err_firefox": None,
    "r_bot_score": 0,
    "r_bot_score_suspicious_keys": [],
    "r_bot_score_2": 0,
    "audio_hash": "-1",
    "extensions": [False],
    "parent_win_hash": "13973576902552973121",
    "webrtc_hash": "-1",
    "performance_hash": "4837630727981787945",
    "unique_keys": "_epicEnableCookieGuard,a0_0x36f8,core,AppInit,__core-js_shared__,_epicTrackingCountryCode,_sentryDebugIds,talon,SENTRY_RELEASE,k,__axiosInstanceCached,__tracking_base,MotionHandoffIsComplete,__STATSIG__,0,a0_0x5ba2,i,__SENTRY__,_sentryDebugIdIdentifier,hcaptcha,1,__store,setImmediate,__axiosInstance,regeneratorRuntime,2,grecaptcha,_epicTrackingCookieDomainId,_epicTracking,clearImmediate",
    "inv_unique_keys": "global,_sharedLibs,hsj,__wdata,8476431583",
    "common_keys_hash": 3319060579,
    "common_keys_tail": "scrollTo,setInterval,setTimeout,stop,structuredClone,webkitCancelAnimationFrame,webkitRequestAnimationFrame,chrome,crashReport,cookieStore,ondevicemotion,ondeviceorientation,ondeviceorientationabsolute,onpointerrawupdate,caches,documentPictureInPicture,sharedStorage,fetchLater,getScreenDetails,queryLocalFonts,showDirectoryPicker,showOpenFilePicker,showSaveFilePicker,originAgentCluster,viewport,onpageswap,onpagereveal,credentialless,fence,launchQueue,speechSynthesis,onscrollsnapchange,onscrollsnapchanging,ongamepadconnected,ongamepaddisconnected,webkitRequestFileSystem,webkitResolveLocalFileSystemURL,Raven",
    "features": {
        "performance_entries": True,
        "web_audio": True,
        "web_rtc": True,
        "canvas_2d": True,
        "fetch": True,
    },
}

_TEMPLATE_COMPONENT_FIELDS = (
    "has_session_storage",
    "has_local_storage",
    "has_indexed_db",
    "web_gl_hash",
    "canvas_hash",
    "has_touch",
    "notification_api_permission",
    "chrome",
    "to_string_length",
    "err_firefox",
    "r_bot_score",
    "r_bot_score_suspicious_keys",
    "r_bot_score_2",
    "audio_hash",
    "extensions",
    "webrtc_hash",
    "performance_hash",
)

_FOOX1_SAFE_EVENT_IDS = {
    317671698,
    2539159609,
    359759834,
    4181015304,
    2671296585,
    2264528771,
    462289253,
    1145363943,
    3865101243,
    2737207841,
    772896908,
    1369899379,
    559251292,
    3320102372,
    3405509837,
    562823142,
    1866465638,
    1267668072,
    1728464210,
    3114937725,
    3554363111,
    2408498452,
    3923352168,
    3911512191,
    1784476536,
    2935681427,
    2402750047,
    3055761315,
    2387740133,
    2426461220,
    2075394470,
    3962939203,
    1755893731,
    58508894,
    2189040541,
    1181016567,
    3486023461,
    504458258,
    1000750690,
    # encrypted cross-validation events (GPU, timezone, memory)
    3495389113,
    4009980312,
    2795229317,
    # performance/resource timing and script loading
    3357624742,
    3427390490,
    2556820389,
}

_DYNAMIC_EVENT_IDS = {
    1000750690,
    1181016567,
    1866465638,
    2054986590,
    2402750047,
    2972341029,
    3663932439,
    4181015304,
    504458258,
    580323850,
}


def _load_profiles() -> Dict[str, Any]:
    try:
        return json.loads(_PROFILES_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


_PROFILES = _load_profiles()


def parse_jwt(jwt_str: str) -> Optional[Dict[str, Any]]:
    parts = jwt_str.split(".")
    if len(parts) < 2:
        return None

    payload = parts[1].replace("-", "+").replace("_", "/")
    while len(payload) % 4 != 0:
        payload += "="

    try:
        return json.loads(base64.b64decode(payload))
    except Exception:
        return None


def solve_hashcash(difficulty: int, data: str) -> str:
    leading_zeros = math.ceil(difficulty / 4.0)
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    rand_bytes = os.urandom(8)
    rand_str = "".join(chars[b % len(chars)] for b in rand_bytes)
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    prefix = f"1:{difficulty}:{date_str}:{data}::{rand_str}:"

    for nonce in range(0x7FFFFFFF):
        stamp = prefix + format(nonce, "x")
        hash_hex = hashlib.sha1(stamp.encode()).hexdigest()
        if all(hash_hex[i] == "0" for i in range(leading_zeros)):
            return stamp

    raise RuntimeError("hashcash solution not found")


def solve_hsl(jwt_str: str) -> str:
    payload = parse_jwt(jwt_str)
    if not payload:
        raise ValueError("Invalid HSL JWT")

    difficulty = int(payload.get("s", 16))
    data = str(payload.get("d", ""))
    if not data or difficulty == 0:
        raise ValueError(f"HSL: invalid spec (data={data!r} difficulty={difficulty})")

    charset = "0123456789/:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    base = len(charset)

    def check_bits(digest: bytes, diff: int) -> bool:
        required = diff - 1
        full_bytes = required // 8
        for i in range(full_bytes):
            if digest[i] != 0:
                return False
        remain_bits = required % 8
        if remain_bits > 0:
            mask = (1 << remain_bits) - 1
            if digest[full_bytes] & mask != 0:
                return False
        return True

    def increment_counter(counter: list[int]) -> bool:
        for i in range(len(counter) - 1, -1, -1):
            if counter[i] < base - 1:
                counter[i] += 1
                return True
            counter[i] = 0
        return False

    def encode_counter(counter: list[int]) -> str:
        return "".join(charset[c] for c in counter)

    hash_prefix = (data + "::").encode()
    for length in range(1, 26):
        counter = [0] * length
        while increment_counter(counter):
            counter_str = encode_counter(counter)
            digest = hashlib.sha1(hash_prefix + counter_str.encode()).digest()
            if check_bits(digest, difficulty):
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
                return f"1:{difficulty}:{timestamp}:{data}::{counter_str}"

    raise RuntimeError("HSL hashcash solution not found")


def _generate_events_minimal() -> list[list[Any]]:
    now = str(int(time.time() * 1000))
    return [
        [EVENT_HASH_TIMESTAMP, now],
        [EVENT_HASH_CSP_ERROR, '"Error: CSP"'],
    ]


def _generate_rand_pair() -> list[float]:
    buf = os.urandom(16)
    r1 = struct.unpack("<Q", buf[:8])[0]
    r2 = struct.unpack("<Q", buf[8:])[0]
    return [(r1 >> 11) * 2**-53, (r2 >> 11) * 2**-53]


def _clone(value: Any) -> Any:
    return json.loads(json.dumps(value))


def _foox1_template(cfg: Optional[Any]) -> Optional[Dict[str, Any]]:
    if cfg is None:
        return None

    profile_data = getattr(cfg, "profile_data", None)
    if not isinstance(profile_data, dict):
        return None

    template = profile_data.get("foox1_template")
    if not isinstance(template, dict):
        return None

    return template


def _static_full_template(cfg: Optional[Any]) -> Optional[Dict[str, Any]]:
    if cfg is None:
        return None
    profile_data = getattr(cfg, "profile_data", None)
    if not isinstance(profile_data, dict):
        return None
    template = profile_data.get("static_fp_template")
    if isinstance(template, dict):
        return template
    return None


def _foox1_event_map(cfg: Optional[Any]) -> Dict[int, Any]:
    template = _foox1_template(cfg)
    if template is None:
        return {}

    event_map: Dict[int, Any] = {}
    for row in template.get("events", []):
        if not isinstance(row, list) or len(row) < 2:
            continue
        try:
            event_id = int(row[0])
        except Exception:
            continue
        event_map[event_id] = row[1]
    return event_map


def _random_numeric_string(min_length: int = 19, max_length: int = 20) -> str:
    length = random.randint(min_length, max_length)
    text = str(random.randint(1, 9))
    while len(text) < length:
        text += str(random.randint(0, 9))
    return text


def _json_value(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _random_screen_profile() -> Dict[str, Any]:
    return _clone(random.choice(_SCREEN_PROFILES))


def _screen_profile_from_cfg(cfg: Optional[Any]) -> Optional[Dict[str, Any]]:
    if cfg is None:
        return None

    cfg_screen = getattr(cfg, "screen", None)
    if cfg_screen is None:
        return None

    return {
        "width": int(getattr(cfg_screen, "width", _DEFAULT_COMPONENTS["screen"]["width"])),
        "height": int(getattr(cfg_screen, "height", _DEFAULT_COMPONENTS["screen"]["height"])),
        "avail_width": int(getattr(cfg_screen, "avail_width", _DEFAULT_COMPONENTS["screen"]["avail_width"])),
        "avail_height": int(getattr(cfg_screen, "avail_height", _DEFAULT_COMPONENTS["screen"]["avail_height"])),
        "device_pixel_ratio": float(
            getattr(cfg, "device_pixel_ratio", _DEFAULT_COMPONENTS["device_pixel_ratio"])
        ),
    }


def _pick_screen_profile(cfg: Optional[Any]) -> Dict[str, Any]:
    cfg_screen = _screen_profile_from_cfg(cfg)
    if cfg_screen is not None:
        return cfg_screen
    return _random_screen_profile()


def _timezone_name(cfg: Optional[Any] = None) -> str:
    if cfg is not None:
        timezone_name = getattr(cfg, "timezone", None)
        if timezone_name:
            return str(timezone_name)
    tz = os.environ.get("TZ")
    if tz:
        return tz
    return "Africa/Cairo"


def _pick_gpu_profile(cfg: Optional[Any] = None) -> tuple[str, str]:
    if cfg is not None:
        gpu_vendor = getattr(cfg, "gpu_vendor", None)
        gpu_renderer = getattr(cfg, "renderer", None)
        if gpu_vendor and gpu_renderer:
            return str(gpu_vendor), str(gpu_renderer)
    return random.choice(_GPU_PROFILES)


def _use_profile_fp_overrides(cfg: Optional[Any], site_profile: Dict[str, Any]) -> bool:
    site_type = str(site_profile.get("site_type") or "").strip().lower()
    if site_type == "epic":
        return False
    sitekey = str(getattr(cfg, "sitekey", "") or "")
    if sitekey == "91e4137f-95af-4bc9-97af-cdcedce21c8c":
        return False
    return True


def _apply_foox1_components(components: Dict[str, Any], cfg: Optional[Any]) -> Dict[str, Any]:
    template = _foox1_template(cfg)
    if template is None:
        return components

    source_components = template.get("components")
    if not isinstance(source_components, dict):
        return components

    source_navigator = source_components.get("navigator")
    if isinstance(source_navigator, dict):
        for key, value in source_navigator.items():
            if key in components["navigator"]:
                components["navigator"][key] = _clone(value)

    source_screen = source_components.get("screen")
    if isinstance(source_screen, dict):
        for key, value in source_screen.items():
            if key in components["screen"]:
                components["screen"][key] = _clone(value)

    if "device_pixel_ratio" in source_components:
        components["device_pixel_ratio"] = _clone(source_components["device_pixel_ratio"])

    for key in _TEMPLATE_COMPONENT_FIELDS:
        if key in source_components:
            components[key] = _clone(source_components[key])

    source_features = source_components.get("features")
    if isinstance(source_features, dict):
        components["features"] = _clone(source_features)

    if cfg is not None:
        languages = list(getattr(cfg, "languages", []) or components["navigator"].get("languages", []))
        primary_language = languages[0] if languages else getattr(cfg, "lang", components["navigator"].get("language", "en"))
        components["navigator"]["user_agent"] = getattr(cfg, "ua", components["navigator"]["user_agent"])
        components["navigator"]["language"] = primary_language
        components["navigator"]["languages"] = languages or [primary_language]
        components["navigator"]["platform"] = getattr(cfg, "platform", components["navigator"]["platform"])
        components["navigator"]["max_touch_points"] = int(
            getattr(cfg, "max_touch_points", components["navigator"]["max_touch_points"]) or 0
        )
        cfg_screen = getattr(cfg, "screen", None)
        if cfg_screen is not None:
            components["screen"]["width"] = int(getattr(cfg_screen, "width", components["screen"]["width"]))
            components["screen"]["height"] = int(getattr(cfg_screen, "height", components["screen"]["height"]))
            components["screen"]["avail_width"] = int(
                getattr(cfg_screen, "avail_width", components["screen"]["avail_width"])
            )
            components["screen"]["avail_height"] = int(
                getattr(cfg_screen, "avail_height", components["screen"]["avail_height"])
            )
            components["screen"]["color_depth"] = int(
                getattr(cfg_screen, "color_depth", components["screen"]["color_depth"])
            )
            components["screen"]["pixel_depth"] = int(
                getattr(cfg_screen, "pixel_depth", components["screen"]["pixel_depth"])
            )
        components["device_pixel_ratio"] = float(
            getattr(cfg, "device_pixel_ratio", components["device_pixel_ratio"])
        )

    components["has_touch"] = components["navigator"]["max_touch_points"] > 0
    return components


def _apply_foox1_events(events: Dict[int, Any], cfg: Optional[Any]) -> Dict[int, Any]:
    event_map = _foox1_event_map(cfg)
    if not event_map:
        return events

    for event_id in _FOOX1_SAFE_EVENT_IDS:
        if event_id in event_map:
            events[event_id] = event_map[event_id]

    return events


def _build_components(cfg: Optional[Any], site_profile: Dict[str, Any], screen: Dict[str, Any]) -> Dict[str, Any]:
    components = _clone(_DEFAULT_COMPONENTS)
    navigator = components["navigator"]

    if cfg is not None:
        ua = getattr(cfg, "ua", navigator["user_agent"])
        lang = getattr(cfg, "lang", "en")
        languages = list(getattr(cfg, "languages", []) or ["en-US"])
        primary_language = languages[0] if languages else ("en-US" if lang == "en" else lang)
        navigator["platform"] = getattr(cfg, "platform", navigator["platform"])
        navigator["max_touch_points"] = int(getattr(cfg, "max_touch_points", navigator["max_touch_points"]) or 0)
        navigator["user_agent"] = ua
        navigator["language"] = primary_language
        navigator["languages"] = languages

    components["screen"] = {
        "color_depth": 32,
        "pixel_depth": 32,
        "width": screen["width"],
        "height": screen["height"],
        "avail_width": screen["avail_width"],
        "avail_height": screen["avail_height"],
    }
    components["device_pixel_ratio"] = screen["device_pixel_ratio"]
    components["has_touch"] = navigator["max_touch_points"] > 0
    components["canvas_hash"] = _random_numeric_string()
    components["parent_win_hash"] = _random_numeric_string()
    components["performance_hash"] = _random_numeric_string()
    components = _apply_foox1_components(components, cfg)

    if _use_profile_fp_overrides(cfg, site_profile):
        overrides = site_profile.get("overrides", {})
        for key, value in overrides.items():
            if value == "random":
                components[key] = _random_numeric_string()
            else:
                components[key] = value

    return components


def _build_navigator_event(cfg: Optional[Any]) -> str:
    ua = getattr(cfg, "ua", _DEFAULT_COMPONENTS["navigator"]["user_agent"]) if cfg is not None else _DEFAULT_COMPONENTS["navigator"]["user_agent"]
    languages = list(getattr(cfg, "languages", []) or ["en-US"]) if cfg is not None else ["en-US"]
    language = languages[0] if languages else "en-US"
    device_memory = int(getattr(cfg, "device_memory", 4) or 4) if cfg is not None else 4
    hardware_concurrency = int(getattr(cfg, "hardware_concurrency", 4) or 4) if cfg is not None else 4
    platform = getattr(cfg, "platform", "Win32") if cfg is not None else "Win32"
    if "Firefox/" in str(ua):
        data = [
            "5.0 (Windows)",
            ua,
            None,
            hardware_concurrency,
            language,
            languages,
            platform,
            "Windows NT 10.0; Win64; x64",
            [],
            None,
            None,
            2,
            5,
            True,
            False,
            None,
            False,
            False,
            False,
            False,
            False,
            False,
        ]
        return _json_value(data)
    data = [
        ua.split("Mozilla/")[-1] if ua.startswith("Mozilla/") else ua,
        ua,
        device_memory,
        hardware_concurrency,
        language,
        languages,
        platform,
        None,
        ["Chromium 146", "Not-A.Brand 24", "Brave 146"],
        False,
        "Windows",
        2,
        7,
        True,
        False,
        None,
        False,
        False,
        True,
        "null",
        True,
        False,
    ]
    return _json_value(data)


def _build_screen_event(screen: Dict[str, Any]) -> str:
    return _json_value(
        [
            screen["width"],
            screen["height"],
            screen["avail_width"],
            screen["avail_height"],
            32,
            32,
            False,
            0,
            screen["device_pixel_ratio"],
            screen["avail_width"],
            screen["avail_height"],
            False,
            True,
            True,
            False,
        ]
    )


def _build_resource_timing_event(cfg: Optional[Any]) -> str:
    """Build event 3357624742 — performance resource timing entries."""
    from .config import PopularCaptcha_VERSION
    rand_sub = "".join(random.choices("0123456789abcdef", k=12))
    fetch_start = round(random.uniform(5.0, 80.0), 6)
    fetch_dur = round(random.uniform(180.0, 500.0), 1)
    nav_start = round(random.uniform(30.0, 80.0), 0)
    nav_dur = round(random.uniform(120.0, 250.0), 6)
    script_start = round(random.uniform(10.0, 40.0), 0)
    script_dur = round(random.uniform(50.0, 120.0), 6)
    xhr_dur = round(random.uniform(30.0, 90.0), 6)
    return _json_value([
        [f"fetch:{rand_sub}.w.hcaptcha.com", fetch_start, fetch_dur],
        ["navigation:newassets.hcaptcha.com", nav_start, nav_dur],
        ["script:newassets.hcaptcha.com", script_start, script_dur],
        ["xmlhttprequest:api.hcaptcha.com", 0, xhr_dur],
    ])


def _build_script_loading_event(cfg: Optional[Any], worker_hash: str = "") -> str:
    """Build event 3427390490 — script/resource loading info with worker hash from JWT."""
    if not worker_hash:
        from .config import PopularCaptcha_VERSION
        worker_hash = PopularCaptcha_VERSION
        if cfg is not None:
            worker_hash = str(getattr(cfg, "version", worker_hash) or worker_hash)
    main_size = random.randint(400000, 700000)
    return _json_value([
        [
            ["", main_size, 1],
            [f"https://newassets.hcaptcha.com/c/{worker_hash}/hsj.js", 0, 3],
        ],
        [["*", random.randint(60, 120), random.randint(6, 12)]],
    ])


def _build_events(cfg: Optional[Any], site_profile: Dict[str, Any], screen: Dict[str, Any], worker_hash: str = "") -> list[list[Any]]:
    events = dict(_DEFAULT_EVENTS)
    events = _apply_foox1_events(events, cfg)
    template_event_map = _foox1_event_map(cfg)
    timezone_name = _timezone_name(cfg)
    gpu_vendor, gpu_renderer = _pick_gpu_profile(cfg)

    events[EVENT_HASH_TIMESTAMP] = str(int(time.time() * 1000))
    events[1181016567] = template_event_map.get(1181016567, _json_value(timezone_name))
    events[1866465638] = template_event_map.get(1866465638, _json_value([gpu_vendor, gpu_renderer]))
    events[4181015304] = template_event_map.get(4181015304, _random_numeric_string())
    events[2402750047] = template_event_map.get(2402750047, _random_numeric_string())
    events[2054986590] = str(round(time.time() * 1000, 1))
    events[3663932439] = str(round(random.uniform(20_000_000, 40_000_000), 7))
    events[2972341029] = str(round(random.uniform(80.0, 140.0), 7))
    events[580323850] = str(round(random.uniform(220.0, 320.0), 2))
    events[504458258] = template_event_map.get(504458258, _build_navigator_event(cfg))
    events[1000750690] = template_event_map.get(1000750690, _build_screen_event(screen))

    # ── Encrypted cross-validation events ──
    # These MUST be consistent with the plaintext events above.
    # Use foox1 values (already consistent) or generate fresh from current plaintext.

    # Resolve the actual plaintext GPU used (from foox1 or fallback)
    actual_gpu_str = events.get(1866465638, "")
    try:
        actual_gpu = json.loads(actual_gpu_str)
        actual_gpu_vendor = str(actual_gpu[0])
        actual_gpu_renderer = str(actual_gpu[1])
    except Exception:
        actual_gpu_vendor, actual_gpu_renderer = gpu_vendor, gpu_renderer

    # Resolve the actual plaintext timezone used
    actual_tz_str = events.get(1181016567, "")
    try:
        actual_tz = json.loads(actual_tz_str)
    except Exception:
        actual_tz = timezone_name

    # Resolve the actual memory value from event 58508894
    actual_mem_str = events.get(58508894, "")
    try:
        actual_mem = json.loads(actual_mem_str)
        mem_val = str(actual_mem[0]) if isinstance(actual_mem, list) else str(actual_mem)
    except Exception:
        mem_val = "2147483648"

    # Always regenerate encrypted events to match current plain-text values.
    # Foox1 encrypted values may be stale or corrupted by patch_profile_events.
    events[3495389113] = _build_encrypted_gpu_event(actual_gpu_vendor, actual_gpu_renderer)
    events[4009980312] = _build_encrypted_timezone_event(actual_tz)
    events[2795229317] = _build_encrypted_memory_event(mem_val)

    # 3357624742 — performance resource timing (always regenerate: contains session-specific subdomains)
    events[3357624742] = _build_resource_timing_event(cfg)

    # 3427390490 — script loading info (use worker hash from JWT, not build hash)
    events[3427390490] = _build_script_loading_event(cfg, worker_hash=worker_hash)

    # 2556820389 — resource metrics
    if 2556820389 not in events:
        val = random.randint(5000, 15000)
        events[2556820389] = _json_value([0, val, val])

    if _use_profile_fp_overrides(cfg, site_profile):
        for raw_key, value in site_profile.get("event_overrides", {}).items():
            try:
                event_id = int(raw_key)
            except Exception:
                continue
            if event_id in template_event_map:
                continue
            if isinstance(value, list):
                events[event_id] = random.choice(value)
            else:
                events[event_id] = value

    ordered_ids = sorted(events.keys())
    return [[event_id, events[event_id]] for event_id in ordered_ids]


def _build_stack_data(site_profile: Dict[str, Any]) -> list[str]:
    stack_data = site_profile.get("stack_data")
    if isinstance(stack_data, list) and stack_data:
        return stack_data
    return list(_DEFAULT_STACK_DATA)


def _build_perf(site_profile: Dict[str, Any]) -> list[list[float]]:
    perf_cfg = site_profile.get("perf", {})
    phases = int(perf_cfg.get("phases", 3))
    phase1_min, phase1_max = perf_cfg.get("phase1_range", [15, 50])
    phase2_min, phase2_max = perf_cfg.get("phase2_range", [100, 250])

    perf = [
        [1, round(random.uniform(float(phase1_min), float(phase1_max)), 1)],
        [2, round(random.uniform(float(phase2_min), float(phase2_max)), 1)],
    ]
    if phases >= 3:
        perf.append([3, round(random.uniform(5.0, 20.0), 1)])
    return perf


def _build_proof_spec(jwt_payload: Optional[dict], cfg: Optional[Any] = None) -> dict:
    difficulty = 20
    data = "test"
    fingerprint_type: Any = None
    proof_type = "1"
    location = ""

    if jwt_payload:
        if "s" in jwt_payload:
            difficulty = int(jwt_payload["s"])
        if "d" in jwt_payload:
            data = str(jwt_payload["d"])
        if "f" in jwt_payload:
            value = jwt_payload["f"]
            fingerprint_type = int(value) if isinstance(value, (int, float)) else value
        if "t" in jwt_payload:
            proof_type = str(jwt_payload["t"])
        if "l" in jwt_payload:
            location = str(jwt_payload["l"])

    static_template = _static_full_template(cfg)
    if static_template is not None:
        spec = _clone(static_template)
        proof_spec = spec.get("proof_spec") if isinstance(spec.get("proof_spec"), dict) else {}
        proof_spec["difficulty"] = difficulty
        proof_spec["fingerprint_type"] = fingerprint_type
        proof_spec["_type"] = proof_type
        proof_spec["data"] = data
        proof_spec["_location"] = location
        proof_spec["timeout_value"] = float(proof_spec.get("timeout_value", 1000.0) or 1000.0)
        spec["proof_spec"] = proof_spec
        spec["stamp"] = solve_hashcash(difficulty, data)
        # Refresh per-request randomness so replayed templates aren't detectable
        # as replays (rand and perf would otherwise be identical across challenges).
        spec["rand"] = _generate_rand_pair()
        # Refresh perf with realistic phase timings instead of replaying old ones.
        spec["perf"] = [
            [1, random.randint(15, 50)],
            [2, random.randint(100, 250)],
            [3, random.randint(1, 8)],
        ]
        if cfg is not None:
            spec["href"] = getattr(cfg, "href", None) or spec.get("href") or None
        return spec

    # Extract worker hash from JWT _location for script loading events
    worker_hash = ""
    if location and "/c/" in location:
        worker_hash = location.split("/c/")[-1].rstrip("/")

    if cfg is not None:
        sitekey = getattr(cfg, "sitekey", "")
        site_profile = _PROFILES.get(sitekey, {})
        screen = _pick_screen_profile(cfg)
        components = _build_components(cfg, site_profile, screen)
        events = _build_events(cfg, site_profile, screen, worker_hash=worker_hash)
        perf = _build_perf(site_profile)
        stack_data = _build_stack_data(site_profile)
        errs_val = {"list": []}
        href = getattr(cfg, "href", None) or None
    else:
        start = time.time()
        events = _generate_events_minimal()
        phase1 = max(1, int((time.time() - start) * 1000))
        perf = [[1, phase1], [2, 1], [3, max(1, int(random.uniform(1, 8)))]]
        components = None
        stack_data = None
        href = None
        if jwt_payload:
            errs_val = {"list": ["src/lib.rs:125:31 - inspekt-window"]}
        else:
            errs_val = {
                "list": [
                    "inspekt-invalid-spec-default-fallback",
                    "src/lib.rs:125:31 - inspekt-window",
                ]
            }

    return {
        "proof_spec": {
            "difficulty": difficulty,
            "fingerprint_type": fingerprint_type,
            "_type": proof_type,
            "data": data,
            "_location": location,
            "timeout_value": 1000.0,
        },
        "rand": _generate_rand_pair(),
        "components": components,
        "events": events,
        "suspicious_events": [],
        "messages": None,
        "stack_data": stack_data,
        "stamp": solve_hashcash(difficulty, data),
        "href": href,
        "ardata": None,
        "errs": errs_val,
        "perf": perf,
    }


def solve_hsj(jwt_str: str, cfg: Optional[Any] = None) -> str:
    payload = parse_jwt(jwt_str)
    spec = _build_proof_spec(payload, cfg)
    return json.dumps(spec, ensure_ascii=False, separators=(",", ":"))


def random_widget_id() -> str:
    chars = "0123456789abcdefghijklmnopqrstuvwxyz"
    return "".join(random.choices(chars, k=12))
