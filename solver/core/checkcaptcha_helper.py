import base64
import json
import hashlib
import random
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

from Crypto.Cipher import AES as _AES_GCM
from Crypto.Random import get_random_bytes as _aes_rand

from .foox1_pool import pick_foox1_template
from .hsj import solve_hsj, solve_hsl
from .config import PopularCaptcha_VERSION, REDUCED_UA, Screen, SolveConfig


EPIC_SITEKEY = "91e4137f-95af-4bc9-97af-cdcedce21c8c"
EPIC_HOST = "www.epicgames.com"
EPIC_HREF = (
    "https://www.epicgames.com/id/login"
    "?lang=en-US&noHostRedirect=true"
    "&redirectUrl=https%3A%2F%2Fstore.epicgames.com"
    "&client_id=875a3b57d3a640a6b7f9b4e883463ab4"
)

_AES_N_KEY = bytes.fromhex("30ae898a867d2d05149ce95e85c0372ac4c59bed6c2ca8e859988a2c153cc596")
_AES_RESP_KEY = bytes.fromhex("949970B3C3204FF46E010A67A0B5C24CC06026292DE689358D861A79C5F39C37")
_PROFILE_STATE_LOCK = threading.Lock()
_PROFILE_STATE_PATH = Path(__file__).resolve().with_name("epic_profile_state.json")
_SFP_VARIANT_STATE_PATH = Path(__file__).resolve().with_name("sfp_variant_state.json")
_DEFAULT_STATIC_FP_PATH = Path(__file__).resolve().with_name("static_fp.json")
_SFP_COHORT_COUNT = 96
_SFP_MUTABLE_HASH_EVENT_IDS = {
    4181015304,
    2402750047,
    2539159609,
    2671296585,
    3320102372,
    1728464210,
    3931073091,
    1267668072,
    562823142,
    2075394470,
    317671698,
    3405509837,
    2408498452,
    3923352168,
}
_PINNED_STATIC_COMPONENT_KEYS = {
    "unique_keys",
    "inv_unique_keys",
    "common_keys_hash",
    "common_keys_tail",
}
_SFP_SOFT_MUTABLE_EVENT_IDS = {
    2426461220,
    1369899379,
    772896908,
    1784476536,
    3055761315,
}


def _parse_event_value(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except Exception:
        return None


def _coerce_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _coerce_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _clone_json(value: Any) -> Any:
    return json.loads(json.dumps(value))


def _is_numeric_hash_like(value: Any) -> bool:
    text = str(value or "").strip()
    return text.isdigit() and len(text) >= 10


def _derive_numeric_variant(seed: str, label: str, original: Any) -> str:
    text = str(original or "").strip()
    if not text:
        return text
    length = len(text)
    material = f"{seed}:{label}:{text}".encode("utf-8")
    digits: list[str] = []
    digest = hashlib.sha256(material).digest()
    while len(digits) < length:
        for byte in digest:
            digits.append(str(byte % 10))
            if len(digits) >= length:
                break
        digest = hashlib.sha256(digest + material).digest()
    if digits and digits[0] == "0":
        digits[0] = "1"
    return "".join(digits[:length])


def _derive_component_hash_variant(
    seed: str,
    label: str,
    current: Any,
    *,
    fallback_length: int = 19,
    negative_only: bool = False,
) -> str:
    text = str(current or "").strip()
    sign = ""
    if text.startswith("-"):
        sign = "-"
        text = text[1:]
    elif text.startswith("+"):
        text = text[1:]

    if text.isdigit() and len(text) >= 10:
        base_digits = text
        length = len(text)
    else:
        length = max(10, int(fallback_length))
        base_digits = "7" * length

    derived = _derive_numeric_variant(seed, label, base_digits)
    if negative_only:
        sign = "-"
    return f"{sign}{derived[:length]}"


def _template_identity_seed(template_data: Dict[str, Any], chosen_variant: Dict[str, Any]) -> str:
    components = template_data.get("components") if isinstance(template_data.get("components"), dict) else {}
    navigator = components.get("navigator") if isinstance(components.get("navigator"), dict) else {}
    screen = components.get("screen") if isinstance(components.get("screen"), dict) else {}
    event_map = {
        int(row[0]): row[1]
        for row in template_data.get("events", [])
        if isinstance(row, list) and len(row) >= 2 and str(row[0]).isdigit()
    }
    timezone_name = ""
    timezone_event = _parse_event_value(event_map.get(3486023461))
    if isinstance(timezone_event, list) and timezone_event:
        timezone_name = str(timezone_event[0] or "")
    else:
        raw_timezone_name = _parse_event_value(event_map.get(1181016567))
        if isinstance(raw_timezone_name, str):
            timezone_name = raw_timezone_name

    width = _coerce_int(screen.get("width"), 0)
    height = _coerce_int(screen.get("height"), 0)
    dpr = _coerce_float(components.get("device_pixel_ratio"), 1.0)
    return "|".join(
        (
            "sfp-identity",
            str(chosen_variant.get("profile_name") or ""),
            str(navigator.get("user_agent") or ""),
            str(navigator.get("language") or ""),
            timezone_name,
            f"{width}x{height}",
            f"{dpr:.3f}",
        )
    )


def _stable_index(seed: str, label: str, modulo: int) -> int:
    if modulo <= 0:
        return 0
    digest = hashlib.sha256(f"{seed}:{label}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % modulo


def _mutate_gpu_event_value(raw_value: Any, seed: str) -> Any:
    parsed = _parse_event_value(raw_value)
    if not isinstance(parsed, list) or len(parsed) < 2:
        return raw_value

    base_vendor = str(parsed[0] or "Mozilla")
    renderer_pool = [
        "ANGLE (NVIDIA, NVIDIA GeForce GTX 980 Direct3D11 vs_5_0 ps_5_0), or similar",
        "ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0), or similar",
        "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 Ti Direct3D11 vs_5_0 ps_5_0), or similar",
        "ANGLE (NVIDIA, NVIDIA GeForce RTX 2050 Direct3D11 vs_5_0 ps_5_0), or similar",
        "ANGLE (NVIDIA, NVIDIA GeForce RTX 3050 Laptop GPU Direct3D11 vs_5_0 ps_5_0), or similar",
    ]
    parsed[0] = base_vendor
    parsed[1] = renderer_pool[_stable_index(seed, "gpu-renderer", len(renderer_pool))]
    return _json_compact(parsed)


def _mutate_window_keys_event_value(raw_value: Any, seed: str) -> Any:
    parsed = _parse_event_value(raw_value)
    if not isinstance(parsed, list) or len(parsed) < 17:
        return raw_value

    next_payload = _clone_json(parsed)
    delta_pool = (-2, -1, 1, 2)
    shared_delta = delta_pool[_stable_index(seed, "window-keys-delta", len(delta_pool))]
    for index in (1, 2, 7):
        if index >= len(next_payload):
            continue
        try:
            next_payload[index] = max(1, int(next_payload[index]) + shared_delta)
        except Exception:
            continue

    if len(next_payload) > 14 and isinstance(next_payload[14], list):
        additions = ["setImmediate", "queueMicrotask", "scheduler"]
        picked = additions[_stable_index(seed, "window-keys-extra", len(additions))]
        if picked not in next_payload[14]:
            next_payload[14] = list(next_payload[14]) + [picked]

    return _json_compact(next_payload)


def _normalize_static_fp_template(raw: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, dict):
        return None
    if isinstance(raw.get("proof_spec"), dict) and isinstance(raw.get("components"), dict) and isinstance(raw.get("events"), list):
        return _clone_json(raw)
    nested = raw.get("data")
    if isinstance(nested, dict) and isinstance(nested.get("proof_spec"), dict) and isinstance(nested.get("components"), dict) and isinstance(nested.get("events"), list):
        return _clone_json(nested)
    return None


def _template_user_agent(template_data: Optional[Dict[str, Any]]) -> str:
    if not isinstance(template_data, dict):
        return ""
    components = template_data.get("components")
    if not isinstance(components, dict):
        return ""
    navigator = components.get("navigator")
    if not isinstance(navigator, dict):
        return ""
    return str(navigator.get("user_agent") or "").strip()


def _load_static_fp_template(static_fp_path: str = "", static_fp_data: Any = None) -> tuple[Optional[Dict[str, Any]], str]:
    source_name = ""
    raw: Any = None
    if static_fp_path.strip():
        path = Path(static_fp_path).expanduser()
        raw = json.loads(path.read_text(encoding="utf-8"))
        source_name = path.name
    elif isinstance(static_fp_data, dict):
        raw = static_fp_data
        source_name = "inline_static_fp"
    template = _normalize_static_fp_template(raw)
    if raw is not None and template is None:
        raise ValueError("Provided static fingerprint is not a full proof template with proof_spec/components/events")
    return template, source_name


def _firefox_versions_from_ua(user_agent: str) -> tuple[str, str]:
    text = str(user_agent or "")
    marker = "Firefox/"
    if marker not in text:
        return "", ""
    full_version = text.split(marker, 1)[1].split(" ", 1)[0].strip()
    major_version = full_version.split(".", 1)[0] if full_version else ""
    return major_version, full_version


def _chrome_versions_from_ua(user_agent: str) -> tuple[str, str]:
    text = str(user_agent or "")
    marker = "Chrome/"
    if marker not in text:
        return "", ""
    full_version = text.split(marker, 1)[1].split(" ", 1)[0].strip()
    major_version = full_version.split(".", 1)[0] if full_version else ""
    return major_version, full_version


def _apply_browser_identity(cfg: SolveConfig) -> SolveConfig:
    if is_firefox_user_agent(cfg.ua):
        major, full = _firefox_versions_from_ua(cfg.ua)
        cfg.sec_ch_ua = ""
        if major:
            cfg.chrome_version = major
        if full:
            cfg.chrome_full_version = full
        if not cfg.lang:
            cfg.lang = "en-US"
        if not cfg.languages:
            cfg.languages = [cfg.lang, "en"]
    else:
        major, full = _chrome_versions_from_ua(cfg.ua)
        if major:
            cfg.chrome_version = major
        if full:
            cfg.chrome_full_version = full
        cfg.sec_ch_ua = (
            f'"Chromium";v="{cfg.chrome_version}", '
            f'"Not-A.Brand";v="24", '
            f'"Google Chrome";v="{cfg.chrome_version}"'
        )
    return cfg


def _preferred_foox1_cluster_for_target(
    host: str = "",
    sitekey: str = "",
    href: str = "",
) -> str:
    host_text = str(host or "").strip().lower()
    sitekey_text = str(sitekey or "").strip().lower()
    href_text = str(href or "").strip().lower()

    if (
        "riotgames.com" in host_text
        or "riotgames.com" in href_text
        or sitekey_text in {
            "019f1553-3845-481c-a6f5-5a60ccf6d830",
            "db18a187-7b77-4dac-a6cb-6dd5215973cf",
        }
    ):
        return "ptbr_saopaulo"

    if (
        "epicgames.com" in host_text
        or "epicgames.com" in href_text
        or "discord.com" in host_text
        or "discord.com" in href_text
        or sitekey_text in {
            "91e4137f-95af-4bc9-97af-cdcedce21c8c",
            "f5561ba9-8f1e-40ca-9b5b-a0b3f719ef34",
        }
    ):
        return "enus_america"

    return "enus_america"


def _json_compact(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _load_sfp_variant_state() -> Dict[str, Any]:
    if not _SFP_VARIANT_STATE_PATH.exists():
        return {}
    try:
        raw = json.loads(_SFP_VARIANT_STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return raw if isinstance(raw, dict) else {}


def _save_sfp_variant_state(state: Dict[str, Any]) -> None:
    try:
        _SFP_VARIANT_STATE_PATH.write_text(json.dumps(state, ensure_ascii=True, indent=2), encoding="utf-8")
    except Exception:
        pass


def _build_sfp_variants() -> list[Dict[str, Any]]:
    variants: list[Dict[str, Any]] = []
    for cohort_index in range(_SFP_COHORT_COUNT):
        profile_name = f"static_fp_Africa_Cairo__en_US__nvidia__1680x1050@1_25__c{cohort_index:02d}_sfp.json"
        variants.append(
            {
                "profile_name": profile_name,
                "cohort": cohort_index,
            }
        )
    return variants


def _pick_sfp_variant() -> Dict[str, Any]:
    rng = random.SystemRandom()
    variants = _build_sfp_variants()
    rng.shuffle(variants)
    state = _load_sfp_variant_state()
    recent = [str(item) for item in state.get("recent", []) if str(item).strip()]
    recent_set = set(recent)

    scored: list[tuple[float, Dict[str, Any]]] = []
    for variant in variants:
        profile_name = str(variant["profile_name"])
        fail_streak = get_epic_profile_fail_streak(profile_name)
        score = float(fail_streak * 100)
        if profile_name in recent_set:
            score += 40 + recent.index(profile_name)
        scored.append((score, variant))

    scored.sort(key=lambda item: item[0])
    best_score = scored[0][0] if scored else 0.0
    shortlist = [item[1] for item in scored if item[0] <= best_score + 5][: min(32, len(scored))]
    chosen = _clone_json(rng.choice(shortlist or variants))

    recent_next = [str(chosen["profile_name"])]
    for item in recent:
        if item != chosen["profile_name"]:
            recent_next.append(item)
        if len(recent_next) >= 24:
            break
    state["recent"] = recent_next
    _save_sfp_variant_state(state)
    return chosen


def _set_event_value(template_data: Dict[str, Any], event_id: int, value: Any) -> None:
    rows = template_data.get("events")
    if not isinstance(rows, list):
        template_data["events"] = [[event_id, value]]
        return
    for row in rows:
        if not isinstance(row, list) or len(row) < 2:
            continue
        try:
            if int(row[0]) != int(event_id):
                continue
        except Exception:
            continue
        row[1] = value
        return
    rows.append([event_id, value])


def _mutate_request_history_payload(payload: list[Any], *, rng: random.SystemRandom) -> list[Any]:
    next_payload = _clone_json(payload)
    shared_start_scale = rng.uniform(0.996, 1.008)
    shared_end_scale = rng.uniform(0.996, 1.012)
    rolling_bias = rng.uniform(-1.25, 1.25)
    for index, row in enumerate(next_payload):
        if not isinstance(row, list) or len(row) < 3:
            continue
        try:
            start_value = float(row[1])
            end_value = float(row[2])
        except Exception:
            continue
        next_start = max(0.0, (start_value * shared_start_scale) + rolling_bias + rng.uniform(-0.35, 0.35))
        next_end = max(next_start, (end_value * shared_end_scale) + rolling_bias + rng.uniform(-0.5, 0.5))
        row[1] = round(next_start, 7)
        row[2] = round(next_end, 7)
        rolling_bias += rng.uniform(-0.15, 0.15) * (1 if index % 2 == 0 else -1)
    return next_payload


def _mutate_mark_payload(payload: list[Any], *, rng: random.SystemRandom) -> list[Any]:
    next_payload = _clone_json(payload)
    if not next_payload or not isinstance(next_payload[0], list):
        return next_payload
    shared_offset = rng.choice([-2, -1, 1, 2])
    next_numbers = []
    for item in next_payload[0]:
        try:
            value = int(item)
        except Exception:
            next_numbers.append(item)
            continue
        next_numbers.append(value + shared_offset + rng.choice([0, 0, 0, -1, 1]))
    next_payload[0] = next_numbers
    return next_payload


def _mutate_int_list_payload(
    payload: list[Any],
    *,
    rng: random.SystemRandom,
    delta_choices: tuple[int, ...] = (-1, 0, 1),
    clamp_min: int = 0,
) -> list[Any]:
    next_payload = _clone_json(payload)
    for index, item in enumerate(next_payload):
        try:
            value = int(item)
        except Exception:
            continue
        next_payload[index] = max(clamp_min, value + rng.choice(delta_choices))
    return next_payload


def _mutate_nearby_screen(
    width: int,
    height: int,
    avail_width: int,
    avail_height: int,
    dpr: float,
    *,
    rng: random.SystemRandom,
) -> tuple[int, int, int, int, float]:
    delta_h = max(24, height - avail_height)
    variants = [
        (width, height, width, max(0, height - delta_h), dpr),
        (width + 64, height + 36, width + 64, max(0, height + 36 - delta_h), min(1.5, max(1.0, dpr))),
        (max(1280, width - 64), max(720, height - 36), max(1280, width - 64), max(0, max(720, height - 36) - delta_h), min(1.5, max(1.0, dpr))),
    ]
    next_width, next_height, next_avail_width, next_avail_height, next_dpr = rng.choice(variants)
    if rng.choice([True, False]):
        next_dpr = 1.25 if abs(next_dpr - 1.25) < abs(next_dpr - 1.0) else 1.0
    return int(next_width), int(next_height), int(next_avail_width), int(next_avail_height), float(next_dpr)


def _mutate_builtin_static_fp_template(template_data: Dict[str, Any]) -> Dict[str, Any]:
    mutated = _clone_json(template_data)
    rng = random.SystemRandom()
    chosen_variant = _pick_sfp_variant()
    cohort = int(chosen_variant["cohort"])
    profile_identity_seed = _template_identity_seed(template_data, chosen_variant)
    session_seed = f"{profile_identity_seed}|solve|{time.time_ns()}|{rng.random()}"
    original_event_map = {
        int(row[0]): row[1]
        for row in template_data.get("events", [])
        if isinstance(row, list) and len(row) >= 2
        and str(row[0]).isdigit()
    }

    mutated["rand"] = [rng.random(), rng.random()]

    components = mutated.get("components")
    original_components = template_data.get("components") if isinstance(template_data.get("components"), dict) else {}
    original_navigator = original_components.get("navigator") if isinstance(original_components.get("navigator"), dict) else {}
    if isinstance(components, dict):
        component_hash_specs = (
            ("canvas_hash", 20, False),
            ("parent_win_hash", 19, False),
            ("performance_hash", 20, False),
            ("webrtc_hash", 19, True),
        )
        for key, fallback_length, negative_only in component_hash_specs:
            current = components.get(key)
            components[key] = _derive_component_hash_variant(
                profile_identity_seed,
                f"component:{key}",
                current,
                fallback_length=fallback_length,
                negative_only=negative_only,
            )
        navigator = components.get("navigator")
        if isinstance(navigator, dict):
            if "language" in original_navigator:
                navigator["language"] = _clone_json(original_navigator["language"])
            if "languages" in original_navigator:
                navigator["languages"] = _clone_json(original_navigator["languages"])
            current_mtp = _coerce_int(navigator.get("max_touch_points"), 0)
            if current_mtp > 0:
                navigator["max_touch_points"] = max(0, current_mtp + rng.choice([-1, 0, 1]))
            components["has_touch"] = int(navigator.get("max_touch_points") or 0) > 0
        screen = components.get("screen")
        if isinstance(screen, dict):
            width = _coerce_int(screen.get("width"), 0)
            height = _coerce_int(screen.get("height"), 0)
            avail_width = _coerce_int(screen.get("avail_width"), width)
            avail_height = _coerce_int(screen.get("avail_height"), height)
            dpr = _coerce_float(components.get("device_pixel_ratio"), 1.0)
            if width > 0 and height > 0:
                next_width, next_height, next_avail_width, next_avail_height, next_dpr = _mutate_nearby_screen(
                    width,
                    height,
                    avail_width,
                    avail_height,
                    dpr,
                    rng=rng,
                )
                screen["width"] = next_width
                screen["height"] = next_height
                screen["avail_width"] = next_avail_width
                screen["avail_height"] = next_avail_height
                components["device_pixel_ratio"] = next_dpr
        for key in _PINNED_STATIC_COMPONENT_KEYS:
            if key in original_components:
                components[key] = _clone_json(original_components[key])

    perf_rows = mutated.get("perf")
    if isinstance(perf_rows, list):
        next_perf = []
        perf_scale = rng.uniform(0.996, 1.01)
        for row in perf_rows:
            if not isinstance(row, list) or len(row) < 2:
                next_perf.append(row)
                continue
            new_row = list(row)
            try:
                base_value = float(new_row[1])
            except Exception:
                next_perf.append(new_row)
                continue
            phase_scale = perf_scale * rng.uniform(0.9985, 1.0025)
            new_row[1] = round(max(1.0, base_value * phase_scale), 1)
            next_perf.append(new_row)
        mutated["perf"] = next_perf

    _set_event_value(mutated, 2054986590, f"{time.time() * 1000:.1f}")

    for event_id, low, high in (
        (3663932439, 0.992, 1.012),
        (2972341029, 0.992, 1.01),
        (580323850, 0.992, 1.01),
        (2182569285, 0.992, 1.012),
    ):
        current = None
        for row in mutated.get("events", []):
            if not isinstance(row, list) or len(row) < 2:
                continue
            try:
                if int(row[0]) != event_id:
                    continue
            except Exception:
                continue
            current = row[1]
            break
        if current is None:
            continue
        try:
            base_value = float(current)
        except Exception:
            continue
        next_value = base_value * rng.uniform(low, high)
        if isinstance(current, str) and "." in current:
            _set_event_value(mutated, event_id, str(round(next_value, 7)).rstrip("0").rstrip("."))
        else:
            _set_event_value(mutated, event_id, str(int(round(next_value))))

    for row in mutated.get("events", []):
        if not isinstance(row, list) or len(row) < 2:
            continue
        try:
            event_id = int(row[0])
        except Exception:
            continue
        if event_id in _SFP_MUTABLE_HASH_EVENT_IDS and _is_numeric_hash_like(row[1]):
            row[1] = _derive_numeric_variant(session_seed, f"event:{event_id}", row[1])
            continue
        if event_id == 504458258:
            parsed = _parse_event_value(row[1])
            if isinstance(parsed, list) and len(parsed) >= 6 and isinstance(components, dict):
                navigator = components.get("navigator")
                if isinstance(navigator, dict):
                    parsed[4] = str(original_navigator.get("language") or navigator.get("language") or parsed[4])
                    parsed[5] = list(original_navigator.get("languages") or navigator.get("languages") or [parsed[4]])
                if len(parsed) > 2:
                    try:
                        current_mem = int(parsed[2])
                    except Exception:
                        current_mem = 8
                    parsed[2] = max(4, current_mem + rng.choice([-4, 0, 4]))
                if len(parsed) > 3:
                    try:
                        current_hc = int(parsed[3])
                    except Exception:
                        current_hc = 4
                    parsed[3] = max(2, current_hc + rng.choice([-2, 0, 2]))
                _set_event_value(mutated, 504458258, _json_compact(parsed))
                continue
        if event_id == 1000750690:
            parsed = _parse_event_value(row[1])
            screen = components.get("screen") if isinstance(components, dict) else None
            navigator = components.get("navigator") if isinstance(components, dict) else None
            if isinstance(parsed, list) and len(parsed) > 10 and isinstance(screen, dict):
                width = _coerce_int(screen.get("width"), _coerce_int(parsed[0], 0))
                height = _coerce_int(screen.get("height"), _coerce_int(parsed[1], 0))
                avail_width = _coerce_int(screen.get("avail_width"), width)
                avail_height = _coerce_int(screen.get("avail_height"), height)
                dpr = _coerce_float(components.get("device_pixel_ratio") if isinstance(components, dict) else parsed[8], _coerce_float(parsed[8], 1.0))
                parsed[0] = width
                parsed[1] = height
                parsed[2] = avail_width
                parsed[3] = avail_height
                parsed[7] = _coerce_int((navigator or {}).get("max_touch_points"), _coerce_int(parsed[7], 0))
                parsed[8] = dpr
                parsed[9] = avail_width
                parsed[10] = avail_height
                _set_event_value(mutated, 1000750690, _json_compact(parsed))
                continue
        if event_id in _SFP_SOFT_MUTABLE_EVENT_IDS:
            parsed = _parse_event_value(row[1])
            if event_id in {2426461220, 1369899379}:
                try:
                    base_value = int(str(row[1]).strip())
                except Exception:
                    continue
                if event_id == 2426461220:
                    row[1] = str(max(1000, base_value + rng.choice([-8, -4, -2, 2, 4, 8])))
                else:
                    row[1] = str(max(1, base_value + rng.choice([-2, -1, 1, 2])))
                continue
            if event_id == 772896908 and isinstance(parsed, list):
                _set_event_value(
                    mutated,
                    772896908,
                    _json_compact(_mutate_int_list_payload(parsed, rng=rng, delta_choices=(-1, 0, 1), clamp_min=0)),
                )
                continue
            if event_id == 1784476536 and isinstance(parsed, list):
                next_payload = _clone_json(parsed)
                for target_index in (3, 4, 5):
                    if target_index >= len(next_payload):
                        continue
                    try:
                        next_payload[target_index] = max(1, int(next_payload[target_index]) + rng.choice([-1, 0, 1]))
                    except Exception:
                        continue
                _set_event_value(mutated, 1784476536, _json_compact(next_payload))
                continue
            if event_id == 3055761315 and isinstance(parsed, list):
                next_payload = _clone_json(parsed)
                for target_index, deltas in ((0, (-1, 0, 1)), (1, (-1, 0, 1)), (3, (-256, -128, 0, 128, 256)), (4, (-256, -128, 0, 128, 256))):
                    if target_index >= len(next_payload):
                        continue
                    try:
                        next_payload[target_index] = max(1, int(next_payload[target_index]) + rng.choice(deltas))
                    except Exception:
                        continue
                _set_event_value(mutated, 3055761315, _json_compact(next_payload))
                continue
        parsed = _parse_event_value(row[1])
        if event_id == 3357624742 and isinstance(parsed, list):
            _set_event_value(mutated, 3357624742, _json_compact(_mutate_request_history_payload(parsed, rng=rng)))
        elif event_id == 4181739560 and isinstance(parsed, list):
            _set_event_value(mutated, 4181739560, _json_compact(_mutate_mark_payload(parsed, rng=rng)))
        elif event_id == 2556820389 and isinstance(parsed, list) and len(parsed) >= 3:
            try:
                loop_count = int(parsed[1])
            except Exception:
                continue
            next_loop = max(512, loop_count + rng.choice([-3, -2, -1, 0, 1, 2, 3]))
            parsed[1] = next_loop
            parsed[2] = next_loop
            _set_event_value(mutated, 2556820389, _json_compact(parsed))
        elif event_id == 58508894 and isinstance(parsed, list) and len(parsed) >= 2:
            try:
                parsed[1] = int(max(1, round(float(parsed[1]) * rng.uniform(0.999, 1.002))))
            except Exception:
                continue
            _set_event_value(mutated, 58508894, _json_compact(parsed))
        elif event_id == 1000750690 and isinstance(parsed, list) and len(parsed) > 10:
            try:
                avail_width = int(parsed[2])
                avail_height = int(parsed[3])
                inner_width = int(parsed[9])
                inner_height = int(parsed[10])
            except Exception:
                continue
            parsed[9] = max(640, min(avail_width, inner_width + rng.choice([-8, 0, 8])))
            parsed[10] = max(480, min(avail_height, inner_height + rng.choice([-8, 0, 8])))
            _set_event_value(mutated, 1000750690, _json_compact(parsed))

    for row in mutated.get("events", []):
        if not isinstance(row, list) or len(row) < 2:
            continue
        try:
            event_id = int(row[0])
        except Exception:
            continue
        parsed = _parse_event_value(row[1])
        if event_id == 1000750690 and isinstance(parsed, list) and len(parsed) > 10:
            try:
                avail_width = int(parsed[2])
                avail_height = int(parsed[3])
                inner_width = int(parsed[9])
                inner_height = int(parsed[10])
            except Exception:
                continue
            parsed[9] = max(640, min(avail_width, inner_width + rng.choice([-8, 0, 8])))
            parsed[10] = max(480, min(avail_height, inner_height + rng.choice([-8, 0, 8])))
            _set_event_value(mutated, 1000750690, _json_compact(parsed))

    original_gpu_event = original_event_map.get(1866465638)
    if original_gpu_event not in (None, ""):
        _set_event_value(mutated, 1866465638, _mutate_gpu_event_value(original_gpu_event, profile_identity_seed))
    original_window_keys_event = original_event_map.get(1075205395)
    if original_window_keys_event not in (None, ""):
        _set_event_value(mutated, 1075205395, _mutate_window_keys_event_value(original_window_keys_event, profile_identity_seed))
    for timezone_event_id in (1181016567, 3486023461):
        original_timezone_event = original_event_map.get(timezone_event_id)
        if original_timezone_event not in (None, ""):
            _set_event_value(mutated, timezone_event_id, _clone_json(original_timezone_event))

    mutated["__sfp_variant_id__"] = f"cohort__c{cohort:02d}"
    mutated["__sfp_profile_name__"] = str(chosen_variant["profile_name"])
    return mutated


def _apply_template_to_cfg(
    cfg: SolveConfig,
    template_data: Dict[str, Any],
    *,
    profile_name: str,
    profile_source: str,
    directory: str = "",
    cluster: str = "",
    language: str = "",
    timezone_name: str = "",
    quality_score: int = 0,
    static_full: bool = False,
    sfp_enabled: bool = False,
) -> SolveConfig:
    components = template_data.get("components", {})
    proof_spec = template_data.get("proof_spec", {}) if isinstance(template_data.get("proof_spec"), dict) else {}
    navigator = components.get("navigator", {}) if isinstance(components, dict) else {}
    screen = components.get("screen", {}) if isinstance(components, dict) else {}
    event_map = {}
    for row in template_data.get("events", []):
        if not isinstance(row, list) or len(row) < 2:
            continue
        try:
            event_map[int(row[0])] = row[1]
        except Exception:
            continue

    if isinstance(navigator, dict):
        user_agent = navigator.get("user_agent")
        if user_agent:
            cfg.ua = str(user_agent)

        languages = navigator.get("languages")
        if isinstance(languages, list):
            parsed_languages = [str(item) for item in languages if item]
            if parsed_languages:
                cfg.languages = parsed_languages

        nav_language = navigator.get("language")
        if nav_language:
            cfg.lang = str(nav_language)
        elif cfg.languages:
            cfg.lang = cfg.languages[0]

        platform = navigator.get("platform")
        if platform:
            cfg.platform = str(platform)

        cfg.max_touch_points = _coerce_int(navigator.get("max_touch_points"), cfg.max_touch_points)

    if isinstance(screen, dict):
        cfg.screen = Screen(
            avail_height=_coerce_int(screen.get("avail_height"), cfg.screen.avail_height),
            avail_width=_coerce_int(screen.get("avail_width"), cfg.screen.avail_width),
            height=_coerce_int(screen.get("height"), cfg.screen.height),
            width=_coerce_int(screen.get("width"), cfg.screen.width),
            color_depth=_coerce_int(screen.get("color_depth"), cfg.screen.color_depth),
            pixel_depth=_coerce_int(screen.get("pixel_depth"), cfg.screen.pixel_depth),
        )

    cfg.device_pixel_ratio = _coerce_float(components.get("device_pixel_ratio"), cfg.device_pixel_ratio)
    if template_data.get("href"):
        cfg.href = str(template_data.get("href"))
    if "fingerprint_type" in proof_spec:
        cfg.fingerprint_type = proof_spec.get("fingerprint_type")

    navigator_event = _parse_event_value(event_map.get(504458258))
    if isinstance(navigator_event, list):
        if len(navigator_event) > 2:
            cfg.device_memory = _coerce_int(navigator_event[2], cfg.device_memory)
        if len(navigator_event) > 3:
            cfg.hardware_concurrency = _coerce_int(navigator_event[3], cfg.hardware_concurrency)

    gpu_event = _parse_event_value(event_map.get(1866465638))
    if isinstance(gpu_event, list) and len(gpu_event) >= 2:
        cfg.gpu_vendor = str(gpu_event[0])
        cfg.renderer = str(gpu_event[1])

    timezone_event = _parse_event_value(event_map.get(3486023461))
    if isinstance(timezone_event, list) and len(timezone_event) >= 2:
        cfg.timezone = str(timezone_event[0])
        cfg.timezone_offset = _coerce_int(timezone_event[1], cfg.timezone_offset)
    else:
        event_timezone_name = _parse_event_value(event_map.get(1181016567))
        if isinstance(event_timezone_name, str) and event_timezone_name:
            cfg.timezone = event_timezone_name

    ua_entropy_event = _parse_event_value(event_map.get(2189040541))
    if isinstance(ua_entropy_event, list) and len(ua_entropy_event) >= 6:
        chrome_full_version = str(ua_entropy_event[5])
        if chrome_full_version:
            cfg.chrome_full_version = chrome_full_version
            cfg.chrome_version = chrome_full_version.split(".", 1)[0]

    cfg.profile_data = {
        "profile_name": profile_name,
        "profile_source": profile_source,
        "foox1_name": profile_name,
        "foox1_directory": directory,
        "foox1_cluster": cluster,
        "foox1_language": language or cfg.lang,
        "foox1_timezone": timezone_name or cfg.timezone,
        "foox1_template": _clone_json(template_data),
        "foox1_quality_score": int(quality_score or 0),
        "browser": "firefox" if is_firefox_user_agent(cfg.ua) else "chrome",
        "static_fp_enabled": bool(static_full),
        "sfp_enabled": bool(sfp_enabled),
    }
    if static_full:
        cfg.profile_data["static_fp_template"] = _clone_json(template_data)
    return _apply_browser_identity(cfg)


def build_epic_cfg(
    user_agent_override: str = "",
    static_fp_path: str = "",
    static_fp_data: Any = None,
    static_fp_mutate: bool = False,
    target_host: str = "",
    target_sitekey: str = "",
    target_href: str = "",
) -> SolveConfig:
    cfg = SolveConfig()
    cfg.ua = REDUCED_UA
    cfg.lang = "en-US"
    cfg.languages = ["en-US", "en"]
    cfg.sitekey = EPIC_SITEKEY
    cfg.host = EPIC_HOST
    cfg.href = EPIC_HREF
    cfg.version = PopularCaptcha_VERSION

    # Apply UA override BEFORE profile selection so the correct browser is picked
    if user_agent_override and user_agent_override.strip():
        cfg.ua = user_agent_override.strip()

    static_template, static_name = _load_static_fp_template(static_fp_path=static_fp_path, static_fp_data=static_fp_data)
    if static_template is not None:
        effective_template = _mutate_builtin_static_fp_template(static_template) if static_fp_mutate else static_template
        effective_profile_name = str(
            effective_template.get("__sfp_profile_name__")
            or ((static_name or "static_fp.json").removesuffix(".json") + ("_sfp.json" if static_fp_mutate else ".json"))
        )
        cfg = _apply_template_to_cfg(
            cfg,
            effective_template,
            profile_name=effective_profile_name,
            profile_source="semi_static_fp" if static_fp_mutate else "static_fp",
            directory="static",
            cluster="static_fp_sfp" if static_fp_mutate else "static_fp",
            language=str(effective_template.get("components", {}).get("navigator", {}).get("language") or ""),
            timezone_name="",
            quality_score=1000,
            static_full=True,
            sfp_enabled=bool(static_fp_mutate),
        )
    else:
        template = pick_foox1_template(
            epic_only=True,
            preferred_directory="foox1",
            preferred_browser="firefox" if is_firefox_user_agent(cfg.ua) else "chrome",
            preferred_cluster=_preferred_foox1_cluster_for_target(
                target_host or cfg.host,
                target_sitekey or cfg.sitekey,
                target_href or cfg.href,
            ),
        )
        template_browser = str(template.get("browser") or "").strip().lower() if isinstance(template, dict) else ""
        auto_static_template = None
        auto_static_name = ""
        if _DEFAULT_STATIC_FP_PATH.exists():
            try:
                auto_static_template, auto_static_name = _load_static_fp_template(static_fp_path=str(_DEFAULT_STATIC_FP_PATH))
            except Exception:
                auto_static_template, auto_static_name = None, ""

        use_auto_static = bool(
            auto_static_template is not None
            and is_firefox_user_agent(cfg.ua)
            and is_firefox_user_agent(_template_user_agent(auto_static_template))
            and template_browser != "firefox"
        )

        if use_auto_static and auto_static_template is not None:
            cfg = _apply_template_to_cfg(
                cfg,
                auto_static_template,
                profile_name=auto_static_name or "static_fp_auto.json",
                profile_source="static_fp_auto",
                directory="static",
                cluster="static_fp_auto",
                language=str(auto_static_template.get("components", {}).get("navigator", {}).get("language") or ""),
                timezone_name="",
                quality_score=1000,
                static_full=True,
                sfp_enabled=False,
            )
        elif template is not None:
            cfg = _apply_template_to_cfg(
                cfg,
                template.get("data") or {},
                profile_name=str(template.get("name") or "foox1_template"),
                profile_source="foox1",
                directory=str(template.get("directory") or ""),
                cluster=str(template.get("epic_cluster") or ""),
                language=str(template.get("language") or ""),
                timezone_name=str(template.get("timezone") or ""),
                quality_score=int(template.get("quality_score", 0) or 0),
                static_full=False,
                sfp_enabled=False,
            )
        else:
            cfg.profile_data = {
                "profile_name": "epic_rebuilt_default",
                "profile_source": "static",
                "browser": "firefox" if is_firefox_user_agent(cfg.ua) else "chrome",
                "static_fp_enabled": False,
            }

    if not cfg.profile_data:
        cfg.profile_data = {
            "profile_name": "epic_rebuilt_default",
            "profile_source": "static",
            "browser": "firefox" if is_firefox_user_agent(cfg.ua) else "chrome",
            "static_fp_enabled": False,
        }

    if user_agent_override.strip() and not bool(cfg.profile_data.get("static_fp_enabled")):
        cfg.ua = user_agent_override.strip()
        cfg.profile_data["browser"] = "firefox" if is_firefox_user_agent(cfg.ua) else "chrome"

    return _apply_browser_identity(cfg)


def serialize_solve_config(cfg: SolveConfig) -> Dict[str, Any]:
    return {
        "ua": cfg.ua,
        "lang": cfg.lang,
        "sec_ch_ua": cfg.sec_ch_ua,
        "chrome_version": cfg.chrome_version,
        "chrome_full_version": cfg.chrome_full_version,
        "languages": list(cfg.languages),
        "hardware_concurrency": int(cfg.hardware_concurrency),
        "device_memory": int(cfg.device_memory),
        "device_pixel_ratio": float(cfg.device_pixel_ratio),
        "screen": {
            "avail_height": int(cfg.screen.avail_height),
            "avail_width": int(cfg.screen.avail_width),
            "height": int(cfg.screen.height),
            "width": int(cfg.screen.width),
            "color_depth": int(cfg.screen.color_depth),
            "pixel_depth": int(cfg.screen.pixel_depth),
        },
        "renderer": cfg.renderer,
        "gpu_vendor": cfg.gpu_vendor,
        "max_touch_points": int(cfg.max_touch_points),
        "timezone_offset": int(cfg.timezone_offset),
        "timezone": cfg.timezone,
        "dark_mode": bool(cfg.dark_mode),
        "platform": cfg.platform,
        "sitekey": cfg.sitekey,
        "host": cfg.host,
        "version": cfg.version,
        "href": cfg.href,
        "fingerprint_type": cfg.fingerprint_type,
        "profile_data": cfg.profile_data if isinstance(cfg.profile_data, dict) else {},
    }


def deserialize_solve_config(data: Dict[str, Any]) -> SolveConfig:
    screen_data = data.get("screen") if isinstance(data, dict) else {}
    screen = Screen(
        avail_height=_coerce_int(getattr(screen_data, "get", lambda *_: None)("avail_height"), Screen().avail_height),
        avail_width=_coerce_int(getattr(screen_data, "get", lambda *_: None)("avail_width"), Screen().avail_width),
        height=_coerce_int(getattr(screen_data, "get", lambda *_: None)("height"), Screen().height),
        width=_coerce_int(getattr(screen_data, "get", lambda *_: None)("width"), Screen().width),
        color_depth=_coerce_int(getattr(screen_data, "get", lambda *_: None)("color_depth"), Screen().color_depth),
        pixel_depth=_coerce_int(getattr(screen_data, "get", lambda *_: None)("pixel_depth"), Screen().pixel_depth),
    )
    cfg = SolveConfig(
        ua=str(data.get("ua") or REDUCED_UA),
        lang=str(data.get("lang") or "en-US"),
        sec_ch_ua=str(data.get("sec_ch_ua") or SolveConfig().sec_ch_ua),
        chrome_version=str(data.get("chrome_version") or SolveConfig().chrome_version),
        chrome_full_version=str(data.get("chrome_full_version") or SolveConfig().chrome_full_version),
        languages=[str(item) for item in (data.get("languages") or ["en-US", "en"])],
        hardware_concurrency=_coerce_int(data.get("hardware_concurrency"), 8),
        device_memory=_coerce_int(data.get("device_memory"), 8),
        device_pixel_ratio=_coerce_float(data.get("device_pixel_ratio"), 1.0),
        screen=screen,
        renderer=str(data.get("renderer") or SolveConfig().renderer),
        gpu_vendor=str(data.get("gpu_vendor") or SolveConfig().gpu_vendor),
        max_touch_points=_coerce_int(data.get("max_touch_points"), 0),
        timezone_offset=_coerce_int(data.get("timezone_offset"), 0),
        timezone=str(data.get("timezone") or "UTC"),
        dark_mode=bool(data.get("dark_mode", False)),
        platform=str(data.get("platform") or "Win32"),
        sitekey=str(data.get("sitekey") or EPIC_SITEKEY),
        host=str(data.get("host") or EPIC_HOST),
        version=str(data.get("version") or PopularCaptcha_VERSION),
        href=str(data.get("href") or EPIC_HREF),
        fingerprint_type=data.get("fingerprint_type", 0),
        profile_data=data.get("profile_data") if isinstance(data.get("profile_data"), dict) else {},
    )
    return _apply_browser_identity(cfg)


def is_firefox_user_agent(user_agent: str) -> bool:
    return "Firefox/" in str(user_agent or "")


def _load_profile_state() -> Dict[str, Any]:
    if not _PROFILE_STATE_PATH.exists():
        return {}
    try:
        raw = json.loads(_PROFILE_STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return raw if isinstance(raw, dict) else {}


def record_epic_profile_result(profile_name: str, ok: bool) -> None:
    name = str(profile_name or "").strip()
    if not name:
        return
    with _PROFILE_STATE_LOCK:
        raw = _load_profile_state()
        outcomes = raw.get("outcomes") if isinstance(raw.get("outcomes"), dict) else {}
        entry = outcomes.get(name) if isinstance(outcomes.get(name), dict) else {}
        success = int(entry.get("success", 0) or 0)
        fail = int(entry.get("fail", 0) or 0)
        fail_streak = int(entry.get("fail_streak", 0) or 0)
        if ok:
            success += 1
            fail_streak = 0
        else:
            fail += 1
            fail_streak += 1
        outcomes[name] = {"success": success, "fail": fail, "fail_streak": fail_streak}
        raw["outcomes"] = outcomes
        try:
            _PROFILE_STATE_PATH.write_text(json.dumps(raw, ensure_ascii=True, indent=2), encoding="utf-8")
        except Exception:
            pass


def get_epic_profile_fail_streak(profile_name: str) -> int:
    name = str(profile_name or "").strip()
    if not name:
        return 0
    raw = _load_profile_state()
    outcomes = raw.get("outcomes") if isinstance(raw.get("outcomes"), dict) else {}
    entry = outcomes.get(name) if isinstance(outcomes.get(name), dict) else {}
    return int(entry.get("fail_streak", 0) or 0)


def apply_request_overrides(
    cfg: SolveConfig,
    *,
    host_override: str = "",
    sitekey_override: str = "",
    href_override: str = "",
    rqdata_required: bool = True,
    rqdata_override: str = "",
) -> SolveConfig:
    profile_data = cfg.profile_data if isinstance(cfg.profile_data, dict) else {}
    if sitekey_override.strip():
        cfg.sitekey = sitekey_override.strip()
        profile_data["requested_sitekey"] = cfg.sitekey
    if href_override.strip():
        cfg.href = href_override.strip()
        profile_data["requested_href"] = cfg.href
        if not host_override.strip():
            parsed = urlsplit(cfg.href)
            if parsed.hostname:
                cfg.host = parsed.hostname
                profile_data["requested_host"] = cfg.host
    if host_override.strip():
        cfg.host = host_override.strip()
        profile_data["requested_host"] = cfg.host
        if (
            not profile_data.get("static_fp_enabled")
            and not href_override.strip()
            and (not cfg.href or "www.epicgames.com" in str(cfg.href))
            and cfg.host != EPIC_HOST
        ):
            cfg.href = f"https://{cfg.host}/"
    profile_data["rqdata_required"] = bool(rqdata_required)
    if rqdata_override.strip():
        profile_data["rqdata_override"] = rqdata_override.strip()
    else:
        profile_data.pop("rqdata_override", None)
    cfg.profile_data = profile_data
    return cfg


def solve_pow_answer(c_payload: Any, cfg: Optional[SolveConfig] = None) -> str:
    payload = json.loads(c_payload) if isinstance(c_payload, str) else c_payload
    if not payload or not payload.get("req"):
        return "fail"

    pow_type = payload.get("type", "hsj")
    if pow_type == "hsl":
        return solve_hsl(payload["req"])

    try:
        return solve_hsj(payload["req"], cfg)
    except Exception:
        return solve_hsl(payload["req"])


def encrypt_n_value(plaintext: str) -> str:
    iv = _aes_rand(12)
    cipher = _AES_GCM.new(_AES_N_KEY, _AES_GCM.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    return base64.b64encode(ciphertext + tag + iv + b"\x00").decode("ascii")


def solve_and_encrypt_n(c_payload: Any, cfg: Optional[SolveConfig] = None) -> str:
    n_answer = solve_pow_answer(c_payload, cfg)
    return n_answer if n_answer == "fail" else encrypt_n_value(n_answer)


def _build_accept_language(cfg: SolveConfig) -> str:
    parts = []
    for i, lang in enumerate(cfg.languages):
        if i == 0:
            parts.append(lang)
        else:
            if is_firefox_user_agent(cfg.ua):
                q = max(round(0.5 - (i - 1) * 0.2, 1), 0.1)
            else:
                q = round(1.0 - i * 0.1, 1)
            parts.append(f"{lang};q={max(q, 0.1)}")
    return ",".join(parts)


def _hcaptcha_asset_referer(cfg: SolveConfig) -> str:
    version = str(getattr(cfg, "version", "") or "")
    if not version:
        return "https://newassets.hcaptcha.com/"
    return f"https://newassets.hcaptcha.com/captcha/v1/{version}/static/hcaptcha.html"


def _parse_cookie_header(cookie_header: str) -> Dict[str, str]:
    cookies: Dict[str, str] = {}
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        value = value.strip()
        if name:
            cookies[name] = value
    return cookies


def build_cookie_header(session: Any = None, cookies: Optional[Dict[str, Any]] = None, cookie_header: str = "") -> str:
    merged: Dict[str, str] = {}

    if cookies:
        merged.update({str(k): str(v) for k, v in cookies.items() if v is not None})
    if cookie_header:
        merged.update(_parse_cookie_header(cookie_header))

    jar = getattr(session, "cookies", None)
    if jar is not None:
        try:
            for key, value in jar.items():
                merged[str(key)] = str(value)
        except Exception:
            try:
                for cookie in jar:
                    name = getattr(cookie, "name", None)
                    value = getattr(cookie, "value", None)
                    if name and value is not None:
                        merged[str(name)] = str(value)
            except Exception:
                pass

    return "; ".join(f"{key}={value}" for key, value in merged.items())


def build_checkcaptcha_headers(cfg: SolveConfig, cookie_value: str) -> Dict[str, str]:
    headers = {
        "accept": "application/json, application/octet-stream",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": _build_accept_language(cfg),
        "cache-control": "no-cache",
        "content-type": "application/json;charset=UTF-8",
        "cookie": cookie_value,
        "origin": "https://newassets.hcaptcha.com",
        "pragma": "no-cache",
        "referer": _hcaptcha_asset_referer(cfg),
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "user-agent": cfg.ua,
    }
    if not is_firefox_user_agent(cfg.ua):
        headers["priority"] = "u=1, i"
        headers["sec-fetch-storage-access"] = "active"
    if cfg.sec_ch_ua:
        headers["sec-ch-ua"] = cfg.sec_ch_ua
        headers["sec-ch-ua-mobile"] = "?0"
        headers["sec-ch-ua-platform"] = '"Windows"'
    return headers


def _maybe_decrypt_response(raw: bytes) -> bytes:
    if len(raw) < 28:
        return raw

    try:
        iv = raw[:12]
        tag = raw[-16:]
        ciphertext = raw[12:-16]
        cipher = _AES_GCM.new(_AES_RESP_KEY, _AES_GCM.MODE_GCM, nonce=iv)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except Exception:
        pass

    if len(raw) > 29 and raw[-1:] == b"\x00":
        try:
            iv = raw[-13:-1]
            tag = raw[-29:-13]
            ciphertext = raw[:-29]
            cipher = _AES_GCM.new(_AES_RESP_KEY, _AES_GCM.MODE_GCM, nonce=iv)
            return cipher.decrypt_and_verify(ciphertext, tag)
        except Exception:
            pass

    return raw


def parse_hcaptcha_response(response: Any) -> Dict[str, Any]:
    raw = getattr(response, "content", None)
    if raw is None:
        text = getattr(response, "text", response)
        raw = text.encode("utf-8") if isinstance(text, str) else bytes(text)

    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        pass

    decrypted = _maybe_decrypt_response(raw)
    try:
        return json.loads(decrypted)
    except Exception:
        preview = decrypted[:200] if isinstance(decrypted, (bytes, bytearray)) else str(decrypted)[:200]
        if isinstance(preview, bytes):
            preview = preview.decode("utf-8", "replace")
        return {"error": "Failed to decode response", "raw": preview}


def build_checkcaptcha_payload(
    answers: Dict[str, Any],
    c_payload: Any,
    request_type: str,
    motion_data: Any,
    cfg: Optional[SolveConfig] = None,
    n_value: Optional[str] = None,
) -> Dict[str, Any]:
    cfg = cfg or build_epic_cfg()
    motion_json = motion_data if isinstance(motion_data, str) else json.dumps(motion_data, separators=(",", ":"))
    return {
        "v": cfg.version,
        "job_mode": request_type,
        "answers": answers,
        "serverdomain": cfg.host,
        "sitekey": cfg.sitekey,
        "motionData": motion_json,
        "n": n_value or solve_and_encrypt_n(c_payload, cfg),
        "c": json.dumps(c_payload if not isinstance(c_payload, str) else json.loads(c_payload)),
    }


def submit_checkcaptcha(
    session: Any,
    ekey: str,
    answers: Dict[str, Any],
    c_payload: Any,
    request_type: str,
    motion_data: Any,
    cfg: Optional[SolveConfig] = None,
    cookies: Optional[Dict[str, Any]] = None,
    cookie_header: str = "",
    n_value: Optional[str] = None,
):
    cfg = cfg or build_epic_cfg()
    payload = build_checkcaptcha_payload(
        answers=answers,
        c_payload=c_payload,
        request_type=request_type,
        motion_data=motion_data,
        cfg=cfg,
        n_value=n_value,
    )
    cookie_value = build_cookie_header(session=session, cookies=cookies, cookie_header=cookie_header)
    headers = build_checkcaptcha_headers(cfg, cookie_value)
    response = session.post(
        f"https://api.hcaptcha.com/checkcaptcha/{cfg.sitekey}/{ekey}",
        headers=headers,
        data=json.dumps(payload, separators=(",", ":")),
    )
    return response, parse_hcaptcha_response(response), payload
