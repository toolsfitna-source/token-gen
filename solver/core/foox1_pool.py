import base64
import json
import random
from pathlib import Path
from typing import Any, Dict, List, Optional

from Crypto.Cipher import AES as _AES_GCM

_ROOT = Path(__file__).resolve().parent
_FOOX1_DIRS = (
    _ROOT.parent / "profiles" / "foox1",
)
_CACHE: Optional[List[Dict[str, Any]]] = None
_CACHE_KEY: Optional[tuple[tuple[str, int, int], ...]] = None
_LAST_TEMPLATE_NAME: Optional[str] = None
_RECENT_TEMPLATE_NAMES: List[str] = []
_AES_N_KEY = bytes.fromhex("30ae898a867d2d05149ce95e85c0372ac4c59bed6c2ca8e859988a2c153cc596")
_EPIC_HINTS = (
    "epicgames.com",
    "unrealengine.com",
    "tracking.epicgames.com",
    "talon-service-prod.ecosec.on.epicgames.com",
    "talon-website-prod.ecosec.on.epicgames.com",
)


def _build_event_map(events: Any) -> Dict[int, Any]:
    event_map: Dict[int, Any] = {}
    if not isinstance(events, list):
        return event_map

    for row in events:
        if not isinstance(row, list) or len(row) < 2:
            continue
        try:
            event_id = int(row[0])
        except Exception:
            continue
        event_map[event_id] = row[1]

    return event_map


def _parse_event_value(raw: Any) -> Any:
    if not isinstance(raw, str):
        return raw
    text = raw.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        if value in (None, ""):
            return default
        return int(float(value))
    except Exception:
        return default


def _coerce_float(value: Any, default: float = 0.0) -> float:
    try:
        if value in (None, ""):
            return default
        return float(value)
    except Exception:
        return default


def _extract_timezone_name(event_map: Dict[int, Any]) -> str:
    timezone_event = _parse_event_value(event_map.get(3486023461))
    if isinstance(timezone_event, list) and timezone_event:
        return str(timezone_event[0] or "")
    timezone_name = _parse_event_value(event_map.get(1181016567))
    return str(timezone_name or "") if isinstance(timezone_name, str) else ""


def _detect_browser(user_agent: str) -> str:
    text = str(user_agent or "")
    if "Firefox/" in text:
        return "firefox"
    if "Edg/" in text:
        return "edge"
    if "Chrome/" in text or "Chromium/" in text:
        return "chrome"
    return "unknown"


def _epic_cluster(language: str, timezone_name: str) -> str:
    lang = (language or "").strip()
    timezone_name = (timezone_name or "").strip()
    if lang == "pt-BR" and timezone_name == "America/Sao_Paulo":
        return "ptbr_saopaulo"
    if lang in {"en-US", "en"} and timezone_name.startswith("America/"):
        return "enus_america"
    if lang in {"en-US", "en-GB", "pt-BR", "es-ES", "fr-FR", "de-DE"} and timezone_name.startswith("Europe/"):
        return "europe_desktop"
    return "fallback"


def _template_quality_score(parsed: Dict[str, Any], event_map: Dict[int, Any]) -> int:
    score = 0
    components = parsed.get("components", {}) if isinstance(parsed.get("components"), dict) else {}
    navigator = components.get("navigator", {}) if isinstance(components.get("navigator"), dict) else {}
    screen = components.get("screen", {}) if isinstance(components.get("screen"), dict) else {}

    user_agent = str(navigator.get("user_agent") or "")
    language = str(navigator.get("language") or "")
    width = _coerce_int(screen.get("width"))
    height = _coerce_int(screen.get("height"))
    dpr = _coerce_float(components.get("device_pixel_ratio"), 1.0)
    max_touch_points = _coerce_int(navigator.get("max_touch_points"))
    timezone_name = _extract_timezone_name(event_map)
    cluster = _epic_cluster(language, timezone_name)

    navigator_event = _parse_event_value(event_map.get(504458258))
    device_memory = 0
    hardware_concurrency = 0
    if isinstance(navigator_event, list):
        if len(navigator_event) > 2:
            try:
                device_memory = int(float(navigator_event[2]))
            except Exception:
                device_memory = 0
        if len(navigator_event) > 3:
            try:
                hardware_concurrency = int(float(navigator_event[3]))
            except Exception:
                hardware_concurrency = 0

    gpu_event = _parse_event_value(event_map.get(1866465638))
    gpu_vendor = ""
    gpu_renderer = ""
    if isinstance(gpu_event, list) and len(gpu_event) >= 2:
        gpu_vendor = str(gpu_event[0] or "")
        gpu_renderer = str(gpu_event[1] or "")

    browser = _detect_browser(user_agent)

    if browser == "firefox":
        score += 10
    elif browser in {"chrome", "edge"}:
        score += 8
    if any(tag in language for tag in ("en-US", "en-GB", "pt-BR", "es-ES")):
        score += 5
    elif language.startswith("en"):
        score += 4

    if cluster == "ptbr_saopaulo":
        score += 16
    elif cluster == "enus_america":
        score += 12
    elif cluster == "europe_desktop":
        score += 8
    elif timezone_name.startswith("Asia/"):
        score -= 14
    elif timezone_name.startswith("Africa/"):
        score -= 8
    elif timezone_name in {"UTC", ""}:
        score -= 6

    if width >= 1920 and height >= 1080:
        score += 6
    elif width >= 1366 and height >= 768:
        score += 4
    elif width >= 1280 and height >= 720:
        score += 2
    else:
        score -= 8

    if 0.99 <= dpr <= 1.5:
        score += 2
    elif dpr > 2.0 or dpr < 0.9:
        score -= 3

    if device_memory >= 8:
        score += 5
    elif device_memory >= 4:
        score += 2
    elif device_memory and device_memory < 4:
        score -= 5

    if hardware_concurrency >= 12:
        score += 5
    elif hardware_concurrency >= 8:
        score += 4
    elif hardware_concurrency >= 6:
        score += 1
    elif hardware_concurrency and hardware_concurrency < 6:
        score -= 6

    if max_touch_points == 0:
        score += 2
    elif max_touch_points > 10:
        score -= 3

    renderer_text = f"{gpu_vendor} {gpu_renderer}".lower()
    if "basic render driver" in renderer_text or "swiftshader" in renderer_text or "llvmpipe" in renderer_text:
        score -= 100
    elif "microsoft" in renderer_text or "google, vulkan" in renderer_text:
        score -= 18
    elif any(vendor in renderer_text for vendor in ("nvidia", "amd", "intel")):
        score += 5

    if width and height:
        aspect_ratio = width / max(height, 1)
        if aspect_ratio < 1.2 or aspect_ratio > 2.5:
            score -= 10

    return score


def _decrypt_result_blob(result_b64: str) -> Optional[Dict[str, Any]]:
    try:
        blob = base64.b64decode(result_b64)
    except Exception:
        return None

    if len(blob) < 29 or blob[-1:] != b"\x00":
        return None

    try:
        iv = blob[-13:-1]
        tag = blob[-29:-13]
        ciphertext = blob[:-29]
        plaintext = _AES_GCM.new(_AES_N_KEY, _AES_GCM.MODE_GCM, nonce=iv).decrypt_and_verify(ciphertext, tag)
        parsed = json.loads(plaintext)
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


def _coerce_proof_payload(raw: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, dict):
        return None

    if isinstance(raw.get("proof_spec"), dict) and isinstance(raw.get("components"), dict) and isinstance(raw.get("events"), list):
        return raw

    encoded = str(raw.get("result") or raw.get("resultPreview") or "").strip()
    if not encoded:
        return None

    parsed = _decrypt_result_blob(encoded)
    if not isinstance(parsed, dict):
        return None

    navigator = parsed.get("components", {}).get("navigator", {})
    user_agent = str(raw.get("userAgent") or "").strip()
    if user_agent and isinstance(navigator, dict):
        navigator["user_agent"] = user_agent

    return parsed


def _looks_epic(parsed: Dict[str, Any], event_map: Dict[int, Any]) -> bool:
    texts = [str(parsed.get("href") or "").lower()]
    for event_id in (1075205395, 3357624742, 3427390490):
        value = event_map.get(event_id)
        if isinstance(value, str):
            texts.append(value.lower())
    haystack = " ".join(texts)
    return any(hint in haystack for hint in _EPIC_HINTS)


def _normalize_template(path: Path, raw: Any) -> Optional[Dict[str, Any]]:
    parsed = _coerce_proof_payload(raw)
    if not isinstance(parsed, dict):
        return None

    components = parsed.get("components")
    if not isinstance(components, dict):
        return None

    navigator = components.get("navigator")
    screen = components.get("screen")
    if not isinstance(navigator, dict) or not isinstance(screen, dict):
        return None

    event_map = _build_event_map(parsed.get("events"))
    if not event_map:
        return None

    source_kind = "formatted" if "proof_spec" in raw else "raw_encrypted"
    quality_score = _template_quality_score(parsed, event_map)
    timezone_name = _extract_timezone_name(event_map)
    language = str(navigator.get("language") or "")
    user_agent = str(navigator.get("user_agent") or "")
    return {
        "name": path.name,
        "path": str(path),
        "directory": path.parent.name,
        "browser": _detect_browser(user_agent),
        "language": language,
        "timezone": timezone_name,
        "epic_cluster": _epic_cluster(language, timezone_name),
        "data": parsed,
        "components": components,
        "event_map": event_map,
        "source_kind": source_kind,
        "epic_compatible": source_kind == "formatted" or _looks_epic(parsed, event_map),
        "epic_preferred": quality_score >= 12,
        "quality_score": quality_score,
    }


def _iter_template_paths() -> List[Path]:
    paths: List[Path] = []
    seen: set[str] = set()
    for directory in _FOOX1_DIRS:
        if not directory.exists():
            continue
        for path in sorted(directory.glob("*.json")):
            resolved = str(path.resolve())
            if resolved in seen:
                continue
            seen.add(resolved)
            paths.append(path)
    return paths


def _build_cache_key(paths: List[Path]) -> tuple[tuple[str, int, int], ...]:
    key_parts: List[tuple[str, int, int]] = []
    for path in paths:
        try:
            stat = path.stat()
        except Exception:
            continue
        key_parts.append((str(path.resolve()), int(stat.st_mtime_ns), int(stat.st_size)))
    return tuple(key_parts)


def load_foox1_templates() -> List[Dict[str, Any]]:
    global _CACHE, _CACHE_KEY
    paths = _iter_template_paths()
    cache_key = _build_cache_key(paths)
    if _CACHE is not None and _CACHE_KEY == cache_key:
        return _CACHE

    templates: List[Dict[str, Any]] = []
    for path in paths:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        template = _normalize_template(path, raw)
        if template is not None:
            templates.append(template)

    _CACHE = templates
    _CACHE_KEY = cache_key
    return templates


def get_foox1_pool_stats() -> Dict[str, int]:
    templates = load_foox1_templates()
    epic_count = sum(1 for template in templates if bool(template.get("epic_compatible")))
    preferred_count = sum(1 for template in templates if bool(template.get("epic_preferred")))
    formatted_count = sum(1 for template in templates if str(template.get("source_kind")) == "formatted")
    raw_count = sum(1 for template in templates if str(template.get("source_kind")) == "raw_encrypted")
    primary_count = sum(1 for template in templates if str(template.get("directory")) == "foox1")
    return {
        "total": len(templates),
        "foox1": primary_count,
        "epic_compatible": epic_count,
        "epic_preferred": preferred_count,
        "formatted": formatted_count,
        "raw_encrypted": raw_count,
    }


def pick_foox1_template(
    epic_only: bool = True,
    preferred_directory: str = "foox1",
    preferred_browser: str = "",
    preferred_cluster: str = "",
) -> Optional[Dict[str, Any]]:
    global _LAST_TEMPLATE_NAME, _RECENT_TEMPLATE_NAMES

    templates = load_foox1_templates()
    if not templates:
        return None

    active_templates = templates
    if epic_only:
        epic_templates = [template for template in templates if bool(template.get("epic_compatible"))]
        if epic_templates:
            active_templates = epic_templates

    if preferred_directory:
        preferred_templates = [
            template for template in active_templates if str(template.get("directory") or "") == preferred_directory
        ]
        if preferred_templates:
            active_templates = preferred_templates

    normalized_browser = str(preferred_browser or "").strip().lower()
    if normalized_browser:
        browser_templates = [
            template for template in active_templates if str(template.get("browser") or "").strip().lower() == normalized_browser
        ]
        if browser_templates:
            active_templates = browser_templates

    preferred_quality = [template for template in active_templates if bool(template.get("epic_preferred"))]
    if preferred_quality:
        active_templates = preferred_quality

    cluster_order = []
    normalized_cluster = str(preferred_cluster or "").strip()
    if normalized_cluster:
        cluster_order.append(normalized_cluster)
    for fallback_cluster in ("ptbr_saopaulo", "enus_america", "europe_desktop"):
        if fallback_cluster not in cluster_order:
            cluster_order.append(fallback_cluster)

    for cluster_name in cluster_order:
        cluster_templates = [
            template for template in active_templates if str(template.get("epic_cluster") or "") == cluster_name
        ]
        if cluster_templates:
            active_templates = cluster_templates
            break

    best_score = max(int(template.get("quality_score", 0) or 0) for template in active_templates)
    score_floor = max(best_score - 4, 12)
    top_band = [
        template
        for template in active_templates
        if int(template.get("quality_score", 0) or 0) >= score_floor
    ]
    if top_band:
        active_templates = top_band

    if len(active_templates) == 1:
        _LAST_TEMPLATE_NAME = str(active_templates[0].get("name") or "")
        _RECENT_TEMPLATE_NAMES = [_LAST_TEMPLATE_NAME]
        return active_templates[0]

    choices = [
        template
        for template in active_templates
        if str(template.get("name") or "") not in _RECENT_TEMPLATE_NAMES
    ]
    if not choices:
        choices = [
            template
            for template in active_templates
            if str(template.get("name") or "") != _LAST_TEMPLATE_NAME
        ]
    selected = random.choice(choices or active_templates)
    selected_name = str(selected.get("name") or "")
    _LAST_TEMPLATE_NAME = selected_name
    _RECENT_TEMPLATE_NAMES.append(selected_name)
    _RECENT_TEMPLATE_NAMES = _RECENT_TEMPLATE_NAMES[-6:]
    return selected
