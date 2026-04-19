"""
Phone motionData replay.

Loads a captured phone motionData template (from a real hCaptcha session that
silent-passed) and refreshes only the time-dependent fields so hCaptcha sees a
current-timestamped payload that is otherwise identical to what the phone sent.

Background:
    motionData is a separate form field on getcaptcha / checkcaptcha POSTs. It
    carries screen/navigator snapshots plus timing + vmdata. Our brux-generated
    motionData was algorithmic and hCaptcha scored it poorly. The captured phone
    template already passed silent, so replaying it with fresh timestamps + new
    widget IDs keeps the fingerprint signal strong while staying not-obviously-
    stale.

Notes:
    - `vmdata` ends with a base64 signature blob. The signature seems to cover
      the serialized `150/161/162/...` dict that precedes it. We refresh the
      `150` timestamp inside vmdata so timestamps are consistent, but we do NOT
      recompute the signature — observed success suggests hCaptcha doesn't
      strictly re-verify it (or the sig covers only static fields). If this
      breaks we fall back to brux motion.
    - widgetId is picked per call (must match the wid used in form / ekeys).
"""
import json
import random
import re
import string
import time
from pathlib import Path
from typing import Optional

_TEMPLATES_DIR = Path(__file__).resolve().parent / "profiles" / "motion_templates"
_CACHE: dict = {}


def _load_template(name: str) -> Optional[dict]:
    if name in _CACHE:
        return _CACHE[name]
    p = _TEMPLATES_DIR / name
    if not p.is_file():
        _CACHE[name] = None
        return None
    try:
        tmpl = json.loads(p.read_text(encoding="utf-8"))
        _CACHE[name] = tmpl
        return tmpl
    except Exception:
        _CACHE[name] = None
        return None


def _deep_copy(obj):
    return json.loads(json.dumps(obj))


def _refresh_vmdata_timestamp(vmdata: str, new_ts: int) -> str:
    """vmdata is a double-encoded JSON string like [[0,"[{\\"150\\":TS,...}"]].
    Replace the first occurrence of the "150":<int> timestamp with new_ts."""
    return re.sub(r'\\"150\\":\d+', f'\\\\"150\\\\":{new_ts}', vmdata, count=1)


def _apply_device_to_motion(motion: dict, device: dict) -> None:
    """Rewrite motion's navigator/screen blocks so they match the picked pool
    device. vmdata's embedded 162 screen dict is also updated. Signature at
    the tail is left as-is (observed: hCaptcha still accepts — the signature
    likely covers static trace fields, not live nav/screen snapshots)."""
    top = motion.get("topLevel")
    if not isinstance(top, dict):
        return

    # Navigator block
    nv = top.get("nv")
    if isinstance(nv, dict):
        if device.get("ua"):
            nv["userAgent"] = device["ua"]
            # appVersion is UA without the "Mozilla/5.0 " prefix
            nv["appVersion"] = device["ua"].replace("Mozilla/5.0 ", "", 1)
        if device.get("platform"):
            nv["platform"] = device["platform"]
        if device.get("max_touch_points") is not None:
            nv["maxTouchPoints"] = device["max_touch_points"]
        if device.get("hardware_concurrency") is not None:
            nv["hardwareConcurrency"] = device["hardware_concurrency"]

    # Screen block
    dev_scr = device.get("screen") or {}
    top_scr = top.get("sc")
    if isinstance(top_scr, dict) and dev_scr:
        for k_dev, k_mot in (("width", "width"), ("height", "height"),
                             ("avail_width", "availWidth"),
                             ("avail_height", "availHeight"),
                             ("color_depth", "colorDepth"),
                             ("pixel_depth", "pixelDepth")):
            v = dev_scr.get(k_dev)
            if v is not None:
                top_scr[k_mot] = v

    # "wi" is [innerWidth, innerHeight] — usually screen minus 1px each
    if dev_scr.get("width") and dev_scr.get("height"):
        top["wi"] = [dev_scr["width"] - 1, dev_scr["height"] - 1]

    # "wn" carries [w, h, dpr, ts] rows; patch width/height/dpr
    wn = top.get("wn")
    if isinstance(wn, list):
        for row in wn:
            if isinstance(row, list) and len(row) >= 3:
                if dev_scr.get("width"):
                    row[0] = dev_scr["width"] - 1
                if dev_scr.get("height"):
                    row[1] = dev_scr["height"] - 1
                if device.get("device_pixel_ratio"):
                    row[2] = device["device_pixel_ratio"]

    # vmdata: update the escaped 162 screen dict so it stays consistent
    vmd = motion.get("vmdata")
    if isinstance(vmd, str) and dev_scr:
        aw = dev_scr.get("avail_width", dev_scr.get("width"))
        ah = dev_scr.get("avail_height", dev_scr.get("height"))
        w = dev_scr.get("width")
        h = dev_scr.get("height")
        cd = dev_scr.get("color_depth", 24)
        pd = dev_scr.get("pixel_depth", 24)
        if all(v is not None for v in (aw, ah, w, h)):
            new_162 = (f'\\\\"162\\\\":{{\\\\"availWidth\\\\":{aw},\\\\"availHeight\\\\":{ah},'
                       f'\\\\"width\\\\":{w},\\\\"height\\\\":{h},\\\\"colorDepth\\\\":{cd},'
                       f'\\\\"pixelDepth\\\\":{pd},\\\\"availLeft\\\\":0,\\\\"availTop\\\\":0}}')
            motion["vmdata"] = re.sub(
                r'\\"162\\":\{[^}]+\}', new_162, vmd, count=1,
            )


def _random_widget_id() -> str:
    chars = string.digits + string.ascii_lowercase
    return "".join(random.choices(chars, k=12))


def build_getcaptcha_motion(variant: str = "fail", widget_id: Optional[str] = None,
                            href: Optional[str] = None,
                            device: Optional[dict] = None) -> Optional[dict]:
    """Build a fresh motionData for a getcaptcha POST.

    variant: "fail" for the first getcaptcha (n=fail) or "solved" for the second
             (n=solved PoW).
    widget_id: reuse across both getcaptcha calls and checkcaptcha.
    device: optional overlay from phone_profile.pick_mobile_device() so the
            motion's embedded UA/platform/screen match the profile the solver
            is using this round. Without overlay, motion stays as captured.
    """
    tmpl_name = "motion_getcaptcha_fail.json" if variant == "fail" else "motion_getcaptcha_solved.json"
    tmpl = _load_template(tmpl_name)
    if not tmpl:
        return None

    motion = _deep_copy(tmpl)
    now_ms = int(time.time() * 1000)

    # Outer timestamp + topLevel timestamp (phone's delta was ~250ms between them)
    orig_outer = motion.get("st", 0)
    orig_top = motion.get("topLevel", {}).get("st", 0)
    delta_inner = orig_top - orig_outer if (orig_outer and orig_top) else -242

    motion["st"] = now_ms
    if isinstance(motion.get("topLevel"), dict):
        motion["topLevel"]["st"] = now_ms + delta_inner
        # wn/xy arrays carry per-event timestamps
        for arr_key in ("wn", "xy"):
            arr = motion["topLevel"].get(arr_key)
            if isinstance(arr, list):
                for row in arr:
                    if isinstance(row, list) and len(row) >= 4 and isinstance(row[-1], (int, float)):
                        row[-1] = now_ms + delta_inner

    # Widget id (reused across paired getcaptcha calls)
    wid = widget_id or _random_widget_id()
    motion["widgetId"] = wid
    motion["widgetList"] = [wid]

    # Optional: override href if caller has a specific one
    if href:
        motion["href"] = href

    # Refresh embedded timestamp in vmdata (keeps outer/inner consistent)
    vmd = motion.get("vmdata")
    if isinstance(vmd, str):
        motion["vmdata"] = _refresh_vmdata_timestamp(vmd, now_ms + delta_inner)

    # Apply device overlay last so UA/screen match the profile the solver uses
    if isinstance(device, dict):
        _apply_device_to_motion(motion, device)

    return motion


def build_getcaptcha_fail_motion(widget_id: Optional[str] = None, href: Optional[str] = None,
                                 device: Optional[dict] = None) -> Optional[dict]:
    return build_getcaptcha_motion("fail", widget_id, href, device)


def build_getcaptcha_solved_motion(widget_id: Optional[str] = None, href: Optional[str] = None,
                                   device: Optional[dict] = None) -> Optional[dict]:
    return build_getcaptcha_motion("solved", widget_id, href, device)


def template_available() -> bool:
    return (_TEMPLATES_DIR / "motion_getcaptcha_fail.json").is_file()
