"""
motion.py — Desktop mouse motion data for hCaptcha silent pass.

Generates realistic interaction patterns matching a Windows 10 + Edge 145
browser on epicgames.com login page:

  - Composite cubic Bézier curves with minimum-jerk velocity profile
  - ~16ms frame intervals (requestAnimationFrame aligned at 60fps)
  - Micro-tremor simulating natural hand instability
  - Goal-directed interaction: move → click → type → scroll
  - Consistent fingerprint pulled from SolveConfig
  - vmdata with deterministic CRC32 hash objects
"""

import base64
import hashlib
import json
import math
import os
import random
import string
import time
import zlib
from typing import List, Optional, Tuple
from urllib.parse import parse_qs, urlsplit

from .config import SolveConfig
from .hsj import random_widget_id


GENERATED_M_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "generated_m")


# ─── PERSISTENCE ────────────────────────────────────────────────


def save_motion(motion_dict: dict, prefix: str = "") -> str:
    """Save motion data JSON to generated_m/<random_id>.txt."""
    os.makedirs(GENERATED_M_DIR, exist_ok=True)
    chars = string.ascii_lowercase + string.digits
    file_id = "".join(random.choices(chars, k=14))
    filepath = os.path.join(GENERATED_M_DIR, f"{prefix}{file_id}.txt")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(json.dumps(motion_dict, separators=(",", ":"), ensure_ascii=False))
    return filepath


# ─── MATH HELPERS ───────────────────────────────────────────────


def _mean_period(pts: list) -> float:
    """Mean inter-event period for [x, y, t] arrays."""
    if len(pts) <= 1:
        return 0
    return (pts[-1][-1] - pts[0][-1]) / (len(pts) - 1)


# ── Browser time-buffer simulation ──────────────────────────────
# The real hCaptcha JS uses a circular buffer (class tt) with:
#   minPeriod=16ms, maxAge=15000ms, maxEventsPerWindow=256 (pm/mm) or 128 (md/mu/etc).
# getData() cleans stale events and returns only the most recent ones.

_MAX_AGE = 15000          # ms — events older than this are discarded
_MAX_EVENTS_LARGE = 256   # pm, mm
_MAX_EVENTS_SMALL = 128   # md, mu, kd, ku, wn, xy


def _apply_buffer_limits(events: dict, now_ts: int) -> dict:
    """Simulate the browser time-buffer cleanup on all event arrays.

    - Remove events older than now_ts - _MAX_AGE (15 seconds).
    - Cap pm/mm to 256 entries, others to 128 (keep most recent).
    - Mean period reflects ALL events (matching the browser's incremental average).
    """
    cutoff = now_ts - _MAX_AGE
    out = {}

    for key in ("pm", "mm", "md", "mu", "kd", "ku", "scroll"):
        arr = events.get(key, [])
        if not arr:
            out[key] = arr
            continue

        # Determine timestamp index (last element of each entry)
        # Format: pm/mm=[x,y,t], md/mu=[x,y,t], kd/ku=[code,t], scroll=[dx,dy,t]

        # 1. Remove events older than maxAge
        filtered = [e for e in arr if e[-1] >= cutoff]

        # 2. Cap to maxEventsPerWindow (keep most recent)
        cap = _MAX_EVENTS_LARGE if key in ("pm", "mm") else _MAX_EVENTS_SMALL
        if len(filtered) > cap:
            filtered = filtered[-cap:]

        out[key] = filtered

    return out


def _clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


def _motion_seed_material(cfg: SolveConfig) -> str:
    screen = getattr(cfg, "screen", None)
    return "|".join(
        [
            str(getattr(cfg, "ua", "")),
            str(getattr(cfg, "host", "")),
            str(getattr(cfg, "href", "")),
            str(getattr(cfg, "gpu_vendor", "")),
            str(getattr(cfg, "renderer", "")),
            str(getattr(cfg, "lang", "")),
            str(getattr(screen, "width", "")),
            str(getattr(screen, "height", "")),
            str(getattr(cfg, "device_pixel_ratio", "")),
        ]
    )


def _motion_theme(cfg: SolveConfig) -> int:
    digest = hashlib.sha256((_motion_seed_material(cfg) + "|theme").encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big") & 0x7FFFFFFF


def _motion_hash_objects(cfg: SolveConfig) -> dict:
    digest = hashlib.sha256((_motion_seed_material(cfg) + "|hash-objects").encode("utf-8")).digest()

    def _u32(offset: int) -> int:
        return int.from_bytes(digest[offset:offset + 4], "big")

    return {
        "0": [0, [_u32(0), _u32(4), _u32(8), _u32(12), None, None], [], 0, 0, 0, 0],
        "1": [1, [_u32(16), _u32(20), _u32(24), None, None, None], [], 0, 0, 0, 0],
        "2": [1, [_u32(4), _u32(12), _u32(28), None, None, None], [], 0, 0, 0, 0],
    }


def _motion_hash_b64(cfg: SolveConfig) -> str:
    raw = hashlib.sha256((_motion_seed_material(cfg) + "|hash-b64").encode("utf-8")).digest()
    return base64.b64encode(raw + raw[:12]).decode("ascii").rstrip("=")


# ─── MINIMUM JERK TRAJECTORY ───────────────────────────────────


def _minimum_jerk(t: float) -> float:
    """Minimum-jerk trajectory: 10t³ − 15t⁴ + 6t⁵.

    Models natural human point-to-point reaching movement.
    Starts and ends at zero velocity/acceleration — the optimal
    smoothness profile for biological motor control (Flash & Hogan 1985).
    """
    return 10 * t**3 - 15 * t**4 + 6 * t**5


# ─── CUBIC BÉZIER ──────────────────────────────────────────────


def _cubic_bezier(
    p0: Tuple[float, float],
    p1: Tuple[float, float],
    p2: Tuple[float, float],
    p3: Tuple[float, float],
    t: float,
) -> Tuple[float, float]:
    """Evaluate cubic Bézier curve at parameter t ∈ [0, 1]."""
    u = 1.0 - t
    x = u*u*u*p0[0] + 3*u*u*t*p1[0] + 3*u*t*t*p2[0] + t*t*t*p3[0]
    y = u*u*u*p0[1] + 3*u*u*t*p1[1] + 3*u*t*t*p2[1] + t*t*t*p3[1]
    return (x, y)


def _generate_bezier_path(
    start: Tuple[int, int],
    end: Tuple[int, int],
    curvature: float = 0.10,
) -> List[Tuple[float, float]]:
    """Generate smooth Bézier path with minimum-jerk parameterization.

    Returns raw float (x, y) coordinates before timing/jitter.
    Point density adapts to distance (~1 sample per 8 px).
    Curvature is subtle and consistent (single-arc, no S-curves).
    """
    dx = end[0] - start[0]
    dy = end[1] - start[1]
    dist = math.hypot(dx, dy)

    # Denser sampling: ~1 point per 8px, clamped [10, 60]
    n = max(10, min(60, int(dist / 8)))

    # Perpendicular direction for curvature offset
    if dist > 1:
        perp_x = -dy / dist
        perp_y = dx / dist
    else:
        perp_x, perp_y = 0.0, 1.0

    # Subtle curvature — single consistent arc direction
    offset = dist * curvature * random.uniform(-1, 1)

    # Both control points offset in the same direction to avoid S-curves
    cp1 = (
        start[0] + dx * 0.33 + perp_x * offset,
        start[1] + dy * 0.33 + perp_y * offset,
    )
    cp2 = (
        start[0] + dx * 0.67 + perp_x * offset * 0.6,
        start[1] + dy * 0.67 + perp_y * offset * 0.6,
    )

    points: List[Tuple[float, float]] = []
    for i in range(n):
        t_linear = i / max(1, n - 1)
        t_jerk = _minimum_jerk(t_linear)
        pt = _cubic_bezier(start, cp1, cp2, end, t_jerk)
        points.append(pt)

    return points


# ─── MICRO-TREMOR ──────────────────────────────────────────────


def _add_tremor(x: float, y: float, speed: float = 0.0) -> Tuple[int, int]:
    """Add micro-tremor inversely proportional to speed.

    At low speeds the hand shakes more (σ ≈ 0.6-1.0 px).
    At high speeds the tremor is masked (σ ≈ 0.1-0.3 px).
    """
    sigma = 0.3 + 0.7 * max(0.0, 1.0 - speed / 600.0)
    jx = random.gauss(0, sigma)
    jy = random.gauss(0, sigma)
    return (max(0, int(round(x + jx))), max(0, int(round(y + jy))))


# ─── SINGLE STROKE (cursor → target) ───────────────────────────


def _generate_stroke(
    start: Tuple[int, int],
    end: Tuple[int, int],
    t_start: int,
    frame_ms: float = 16.0,
) -> List[List[int]]:
    """Generate one mouse movement stroke as [x, y, timestamp] events.

    Matches real browser rAF cadence (~11-18ms per frame).
    NO tremor during active movement — coordinates are clean integer
    positions along a smooth Bézier curve (matching real captures).
    Bell-shaped speed profile: slow → fast → slow.
    """
    dist = math.hypot(end[0] - start[0], end[1] - start[1])

    raw = _generate_bezier_path(start, end)

    events: List[List[int]] = []
    t = t_start
    prev_ix, prev_iy = -1, -1

    for i, (rx, ry) in enumerate(raw):
        # Clean integer rounding — no tremor during active strokes
        x = max(0, int(round(rx)))
        y = max(0, int(round(ry)))

        # Skip duplicate coordinates (from minimum-jerk bunching near endpoints)
        if x == prev_ix and y == prev_iy:
            continue

        if prev_ix >= 0:
            progress = i / len(raw)
            # Bell-shaped: intervals ~18ms at start/end, ~11ms in the middle
            speed_mul = 0.7 + 0.6 * math.sin(progress * math.pi)
            interval = frame_ms / speed_mul
            interval = _clamp(interval, 10, 20)
            t += int(interval)

        prev_ix, prev_iy = x, y
        events.append([x, y, t])

    return events


# ─── LOGIN-PAGE INTERACTION TARGETS ─────────────────────────────


def _generate_idle_jitter(
    cursor: Tuple[int, int],
    t_start: int,
    duration_ms: int,
) -> List[List[int]]:
    """Generate small idle cursor jitter during pauses.

    Matches real captures: ±1px gaussian, sparse 100-500ms intervals.
    The cursor barely moves while resting — just subtle hand tremor.
    """
    events: List[List[int]] = []
    t = t_start
    while t < t_start + duration_ms:
        t += random.randint(100, 500)
        if t >= t_start + duration_ms:
            break
        jx = cursor[0] + random.choice([-1, 0, 0, 0, 1])
        jy = cursor[1] + random.choice([-1, 0, 0, 0, 1])
        events.append([max(0, jx), max(0, jy), t])
    return events


def _generate_drift(
    cursor: Tuple[int, int],
    t_start: int,
    duration_ms: int,
    vw: int,
    vh: int,
) -> Tuple[List[List[int]], Tuple[int, int]]:
    """Generate continuous slow cursor drift during pauses.

    Real users don't hold the mouse perfectly still — they slowly drift
    and explore nearby UI elements while thinking/reading. This produces
    continuous pm events at ~15ms intervals even during "pauses".

    Returns (events_list, final_cursor_position).
    """
    events: List[List[int]] = []
    t = t_start
    cx, cy = float(cursor[0]), float(cursor[1])

    # Pick a slow drift direction (small random target nearby)
    drift_x = random.uniform(-80, 80)
    drift_y = random.uniform(-40, 40)
    speed = random.uniform(0.3, 1.2)  # pixels per frame (~15ms)

    while t < t_start + duration_ms:
        interval = random.randint(6, 16)  # ~11ms mean — produces pm-mp ≈ 15ms
        t += interval
        if t >= t_start + duration_ms:
            break

        # Slow drift with occasional direction changes
        if random.random() < 0.02:
            drift_x = random.uniform(-60, 60)
            drift_y = random.uniform(-30, 30)
            speed = random.uniform(0.2, 0.8)

        cx += drift_x * speed / max(abs(drift_x), abs(drift_y), 1) * random.uniform(0.5, 1.5)
        cy += drift_y * speed / max(abs(drift_x), abs(drift_y), 1) * random.uniform(0.5, 1.5)

        # Keep within viewport bounds
        cx = max(10, min(vw - 10, cx))
        cy = max(10, min(vh - 10, cy))

        ix = int(round(cx))
        iy = int(round(cy))

        # Skip if same coordinate as last event (avoid duplicates)
        if events and events[-1][0] == ix and events[-1][1] == iy:
            continue

        events.append([ix, iy, t])

    final = (int(round(cx)), int(round(cy)))
    return events, final


def _login_targets(vw: int, vh: int) -> List[dict]:
    """Interaction targets for login page (universal layout).

    Generates a realistic sequence: explore, scroll, type email,
    type password, hover UI, click login — with enough targets
    to produce ~130-250 mouse events.

    Coordinates are relative to the viewport (inner window).
    """
    cx = vw // 2
    sy = vh / 900.0  # baseline viewport height ~900px
    h_spread = min(vw // 4, 300)
    h_narrow = min(vw // 6, 120)

    targets = [
        # 1. Initial page exploration — move to header/logo area
        {
            "pos": (cx + random.randint(-h_spread, h_spread),
                    int(150 * sy) + random.randint(-20, 20)),
            "action": "hover",
            "pause": (300, 800),
        },
        # 2. Look at social login buttons area
        {
            "pos": (cx + random.randint(-h_narrow, h_narrow),
                    int(650 * sy) + random.randint(-30, 30)),
            "action": "click",
            "pause": (200, 600),
        },
        # 3. Scroll up to see the form
        {
            "pos": None,
            "action": "scroll",
            "pause": (200, 500),
        },
        # 4. Hover over email field area (reading label)
        {
            "pos": (cx + random.randint(-100, -30),
                    int(360 * sy) + random.randint(-10, 10)),
            "action": "hover",
            "pause": (150, 400),
        },
        # 5. Click email field
        {
            "pos": (cx + random.randint(-50, 50),
                    int(380 * sy) + random.randint(-8, 8)),
            "action": "click",
            "pause": (60, 200),
            "type_keys": random.randint(10, 16),
        },
        # 6. Click password field
        {
            "pos": (cx + random.randint(-50, 50),
                    int(460 * sy) + random.randint(-8, 8)),
            "action": "click",
            "pause": (60, 200),
            "type_keys": random.randint(8, 14),
        },
        # 7. Hover near "forgot password" link
        {
            "pos": (cx + random.randint(-h_narrow, h_narrow),
                    int(505 * sy) + random.randint(-10, 10)),
            "action": "click",
            "pause": (200, 700),
        },
        # 8. Scroll slightly
        {
            "pos": None,
            "action": "scroll",
            "pause": (150, 400),
        },
        # 9. Move back toward login button area
        {
            "pos": (cx + random.randint(-80, 80),
                    int(540 * sy) + random.randint(-10, 10)),
            "action": "hover",
            "pause": (4000, 9000),
        },
        # 10. Click login button (triggers hCaptcha)
        {
            "pos": (cx + random.randint(-30, 30),
                    int(560 * sy) + random.randint(-6, 6)),
            "action": "click",
            "pause": (30, 150),
            "login_click": True,
        },
    ]
    return targets


# ─── FULL INTERACTION GENERATION ────────────────────────────────


def _generate_simple_mouse(top_st: int, inner_w: int, inner_h: int) -> dict:
    """Generate compact but natural challenge pointer activity.

    Just a few straight-line movements with no Bézier, no tremor, no typing.
    Silent pass depends on motion being present but not realistic.
    """
    pm: List[List[int]] = []
    mm: List[List[int]] = []
    md: List[List[int]] = []
    mu: List[List[int]] = []

    cx = inner_w // 2
    cy = inner_h // 2
    cursor = (
        cx + random.randint(-inner_w // 6, inner_w // 6),
        cy + random.randint(-inner_h // 7, inner_h // 7),
    )
    t = top_st + random.randint(900, 1800)

    targets: List[Tuple[int, int]] = []
    for index in range(random.randint(2, 4)):
        span_x = inner_w // 5 if index < 2 else inner_w // 10
        span_y = inner_h // 6 if index < 2 else inner_h // 8
        targets.append((
            max(10, min(inner_w - 10, cx + random.randint(-span_x, span_x))),
            max(10, min(inner_h - 10, cy + random.randint(-span_y, span_y))),
        ))

    for target in targets:
        stroke = _generate_stroke(cursor, target, t, frame_ms=random.uniform(13.5, 17.5))
        if stroke:
            pm.extend(stroke)
            t = stroke[-1][2]
            cursor = (stroke[-1][0], stroke[-1][1])

        reaction_ms = random.randint(45, 160)
        drift_evts, cursor = _generate_drift(cursor, t, reaction_ms, inner_w, inner_h)
        pm.extend(drift_evts)
        if drift_evts:
            t = drift_evts[-1][2]
            cursor = (drift_evts[-1][0], drift_evts[-1][1])
        else:
            t += reaction_ms

        click_x = cursor[0] + random.randint(-2, 2)
        click_y = cursor[1] + random.randint(-2, 2)
        hold = int(_clamp(random.gauss(92, 20), 55, 160))
        md.append([click_x, click_y, t])
        mu.append([click_x, click_y, t + hold])
        t += hold

        idle_evts = _generate_idle_jitter(cursor, t, random.randint(90, 320))
        pm.extend(idle_evts)
        if idle_evts:
            t = idle_evts[-1][2]
            cursor = (idle_evts[-1][0], idle_evts[-1][1])

    for px, py, ts in pm:
        mm.append([
            max(0, min(inner_w, px + random.choice([-1, 0, 0, 1]))),
            max(0, min(inner_h, py + random.choice([-1, 0, 0, 1]))),
            ts + random.randint(-1, 1),
        ])

    mm.sort(key=lambda row: row[2])
    return {"pm": pm, "mm": mm, "md": md, "mu": mu, "kd": [], "ku": [], "scroll": []}

    # Start somewhere in the page
    x = random.randint(int(inner_w * 0.3), int(inner_w * 0.7))
    y = random.randint(int(inner_h * 0.3), int(inner_h * 0.6))
    t = top_st + random.randint(800, 2000)

    # A few simple moves (3-8 points, straight-ish, bad intervals)
    n_moves = random.randint(3, 8)
    for _ in range(n_moves):
        x += random.randint(-40, 40)
        y += random.randint(-30, 30)
        x = max(5, min(inner_w - 5, x))
        y = max(5, min(inner_h - 5, y))
        t += random.randint(20, 120)
        pm.append([x, y, t])
        mm.append([x + random.randint(-1, 1), y + random.randint(-1, 1), t + random.randint(-1, 1)])

    # One click
    t += random.randint(50, 200)
    md.append([x, y, t])
    mu.append([x, y, t + random.randint(60, 150)])

    return {"pm": pm, "mm": mm, "md": md, "mu": mu, "kd": [], "ku": [], "scroll": []}


def _event_time_bounds(events: dict) -> Tuple[int, int]:
    timestamps: List[int] = []
    for key in ("pm", "mm", "md", "mu", "kd", "ku", "scroll"):
        for row in events.get(key, []):
            if not row:
                continue
            try:
                timestamps.append(int(row[-1]))
            except Exception:
                continue
    if not timestamps:
        return 0, 0
    return min(timestamps), max(timestamps)


def _shift_events(events: dict, delta_ms: int) -> dict:
    if delta_ms == 0:
        return events
    shifted: dict = {}
    for key in ("pm", "mm", "md", "mu", "kd", "ku", "scroll"):
        rows = []
        for row in events.get(key, []):
            if not row:
                continue
            updated = list(row)
            updated[-1] = int(updated[-1]) + delta_ms
            rows.append(updated)
        shifted[key] = rows
    return shifted


def _fit_events_end(events: dict, desired_end_ts: int) -> Tuple[dict, int]:
    _start_ts, end_ts = _event_time_bounds(events)
    if not end_ts:
        return events, 0
    delta = desired_end_ts - end_ts
    return _shift_events(events, delta), delta


def _get_motion_context(cfg: SolveConfig, is_discord: bool = False) -> dict:
    profile_data = getattr(cfg, "profile_data", None)
    if not isinstance(profile_data, dict):
        profile_data = {}
        cfg.profile_data = profile_data

    if is_discord:
        return {
            "inner_w": random.randint(500, 560),
            "inner_h": random.randint(920, 960),
            "dr": "",
            "pel_html": "<div></div>",
            "theme": _motion_theme(cfg),
            "hash_objects": _motion_hash_objects(cfg),
            "hash_b64": _motion_hash_b64(cfg),
        }

    cached = profile_data.get("_motion_context")
    if isinstance(cached, dict):
        return cached

    avail_w = max(640, int(getattr(cfg.screen, "avail_width", 0) or getattr(cfg.screen, "width", 1280)))
    avail_h = max(480, int(getattr(cfg.screen, "avail_height", 0) or getattr(cfg.screen, "height", 720)))
    width = max(640, int(getattr(cfg.screen, "width", avail_w)))
    height = max(480, int(getattr(cfg.screen, "height", avail_h)))

    inner_w = min(width, avail_w)
    inner_h = min(height, avail_h)

    if inner_h >= height:
        inner_h = max(480, height - random.randint(28, 72))
    if inner_w < inner_h and width >= height:
        inner_w = min(width, max(inner_w, int(width * random.uniform(0.84, 0.96))))
        inner_h = min(height, max(480, int(inner_w * random.uniform(0.58, 0.72))))
    else:
        inner_w = min(width, max(inner_w, int(width * random.uniform(0.92, 1.0))))
        inner_h = min(height, max(480, int(inner_h * random.uniform(0.9, 0.98))))

    host = cfg.host or ""
    href = getattr(cfg, "href", "") or f"https://{host}/"
    redirect_url = (parse_qs(urlsplit(href).query).get("redirectUrl") or [""])[0]
    if "epicgames" in host:
        dr = redirect_url or "https://store.epicgames.com/pt-BR"
        pel_html = '<div id="h_captcha_checkbox_login_prod"></div>'
    elif "riotgames" in host:
        dr = "https://www.riotgames.com/"
        pel_html = "<div></div>"
    else:
        dr = ""
        pel_html = "<div></div>"

    context = {
        "inner_w": int(inner_w),
        "inner_h": int(inner_h),
        "dr": dr,
        "pel_html": pel_html,
        "theme": _motion_theme(cfg),
        "hash_objects": _motion_hash_objects(cfg),
        "hash_b64": _motion_hash_b64(cfg),
    }
    profile_data["_motion_context"] = context
    return context


def _generate_interaction(cfg: SolveConfig, top_st: int,
                          inner_w: int = 0, inner_h: int = 0) -> dict:
    """Generate login-page interaction events.

    Returns dict with keys: pm, mm, md, mu, scroll, kd, ku.
    Coordinates are generated within the viewport (inner_w × inner_h).
    """
    # Use viewport dims if provided, else fallback to screen
    vw = inner_w if inner_w > 0 else cfg.screen.width
    vh = inner_h if inner_h > 0 else cfg.screen.height

    is_epic = "epicgames" in (cfg.host or "")

    pm: List[List[int]] = []
    mm: List[List[int]] = []
    md: List[List[int]] = []
    mu: List[List[int]] = []
    scroll: List[List[int]] = []
    kd: List[List[int]] = []
    ku: List[List[int]] = []

    targets = _login_targets(vw, vh)

    # Starting cursor: near top-center of viewport
    h_spread = min(vw // 4, 300)
    cursor = (
        vw // 2 + random.randint(-h_spread, h_spread),
        random.randint(80, 250),
    )

    # Mouse interaction starts ~8-10s after page load (user reads the page first)
    # Real capture: first mouse event at ~9s, keyboard at ~14s, last event at ~23.6s
    t = top_st + random.randint(8000, 10000)

    for tgt in targets:
        # ── Scroll-only action (no cursor movement) ──
        if tgt["action"] == "scroll":
            n_scrolls = random.randint(2, 5)
            for _ in range(n_scrolls):
                delta = random.choice([-120, -100, -80, -60, -48, 60, 80, 100])
                t += random.randint(80, 250)
                scroll.append([0, delta, t])
            lo, hi = tgt.get("pause", (200, 600))
            pause_ms = random.randint(lo, hi)
            drift_evts, cursor = _generate_drift(cursor, t, pause_ms, vw, vh)
            for evt in drift_evts:
                pm.append(evt)
            if drift_evts:
                t = drift_evts[-1][2]
            else:
                t += pause_ms
            continue

        if tgt["pos"] is None:
            continue

        pos = tgt["pos"]

        # ── Movement stroke ──
        stroke = _generate_stroke(cursor, pos, t)
        for evt in stroke:
            pm.append(evt)

        t = stroke[-1][2]
        cursor = (stroke[-1][0], stroke[-1][1])

        # ── Click ──
        if tgt["action"] == "click":
            # Reaction delay — cursor drifts slightly before pressing
            reaction_ms = random.randint(60, 200)
            drift_evts, cursor = _generate_drift(cursor, t, reaction_ms, vw, vh)
            for evt in drift_evts:
                pm.append(evt)
            t += reaction_ms

            cx = cursor[0] + random.randint(-1, 1)
            cy = cursor[1] + random.randint(-1, 1)
            md.append([cx, cy, t])

            # Last click (login button) has longer hold time (~100-200ms)
            # Normal clicks: ~55-80ms hold
            is_login_click = tgt.get("login_click", False)
            if is_login_click:
                hold = int(_clamp(random.gauss(160, 30), 100, 210))
            else:
                hold = int(_clamp(random.gauss(72, 6), 55, 90))

            # Mouse drifts slightly during click hold
            if hold > 30:
                drift_evts, cursor = _generate_drift(cursor, t, hold, vw, vh)
                for evt in drift_evts:
                    pm.append(evt)

            mu.append([cx, cy, t + hold])
            t += hold

            # Type keys after click (e.g. email / password)
            n_keys = tgt.get("type_keys", 0)
            if n_keys > 0:
                t += random.randint(150, 400)  # focus settle time

                # During typing, the cursor drifts slowly near the input field
                # Real captures show continuous pm events even while typing
                type_duration = n_keys * random.randint(80, 130)
                drift_evts, cursor = _generate_drift(cursor, t, type_duration, vw, vh)
                for evt in drift_evts:
                    pm.append(evt)

                # Reset t to after drift, then interleave keyboard events
                type_start = t
                for ki in range(n_keys):
                    iki = int(random.lognormvariate(math.log(95), 0.35))
                    iki = int(_clamp(iki, 45, 350))
                    t = type_start + int(type_duration * ki / max(1, n_keys - 1)) + random.randint(-20, 20)
                    kd.append([0, t])
                    press = int(_clamp(random.gauss(78, 18), 35, 160))
                    ku.append([0, t + press])

                # Advance t past typing duration
                t = type_start + type_duration

        # ── Post-action pause ──
        lo, hi = tgt.get("pause", (200, 800))
        pause_ms = random.randint(lo, hi)

        # Generate continuous slow drift during all pauses > 50ms
        # Real users keep gently moving the cursor while reading/thinking
        if pause_ms > 50:
            drift_evts, cursor = _generate_drift(cursor, t, pause_ms, vw, vh)
            for evt in drift_evts:
                pm.append(evt)
            if drift_evts:
                t = drift_evts[-1][2]
            else:
                t += pause_ms
        else:
            t += pause_ms

        # ── Occasional scroll during hover pauses ──
        if tgt["action"] == "hover" and random.random() < 0.4:
            for _ in range(random.randint(1, 3)):
                delta = random.choice([-100, -80, -60, -27, -7, 8, 23, 62, 80])
                t += random.randint(60, 200)
                scroll.append([0, delta, t])

    # ── Build mm from pm ──
    # Real data: mm has SAME or MORE events than pm (not fewer).
    # pm = pointermove, mm = mousemove — both fire on mouse movement.
    # They share the same coordinates but timestamps differ by 0-2ms.
    # mm occasionally has extra interpolated events that pm doesn't.
    mm = []
    if pm:
        for evt in pm:
            # Same coords, slightly different timestamp (0-2ms offset, can be negative too)
            t_offset = random.choice([-1, 0, 0, 0, 1, 1, 1, 2])
            mm.append([evt[0], evt[1], evt[2] + t_offset])

        # mm sometimes has 1-3 extra events (interpolated between existing ones)
        n_extra = random.randint(0, 3)
        for _ in range(n_extra):
            if len(mm) < 3:
                break
            idx = random.randint(1, len(mm) - 2)
            prev_evt = mm[idx - 1]
            next_evt = mm[idx]
            # Interpolate coords and time
            mid_x = (prev_evt[0] + next_evt[0]) // 2
            mid_y = (prev_evt[1] + next_evt[1]) // 2
            mid_t = (prev_evt[2] + next_evt[2]) // 2
            if mid_t != prev_evt[2] and mid_t != next_evt[2]:
                mm.insert(idx, [mid_x, mid_y, mid_t])

        # Sort by timestamp in case insertions shuffled order
        mm.sort(key=lambda e: e[2])

    return {
        "pm": pm,
        "mm": mm,
        "md": md,
        "mu": mu,
        "scroll": scroll,
        "kd": kd,
        "ku": ku,
    }


# ─── NAVIGATOR / SCREEN OBJECTS ─────────────────────────────────


def _is_firefox(cfg: SolveConfig) -> bool:
    return "Firefox/" in cfg.ua


def _build_navigator(cfg: SolveConfig) -> dict:
    """Build navigator object matching the browser profile exactly."""
    app_version = cfg.ua
    if app_version.startswith("Mozilla/"):
        app_version = app_version[8:]

    is_firefox = _is_firefox(cfg)
    is_safari = not cfg.sec_ch_ua and not is_firefox

    if is_firefox:
        # Firefox navigator — matches real Firefox 147+ capture exactly
        nav = {
            "permissions": {},
            "pdfViewerEnabled": True,
            "doNotTrack": "unspecified",
            "maxTouchPoints": cfg.max_touch_points,
            "mediaCapabilities": {},
            "oscpu": "Windows NT 10.0; Win64; x64",
            "vendor": "",
            "vendorSub": "",
            "productSub": "20100101",
            "cookieEnabled": True,
            "buildID": "20181001000000",
            "mediaDevices": {},
            "serviceWorker": {},
            "credentials": {},
            "clipboard": {},
            "mediaSession": {},
            "userActivation": {},
            "wakeLock": {},
            "login": {},
            "globalPrivacyControl": False,
            "webdriver": False,
            "hardwareConcurrency": cfg.hardware_concurrency,
            "gpu": {},
            "geolocation": {},
            "appCodeName": "Mozilla",
            "appName": "Netscape",
            "appVersion": "5.0 (Windows)",
            "platform": cfg.platform,
            "userAgent": cfg.ua,
            "product": "Gecko",
            "language": cfg.lang,
            "languages": cfg.languages,
            "locks": {},
            "onLine": True,
            "storage": {},
            "plugins": [
                "internal-pdf-viewer",
                "internal-pdf-viewer",
                "internal-pdf-viewer",
                "internal-pdf-viewer",
                "internal-pdf-viewer",
            ],
        }
        return nav

    nav = {
        "vendorSub": "",
        "productSub": "20030107",
        "vendor": "Apple Computer, Inc." if is_safari else "Google Inc.",
        "maxTouchPoints": cfg.max_touch_points,
        "scheduling": {},
        "userActivation": {},
        "geolocation": {},
        "doNotTrack": None,
        "webkitTemporaryStorage": {},
        "hardwareConcurrency": cfg.hardware_concurrency,
        "cookieEnabled": True,
        "appCodeName": "Mozilla",
        "appName": "Netscape",
        "appVersion": app_version,
        "platform": cfg.platform,
        "product": "Gecko",
        "userAgent": cfg.ua,
        "language": cfg.lang,
        "languages": cfg.languages,
        "onLine": True,
        "webdriver": False,
        "pdfViewerEnabled": not is_safari,
        "connection": {},
        "windowControlsOverlay": {},
    }

    if is_safari:
        # Safari-specific navigator — no userAgentData, no Chrome-only props
        nav.update({
            "clipboard": {},
            "credentials": {},
            "keyboard": {},
            "mediaDevices": {},
            "serviceWorker": {},
            "wakeLock": {},
            "deviceMemory": cfg.device_memory,
            "locks": {},
            "storage": {},
            "mediaCapabilities": {},
            "mediaSession": {},
            "permissions": {},
            "plugins": [],
        })
    else:
        # Chrome-specific navigator
        nav.update({
            "deprecatedRunAdAuctionEnforcesKAnonymity": False,
            "protectedAudience": {},
            "bluetooth": {},
            "clipboard": {},
            "credentials": {},
            "keyboard": {},
            "managed": {},
            "mediaDevices": {},
            "serviceWorker": {},
            "virtualKeyboard": {},
            "wakeLock": {},
            "deviceMemory": cfg.device_memory,
            "userAgentData": {
                "brands": [
                    {"brand": "Chromium", "version": cfg.chrome_version},
                    {"brand": "Not-A.Brand", "version": "24"},
                    {"brand": "Google Chrome", "version": cfg.chrome_version},
                ],
                "mobile": False,
                "platform": "Windows",
            },
            "locks": {},
            "storage": {},
            "gpu": {},
            "login": {},
            "ink": {},
            "mediaCapabilities": {},
            "devicePosture": {},
            "hid": {},
            "mediaSession": {},
            "permissions": {},
            "presentation": {},
            "serial": {},
            "usb": {},
            "xr": {},
            "storageBuckets": {},
            "plugins": [
                "internal-pdf-viewer",
                "internal-pdf-viewer",
                "internal-pdf-viewer",
                "internal-pdf-viewer",
                "internal-pdf-viewer",
            ],
        })

    return nav


def _build_screen(cfg: SolveConfig) -> dict:
    """Build screen config matching SolveConfig exactly."""
    if _is_firefox(cfg):
        # Firefox screen has mozOrientation, no onchange/isExtended
        return {
            "availWidth": cfg.screen.avail_width,
            "availHeight": cfg.screen.avail_height,
            "width": cfg.screen.width,
            "height": cfg.screen.height,
            "colorDepth": cfg.screen.color_depth,
            "pixelDepth": cfg.screen.pixel_depth,
            "top": 0,
            "left": 0,
            "availTop": 0,
            "availLeft": 0,
            "mozOrientation": "landscape-primary",
            "onmozorientationchange": None,
        }
    return {
        "availWidth": cfg.screen.avail_width,
        "availHeight": cfg.screen.avail_height,
        "width": cfg.screen.width,
        "height": cfg.screen.height,
        "colorDepth": cfg.screen.color_depth,
        "pixelDepth": cfg.screen.pixel_depth,
        "availLeft": 0,
        "availTop": 0,
        "onchange": None,
        "isExtended": False,
    }


# ─── VMDATA ─────────────────────────────────────────────────────


def _deterministic_crc32(label: str, version: str = "d5e602eee817b1d3bdd5caf8fb57da50d442d070") -> int:
    """Generate deterministic CRC32 for vmdata hash objects.

    Same hCaptcha version → same hashes every run (no randomness).
    """
    data = f"hcaptcha-{version}-{label}".encode()
    return zlib.crc32(data) & 0xFFFFFFFF


def _build_vmdata(
    cfg: SolveConfig,
    events: dict,
    top_st: int,
    href: str,
    inner_w: int,
    inner_h: int,
    pel_html: str = "",
    theme_val: int = 0,
    dr: str = "",
    orientation: str = "landscape",
) -> str:
    """Build vmdata string matching real browser format exactly.

    Structure: [[0, inner_json_string]]
    Inner array: [toplevel_meta, 0, null, session_id, url, [], [254, secondary, hashes, base_ts, [], []], url, hash_b64]

    Event format in vmdata: [x, y, 1, 0, time_offset_from_base]
    """
    # base_ts (key "150") = topLevel.st + small delta (real: 3ms)
    base_ts = top_st + random.randint(2, 5)
    # secondary base_ts is 1ms after meta base_ts (real: base_ts + 1)
    sec_base_ts = base_ts + 1

    md_list = events["md"]
    mu_list = events["mu"]
    mm_list = events["mm"]
    kd_list = events.get("kd", [])
    ku_list = events.get("ku", [])

    mm_mp = _mean_period(mm_list)

    # ── Toplevel meta (event codes 110-174) ──
    # 110 = mousedown, 111 = mouseup, 112 = mousemove
    # Format: [x, y, 1, 0, time_offset_from_base]
    evt_110 = [[d[0], d[1], 1, 0, d[2] - base_ts] for d in md_list]
    evt_111 = [[u[0], u[1], 1, 0, u[2] - base_ts] for u in mu_list]
    evt_112 = [[m[0], m[1], 1, 0, m[2] - base_ts] for m in mm_list]

    # 120/121 = keydown/keyup events [[0, time_offset_from_base], ...]
    evt_120 = [[0, kd[1] - base_ts] for kd in kd_list] if kd_list else []
    evt_121 = [[0, ku[1] - base_ts] for ku in ku_list] if ku_list else []

    # 131: slightly different from 113 (mm-mp) — real: ~0.0001 diff (precision)
    mm_mp_131 = mm_mp - random.uniform(0.00001, 0.0001) if mm_mp > 0 else 0

    sc = _build_screen(cfg)
    hash_objects = _motion_hash_objects(cfg)
    hash_b64 = _motion_hash_b64(cfg)

    if not pel_html:
        pel_html = "<div></div>"
    theme_val = theme_val or _motion_theme(cfg)

    toplevel_meta = {
        "110": evt_110,
        "111": evt_111,
        "112": evt_112,
        "113": mm_mp,
        "120": evt_120,
        "121": evt_121,
        "130": [],
        "131": mm_mp_131,
        "150": base_ts,
        "161": orientation,
        "162": sc,
        "164": dr,
        "165": [inner_w, inner_h],
        "170": "api",
        "171": pel_html,
        "172": "invisible",
        "173": theme_val,
        "174": True,
    }

    # ── Secondary events (block 254) ──
    # Real pattern from VM reverse engineering:
    # - Event 20 mirrors keydown: offset is exactly 120_offset - 1
    # - Event 21 mirrors keyup: offset is exactly 121_offset - 1
    # - Event 30 counters are NOT sequential — they skip some values
    #   (matches real: [1,3,4,5,7,8] for 6 keydowns)
    # - Events 50-53 are focus/blur relative to mousedown offsets
    kd_offsets = [kd[1] - base_ts for kd in kd_list] if kd_list else []
    ku_offsets = [ku[1] - base_ts for ku in ku_list] if ku_list else []
    md_offsets = [d[2] - base_ts for d in md_list] if md_list else []

    # "20": [0, 0, 2, keydown_offset - 1] — exactly 1ms before 120
    evt_20 = [[0, 0, 2, off - 1] for off in kd_offsets]

    # "21": [0, 0, 2, keyup_offset - 1] — exactly 1ms before 121
    evt_21 = [[0, 0, 2, off - 1] for off in ku_offsets]

    # "30": [counter, 1, 2, keydown_offset + 0-3]
    # Real counters skip some values (e.g. 1,3,4,5,7,8 for 6 keys)
    # This is because the VM counts ALL input events including non-printable
    counter = 1
    evt_30 = []
    for i, off in enumerate(kd_offsets):
        evt_30.append([counter, 1, 2, off + random.randint(0, 3)])
        # Skip 1-2 counter values occasionally (real pattern)
        if random.random() < 0.3:
            counter += 2  # skip one
        else:
            counter += 1

    # "50"/"51"/"52"/"53": focus/blur entries with state=2
    # Real capture shows:
    #   50[time] == md[0] offset exactly (focus at first mousedown)
    #   51[time] == md[-1] offset - 1 (focus at last mousedown)
    #   52[time] == md[0] offset - 200~250 (focusin before first click)
    #   53[time] == midpoint between mousedowns
    if md_offsets:
        first_md = md_offsets[0]
        last_md = md_offsets[-1] if len(md_offsets) > 1 else first_md + random.randint(1500, 2000)
        mid_time = first_md + (last_md - first_md) // 2 + random.randint(-100, 100)
        evt_50 = [[2, first_md]]
        evt_51 = [[2, last_md - 1]]
        evt_52 = [[2, first_md - random.randint(200, 260)]]
        evt_53 = [[2, mid_time]]
    else:
        evt_50 = []
        evt_51 = []
        evt_52 = []
        evt_53 = []

    secondary = {
        "20": evt_20,
        "21": evt_21,
        "30": evt_30,
        "50": evt_50,
        "51": evt_51,
        "52": evt_52,
        "53": evt_53,
    }

    session_id = random.randint(10**15, 10**16 - 1)
    # URL truncated at exactly 150 chars (from VM: document.location.href.slice(0, 150))
    trunc_url = href[:150]

    # Inner array from VM reverse engineering (var 313, PC=34842-34881):
    # [0] = toplevel_meta dict (filled via postMessage from iframe)
    # [1] = performance.getEntriesByType("navigation")[0].duration (0 for API mode)
    # [2] = null
    # [3] = session_id (Math.random() * 10^16 as integer)
    # [4] = document.location.href.slice(0, 150)
    # [5] = [] (empty array)
    # [6] = [254, secondary_events, hash_objects, sec_base_ts, [], []]
    # [7] = window.location.href.slice(0, 150) (same as [4])
    # [8] = hash_b64 constant (VM string index 512)
    inner = [
        toplevel_meta,
        0,
        None,
        session_id,
        trunc_url,
        [],
        [254, secondary, hash_objects, sec_base_ts, [], []],
        trunc_url,
        hash_b64,
    ]

    inner_json = json.dumps(inner, separators=(",", ":"), ensure_ascii=False)
    vmdata = json.dumps([[0, inner_json]], separators=(",", ":"), ensure_ascii=False)
    return vmdata


# ─── DISCORD CHECKBOX MODE ──────────────────────────────────────


def _generate_discord_page_motion(top_st: int, inner_w: int, inner_h: int) -> dict:
    """Generate page-level mouse movement for Discord.

    Simulates the user moving toward the captcha checkbox on the register
    page. Real captures show ~20-30 pm events spanning ~1.5s.
    """
    pm: list = []
    mm: list = []

    # Mouse starts somewhere mid-page (register form area)
    cx = random.randint(int(inner_w * 0.6), int(inner_w * 0.95))
    cy = random.randint(int(inner_h * 0.7), int(inner_h * 0.85))

    t = top_st + random.randint(150, 300)
    pm.append([cx, cy, t])

    # Move around the form area briefly
    for _ in range(random.randint(12, 20)):
        dx = random.randint(-15, 15)
        dy = random.randint(-10, 10)
        cx = max(10, min(inner_w - 10, cx + dx))
        cy = max(10, min(inner_h - 10, cy + dy))
        t += random.randint(14, 20)
        pm.append([cx, cy, t])

    # Sweep toward the captcha widget area (upper-left quadrant)
    target_x = random.randint(80, 150)
    target_y = random.randint(inner_h * 60 // 100, inner_h * 75 // 100)
    sweep = _generate_stroke((cx, cy), (target_x, target_y), t)
    for evt in sweep:
        pm.append(evt)
    if sweep:
        t = sweep[-1][2]

    # Small idle near the checkbox area
    for _ in range(random.randint(2, 5)):
        last = pm[-1]
        nx = last[0] + random.choice([-1, 0, 0, 1])
        ny = last[1] + random.choice([-1, 0, 0, 1])
        t += random.randint(100, 200)
        pm.append([max(0, nx), max(0, ny), t])

    # Build mm from pm (same coords, slight time offset)
    for evt in pm:
        mm.append([evt[0], evt[1], evt[2] + random.randint(0, 2)])

    return {"pm": pm, "mm": mm}


def _generate_checkbox_events(checkbox_st: int) -> dict:
    """Generate mouse events for clicking the hCaptcha checkbox.

    The checkbox iframe is small (~300x74 area). The user moves from
    the edge toward the checkbox control at approximately (25, 40).
    Returns mm (integer coords), md, mu for the checkbox frame.
    """
    target_x = random.randint(22, 28)
    target_y = random.randint(38, 42)

    start_x = random.randint(100, 130)
    start_y = random.randint(60, 80)

    t = checkbox_st + random.randint(800, 1200)
    stroke = _generate_stroke((start_x, start_y), (target_x, target_y), t)

    mm = [[e[0], e[1], e[2]] for e in stroke]

    click_delay = random.randint(60, 120)
    click_t = stroke[-1][2] + click_delay
    md = [[target_x, target_y, click_t]]

    release_delay = random.randint(60, 80)
    mu = [[target_x, target_y, click_t + release_delay]]

    return {"mm": mm, "md": md, "mu": mu}


_HCAPTCHA_VERSION = "f4a6f30bb4f2f71cf58fd8dcd483138f9c494c52"

# Discord hash objects from real capture — deterministic per hcaptcha version
_DISCORD_HASH_OBJECTS = {
    "0": [0, [1027990181, 3885137012, 763506523, 0, None, 2808390301], [], 1, 0, 0, 0],
    "1": [2, [2756490015, 1601457770, 763506523, 0, None, 173542813], [], 0, 0, 0, 0],
    "2": [2, [3544941449, 4166911607, 763506523, 0, None, 813608560], [], 1, 0, 0, 0],
    "3": [1, [1140104728, 901924565, 763506523, 0, None, 1622217596], [], 1, 0, 0, 0],
    "4": [7, [None, None, None, None, None, None], [], 0, 0, 0, 0],
}


def _build_vmdata_discord(
    cfg: SolveConfig,
    page_events: dict,
    checkbox_events: dict,
    top_st: int,
    checkbox_st: int,
    href: str,
    inner_w: int,
    inner_h: int,
    wid: str,
    theme_val: int = 1796889847,
) -> str:
    """Build 3-frame vmdata for Discord checkbox mode.

    Frame 0: toplevel (page context with mouse moves)
    Frame 2: challenge (empty during getCaptcha)
    Frame 1: checkbox (click interaction)
    """
    base_ts = top_st + random.randint(2, 5)
    sc = _build_screen(cfg)
    # cr_s constant from VM string table index 512
    hash_b64 = "pLvoAbItYVMtqSDfmHtOL7cGyExMA55M39x+6bYg+h+h+b4o5dLzpoWhQq3kqnK9wVB8WKduoh8iiMrhHvdy+KZF/RVRiFvGYLHDVVJuvT/YvEbfsg/cGrMZ9TCxxrCd"

    # ── Frame 0: toplevel ──
    mm_list = page_events.get("mm", [])
    mm_mp = _mean_period(mm_list)
    mm_mp_131 = mm_mp - random.uniform(0.00001, 0.0001) if mm_mp > 0 else mm_mp

    toplevel_meta = {
        "112": [[m[0], m[1], 1, 0, m[2] - base_ts] for m in mm_list],
        "113": mm_mp,
        "130": [],
        "131": mm_mp_131,
        "150": base_ts,
        "161": "portrait",
        "162": sc,
        "164": "",
        "165": [inner_w, inner_h],
        "170": "m",
        "171": "<div></div>",
        "173": theme_val,
        "174": False,
    }

    perf_offset = random.uniform(800.0, 1500.0)
    perf_offset = round(perf_offset, 13)
    session_id = random.randint(10**15, 10**16 - 1)

    toplevel_inner = [
        toplevel_meta,
        perf_offset,
        None,
        session_id,
        href,
        [],
        [62, {}, _DISCORD_HASH_OBJECTS, base_ts + 1],
        href,
        hash_b64,
    ]

    # ── Frame 2: challenge (empty during getCaptcha) ──
    challenge_url = (
        f"https://newassets.hcaptcha.com/captcha/v1/{_HCAPTCHA_VERSION}"
        f"/static/hcaptcha.html#frame=challenge&id={wid}&host=discord.co"
    )
    challenge_inner = [
        {},
        0,
        None,
        0,
        challenge_url,
        [],
        [63, {}, {}, None],
        challenge_url,
        hash_b64,
    ]

    # ── Frame 1: checkbox ──
    checkbox_url = (
        f"https://newassets.hcaptcha.com/captcha/v1/{_HCAPTCHA_VERSION}"
        f"/static/hcaptcha.html#frame=checkbox&id={wid}&host=discord.com"
    )
    cb_mm = checkbox_events.get("mm", [])
    cb_md = checkbox_events.get("md", [])
    cb_mu = checkbox_events.get("mu", [])
    cb_mm_mp = _mean_period(cb_mm)
    cb_mm_mp_131 = cb_mm_mp + random.uniform(0.0005, 0.002) if cb_mm_mp > 0 else cb_mm_mp

    checkbox_meta = {
        "110": [[d[0], d[1], 1, 0, d[2] - checkbox_st] for d in cb_md],
        "111": [[u[0], u[1], 1, 0, u[2] - checkbox_st] for u in cb_mu],
        "112": [[m[0], m[1], 1, 0, m[2] - checkbox_st] for m in cb_mm],
        "113": cb_mm_mp,
        "130": [],
        "131": cb_mm_mp_131,
        "150": checkbox_st,
    }

    checkbox_inner = [
        checkbox_meta,
        0,
        None,
        0,
        checkbox_url,
        [],
        [63, {}, {}, None],
        checkbox_url,
        hash_b64,
    ]

    # Serialize each frame
    toplevel_json = json.dumps(toplevel_inner, separators=(",", ":"), ensure_ascii=False)
    challenge_json = json.dumps(challenge_inner, separators=(",", ":"), ensure_ascii=False)
    checkbox_json = json.dumps(checkbox_inner, separators=(",", ":"), ensure_ascii=False)

    vmdata = json.dumps(
        [[0, toplevel_json], [2, challenge_json], [1, checkbox_json]],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return vmdata


# ─── GENERATE INIT MOTION DATA (getCaptcha) ────────────────────


def generate_motion_data(cfg: SolveConfig, prev_pass: bool = False, ekeys: list = None, wid: str = None) -> dict:
    """Generate desktop motion data for getCaptcha (init + silent pass).

    Args:
        cfg: Browser/device configuration.
        prev_pass: True when a previous getCaptcha returned pass:true.
        ekeys: List of [ekey, widget_id] pairs from previous getCaptcha responses.
        wid: Widget ID to use (for consistency across calls). Generated if None.
    """
    now = int(time.time() * 1000)
    st = now

    is_epic = "epicgames" in (cfg.host or "")
    is_discord = "discord" in (cfg.host or "")

    if wid is None:
        wid = random_widget_id()

    href = cfg.href or f"https://{cfg.host}/"

    # ── prev: reflects previous captcha state ──
    if prev_pass:
        prev = {
            "escaped": False,
            "passed": True,
            "expiredChallenge": False,
            "expiredResponse": True,
        }
    else:
        prev = {
            "escaped": False,
            "passed": False,
            "expiredChallenge": False,
            "expiredResponse": False,
        }

    theme_val = 1796889847

    # ────────────────────────────────────────────────────────────
    #  DISCORD: checkbox mode (exec="m", visible widget)
    # ────────────────────────────────────────────────────────────
    if is_discord:
        # Discord: narrow portrait window, widget init close to checkbox
        inner_w = random.randint(500, 560)
        inner_h = random.randint(920, 960)

        # topLevel.st = widget initialization (close to captcha trigger)
        top_st = st - random.randint(500, 1500)
        # st = checkbox frame initialization
        checkbox_st = top_st + random.randint(400, 800)
        st = checkbox_st

        # Generate page-level mouse movements (user moving toward checkbox)
        page_events = _generate_discord_page_motion(top_st, inner_w, inner_h)

        # Generate checkbox interaction (move to checkbox + click)
        cb_events = _generate_checkbox_events(checkbox_st)

        # Build 3-frame vmdata
        vmdata = _build_vmdata_discord(
            cfg, page_events, cb_events, top_st, checkbox_st,
            href, inner_w, inner_h, wid, theme_val=theme_val,
        )

        # Outer pm: checkbox frame pointer events with sub-pixel offset
        pm_offset_x = 0.5
        pm_offset_y = 0.6875
        outer_pm = [[e[0] + pm_offset_x, e[1] + pm_offset_y, e[2]] for e in cb_events["mm"]]
        outer_mm = [[e[0], e[1], e[2]] for e in cb_events["mm"]]
        outer_md = cb_events["md"]
        outer_mu = cb_events["mu"]

        pm_mp = _mean_period(outer_pm)
        mm_mp = _mean_period(outer_mm)
        md_mp = _mean_period(outer_md)
        mu_mp = _mean_period(outer_mu)

        # Page-level mean periods for topLevel
        page_pm_mp = _mean_period(page_events["pm"])
        page_mm_mp = _mean_period(page_events["mm"])

        top_level = {
            "st": top_st,
            "sc": _build_screen(cfg),
            "or": "portrait",
            "wi": [inner_w, inner_h],
            "nv": _build_navigator(cfg),
            "dr": "",
            "inv": False,
            "theme": theme_val,
            "pel": "<div></div>",
            "exec": "m",
            "wn": [[inner_w, inner_h, 1, top_st]],
            "wn-mp": 0,
            "xy": [[0, 0, 1, top_st]],
            "xy-mp": 0,
            "pm": page_events["pm"],
            "pm-mp": page_pm_mp,
            "mm": page_events["mm"],
            "mm-mp": page_mm_mp,
        }

        motion = {
            "st": st,
            "pm": outer_pm,
            "pm-mp": pm_mp,
            "mm": outer_mm,
            "mm-mp": mm_mp,
            "md": outer_md,
            "md-mp": md_mp,
            "mu": outer_mu,
            "mu-mp": mu_mp,
            "v": 1,
            "session": ekeys if ekeys else [],
            "widgetList": [wid],
            "widgetId": wid,
            "topLevel": top_level,
            "href": href,
            "prev": prev,
            "vmdata": vmdata,
        }

        save_motion(motion, "init_discord_")
        return motion

    # ────────────────────────────────────────────────────────────
    #  EPIC / RIOT / OTHER: invisible API mode (exec="api")
    # ────────────────────────────────────────────────────────────

    motion_ctx = _get_motion_context(cfg, is_discord=False)
    inner_w = motion_ctx["inner_w"]
    inner_h = motion_ctx["inner_h"]
    dr = motion_ctx["dr"]
    pel_html = motion_ctx["pel_html"]

    raw_top_st = st - random.randint(14000, 22000)
    events = _generate_interaction(cfg, raw_top_st, inner_w, inner_h)
    events, top_delta = _fit_events_end(events, st - random.randint(180, 1200))
    top_st = raw_top_st + top_delta

    # ── wn/xy: empty for invisible/API mode (real captures show []) ──
    wn = []
    wn_mp = 0

    xy = []
    xy_mp = 0

    orientation = "landscape" if inner_w > inner_h else "portrait"

    pm_mp_full = _mean_period(events["pm"])
    mm_mp_full = _mean_period(events["mm"])
    md_mp_full = _mean_period(events["md"])
    mu_mp_full = _mean_period(events["mu"])

    buf_events = _apply_buffer_limits(events, st)

    vmdata = _build_vmdata(cfg, buf_events, top_st, href, inner_w, inner_h,
                           pel_html=pel_html, theme_val=theme_val, dr=dr,
                           orientation=orientation)

    buf_events = _apply_buffer_limits(events, st)

    top_level = {
        "st": top_st,
        "sc": _build_screen(cfg),
        "or": orientation,
        "wi": [inner_w, inner_h],
        "nv": _build_navigator(cfg),
        "dr": dr,
        "inv": True,
        "size": "invisible",
        "theme": theme_val,
        "pel": pel_html,
        "exec": "api",
        "wn": wn,
        "wn-mp": wn_mp,
        "xy": xy,
        "xy-mp": xy_mp,
        "pm": buf_events["pm"],
        "pm-mp": pm_mp_full,
        "mm": buf_events["mm"],
        "mm-mp": mm_mp_full,
        "md": buf_events["md"],
        "md-mp": md_mp_full,
        "mu": buf_events["mu"],
        "mu-mp": mu_mp_full,
    }

    motion = {
        "st": st,
        "v": 1,
        "session": ekeys if ekeys else [],
        "widgetList": [wid],
        "widgetId": wid,
        "topLevel": top_level,
        "href": href,
        "prev": prev,
        "vmdata": vmdata,
    }

    save_motion(motion, "init_")
    return motion


# ─── GENERATE CHALLENGE MOTION DATA (checkcaptcha) ─────────────


def generate_challenge_motion_data(cfg: SolveConfig, ekeys: list = None, wid: str = None) -> dict:
    """Generate motion data for checkcaptcha (challenge solving).

    Args:
        ekeys: List of [ekey, widget_id] pairs from previous getCaptcha responses.
        wid: Widget ID (for consistency). Generated if None.
    """
    now = int(time.time() * 1000)
    challenge_st = now - random.randint(6000, 10000)

    is_epic = "epicgames" in (cfg.host or "")
    is_discord = "discord" in (cfg.host or "")

    if is_discord:
        top_st = challenge_st - random.randint(1500, 3000)
    else:
        top_st = challenge_st - random.randint(12000, 18000)

    motion_ctx = _get_motion_context(cfg, is_discord=is_discord)
    inner_w = motion_ctx["inner_w"]
    inner_h = motion_ctx["inner_h"]

    href = cfg.href or f"https://{cfg.host}/"

    dr = motion_ctx["dr"]
    pel_html = motion_ctx["pel_html"]
    theme_val = motion_ctx["theme"]

    orientation = "landscape" if inner_w > inner_h else "portrait"

    if is_discord:
        challenge_events = _generate_interaction(cfg, challenge_st, inner_w, inner_h)
        top_events = _generate_interaction(cfg, top_st, inner_w, inner_h)
    else:
        raw_top_st = challenge_st - random.randint(14000, 22000)
        top_events = _generate_interaction(cfg, raw_top_st, inner_w, inner_h)
        top_events, top_delta = _fit_events_end(top_events, challenge_st - random.randint(450, 1800))
        top_st = raw_top_st + top_delta

        raw_challenge_st = challenge_st
        challenge_events = _generate_simple_mouse(raw_challenge_st, inner_w, inner_h)
        challenge_events, challenge_delta = _fit_events_end(challenge_events, now - random.randint(120, 900))
        challenge_st = raw_challenge_st + challenge_delta

    top_pm_mp = _mean_period(top_events["pm"])
    top_mm_mp = _mean_period(top_events["mm"])
    buf_top = _apply_buffer_limits(top_events, now)

    ch_pm_mp = _mean_period(challenge_events["pm"])
    ch_mm_mp = _mean_period(challenge_events["mm"])
    ch_md_mp = _mean_period(challenge_events["md"])
    ch_mu_mp = _mean_period(challenge_events["mu"])
    buf_ch = _apply_buffer_limits(challenge_events, now)

    if is_discord:
        # Discord checkbox mode: topLevel has NO md/mu, NO size, exec="m", inv=False
        # wn and xy are empty during challenge (only set during init)
        top_level = {
            "st": top_st,
            "sc": _build_screen(cfg),
            "or": "portrait",
            "wi": [inner_w, inner_h],
            "nv": _build_navigator(cfg),
            "dr": "",
            "inv": False,
            "theme": theme_val,
            "pel": "<div></div>",
            "exec": "m",
            "wn": [],
            "wn-mp": 0,
            "xy": [],
            "xy-mp": 0,
            "pm": buf_top["pm"],
            "pm-mp": top_pm_mp,
            "mm": buf_top["mm"],
            "mm-mp": top_mm_mp,
        }
    else:
        # Epic / Riot: invisible API mode with md/mu at topLevel
        top_md_mp = _mean_period(top_events["md"])
        top_mu_mp = _mean_period(top_events["mu"])

        top_level = {
            "st": top_st,
            "sc": _build_screen(cfg),
            "or": orientation,
            "wi": [inner_w, inner_h],
            "nv": _build_navigator(cfg),
            "dr": dr,
            "inv": True,
            "size": "invisible",
            "theme": theme_val,
            "pel": pel_html,
            "exec": "api",
            "wn": [],
            "wn-mp": 0,
            "xy": [],
            "xy-mp": 0,
            "pm": buf_top["pm"],
            "pm-mp": top_pm_mp,
            "mm": buf_top["mm"],
            "mm-mp": top_mm_mp,
            "md": buf_top["md"],
            "md-mp": top_md_mp,
            "mu": buf_top["mu"],
            "mu-mp": top_mu_mp,
        }

    motion = {
        "st": challenge_st,
        "dct": challenge_st,
        "pm": buf_ch["pm"],
        "pm-mp": ch_pm_mp,
        "mm": buf_ch["mm"],
        "mm-mp": ch_mm_mp,
        "md": buf_ch["md"],
        "md-mp": ch_md_mp,
        "mu": buf_ch["mu"],
        "mu-mp": ch_mu_mp,
        "topLevel": top_level,
        "v": 1,
        "tc": {},
    }

    save_motion(motion, "challenge_discord_" if is_discord else "challenge_")
    return motion
