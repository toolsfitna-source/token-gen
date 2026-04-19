"""
Patch HSJ profile events to match a Discord Android WebView fingerprint.

Translates the event encrypt/decrypt from the JS implementation to Python.
Patches navigator, screen, GPU, timezone events to match our Discord Android identity.
"""

import json
import os
import random
import string
import base64
from urllib.parse import quote, unquote
from typing import Any, Dict, List, Optional, Tuple


# ── Event encryption (ported from algorithms/encrypt_event.js) ──

def _random_key() -> str:
    return ''.join(random.choices(string.ascii_uppercase, k=13))


def _rand_int(lo: int, hi: int) -> int:
    return random.randint(lo, hi)


def encrypt_event_value(plaintext: str) -> str:
    """Encrypt a single event value. Returns the encrypted array as JSON string."""
    w = _random_key()
    v = _rand_int(1, 26)
    alpha = 'abcdefghijklmnopqrstuvwxyz'

    # Step 1: reverse words
    step1 = ' '.join(plaintext.split(' ')[::-1])
    # Step 2: reverse chars + caesar shift
    step2 = []
    for c in reversed(step1):
        if c.isalpha():
            up = c.isupper()
            idx = alpha.index(c.lower())
            sh = alpha[(idx + v) % 26]
            step2.append(sh.upper() if up else sh)
        else:
            step2.append(c)
    step2 = ''.join(step2)
    # Step 3: URI encode + base64
    b64 = base64.b64encode(quote(step2).encode()).decode()
    # Step 4: reverse base64
    B = b64[::-1]
    l = len(B)
    E = _rand_int(1, max(1, l - 1))
    # Step 5: rotate
    rotated = B[E:] + B[:E]
    # Step 6: case swap for key chars
    key_chars = w + w.lower()
    final = []
    for c in rotated:
        if c in key_chars:
            final.append(c.lower() if c.isupper() else c.upper())
        else:
            final.append(c)
    final_str = ''.join(final)

    return json.dumps([final_str, format(v, 'x'), format(E, 'x'), w])


def decrypt_event_value(encoded_str: str, shift_hex: str, split_hex: str, key_w: str) -> str:
    """Decrypt a single event value."""
    v = int(shift_hex, 16)
    E = int(split_hex, 16)
    alpha = 'abcdefghijklmnopqrstuvwxyz'
    key_chars = key_w + key_w.lower()

    # Case revert
    temp = []
    for c in encoded_str:
        if c in key_chars:
            temp.append(c.lower() if c.isupper() else c.upper())
        else:
            temp.append(c)
    case_reverted = ''.join(temp)

    # Un-rotate
    l = len(case_reverted)
    cut = l - E
    orig_b64_rev = case_reverted[cut:] + case_reverted[:cut]

    # Un-reverse base64
    b64_str = orig_b64_rev[::-1]

    # Decode
    decoded_uri = base64.b64decode(b64_str).decode()
    processed = unquote(decoded_uri)

    # Reverse caesar
    result = []
    for c in processed:
        if c.isalpha():
            up = c.isupper()
            idx = alpha.index(c.lower())
            orig_idx = (idx - v) % 26
            orig_char = alpha[orig_idx]
            result.append(orig_char.upper() if up else orig_char)
        else:
            result.append(c)
    reversed_chars = ''.join(result)[::-1]
    original = ' '.join(reversed_chars.split(' ')[::-1])
    return original


def encrypt_event_array(values: list) -> str:
    """Encrypt an array of values (like GPU [vendor, renderer])."""
    encrypted = [json.loads(encrypt_event_value(v)) for v in values]
    return json.dumps(encrypted)


# ── Event IDs that contain fingerprint data ──

EVENT_NAVIGATOR = 504458258      # Navigator array
EVENT_SCREEN = 1000750690        # Screen dimensions array
EVENT_GPU = 1866465638           # [vendor, renderer] plain text
EVENT_GPU_ALT = 3495389113       # GPU encrypted (DO NOT patch — hsj.py regenerates)
EVENT_TIMEZONE = 1181016567      # Timezone string (plain text)
EVENT_TIMEZONE_ENC = 4009980312  # Timezone encrypted (DO NOT patch — hsj.py regenerates)
EVENT_MEMORY_ENC = 2795229317    # Memory encrypted (DO NOT patch — hsj.py regenerates)
EVENT_TIMESTAMP = 3663932439     # performance.now() at a capture moment (ms, float)
EVENT_TIMESTAMP2 = 2054986590    # Date.now() in ms (big int) — AGES FAST, must refresh

# Session-varying events (observed to differ per capture on same device).
# Regenerating these with fresh/random values makes each solve look like a
# brand-new real session instead of a replay of a past capture.
EVENT_PERF_TIMING_A = 580323850   # performance.now() value (~50-200ms range)
EVENT_PERF_TIMING_B = 2972341029  # performance.now() value (~20-100ms range)
EVENT_INT_COUNTER = 2182569285    # small int (counter-like, ~50-200)
EVENT_RESOURCE_TIMINGS = 3357624742  # [[name, duration_ms, start_ms], ...] for fetches
EVENT_CANVAS_PIXELS = 2737207841  # canvas pixel sample array — leave as-is (complex)
EVENT_LOAD_ERROR = 3427390490     # load error array with URLs containing worker hash


# ── Patch a profile's events ──

def patch_profile_events(profile: dict, device_info: dict = None) -> dict:
    """Patch a profile's encrypted events to match Discord Android WebView.

    Args:
        profile: The HSJ profile dict (with 'events' list of [id, value] pairs)
        device_info: Optional device info from friend_advertiser identity

    Returns:
        The patched profile dict
    """
    if not device_info:
        device_info = {}

    events = profile.get("events", [])
    if not events:
        return profile

    device_model = device_info.get("device_model", "ELI-NX9")
    device_brand = device_info.get("device_brand", "HONOR")
    screen_w = device_info.get("smallest_screen_width", 434)
    screen_h = int(screen_w * 2.2)

    # Build the Android WebView navigator array
    android_ua = (
        f"Mozilla/5.0 (Linux; Android 16; {device_model} "
        f"Build/{device_brand}{device_model.replace('-', '')}; wv) "
        f"AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 "
        f"Chrome/146.0.7680.177 Mobile Safari/537.36"
    )

    new_events = []
    for event in events:
        if not isinstance(event, list) or len(event) < 2:
            new_events.append(event)
            continue

        eid = event[0]
        val = event[1]

        if eid == EVENT_SCREEN:
            # Screen: [width, height, avail_w, avail_h, color_depth, pixel_depth, ...]
            new_val = json.dumps([
                screen_w, screen_h, screen_w, screen_h - 52,
                24, 24, False, 0, 2.5, screen_w, screen_h - 52,
                False, True, True, True
            ])
            new_events.append([eid, new_val])

        elif eid == EVENT_TIMEZONE:
            new_events.append([eid, json.dumps("Europe/Paris")])

        elif eid == EVENT_TIMEZONE_ENC or eid == EVENT_MEMORY_ENC:
            # Encrypted timezone/memory — remove so hsj.py regenerates them
            # to match the patched plain-text values
            continue

        elif eid == EVENT_TIMESTAMP:
            # performance.now() at some moment during captcha init (float ms)
            new_events.append([eid, str(round(random.uniform(500, 1500), 7))])

        elif eid == EVENT_TIMESTAMP2:
            # Date.now() in ms — must be CURRENT or hCaptcha flags stale session
            import time
            new_events.append([eid, str(round(time.time() * 1000, 1))])

        elif eid == EVENT_PERF_TIMING_A:
            # performance.now() captured a bit later (~50-200ms range)
            new_events.append([eid, round(random.uniform(50.0, 200.0), 13)])

        elif eid == EVENT_PERF_TIMING_B:
            # performance.now() smaller window (~20-100ms)
            new_events.append([eid, round(random.uniform(20.0, 100.0), 13)])

        elif eid == EVENT_INT_COUNTER:
            # Small counter — captured values 100-200, randomize in plausible range
            new_events.append([eid, random.randint(80, 220)])

        elif eid == EVENT_RESOURCE_TIMINGS:
            # Resource fetch timings — regenerate for hCaptcha endpoints the
            # WebView would hit on a fresh captcha open. Format:
            # [["fetch:<host>", duration_ms, start_ms], ["navigation:<url>", ...]]
            now_init = round(random.uniform(200, 400), 7)
            duration = lambda lo=50, hi=300: round(random.uniform(lo, hi), 7)
            timings = [
                [f"fetch:{random.randint(100000,999999):06x}.w.hcaptcha.com",
                 duration(40, 80), round(now_init + random.uniform(-50, 50), 7)],
                ["navigation:newassets.hcaptcha.com/captcha/v1/fd8f7b402bd625f3d6aa5600d2245de1bf487eb8/static/hcaptcha.html",
                 duration(80, 200), round(now_init + random.uniform(0, 30), 7)],
                ["fetch:api.hcaptcha.com", duration(30, 100),
                 round(now_init + random.uniform(100, 200), 7)],
            ]
            new_events.append([eid, json.dumps(timings)])

        elif eid == EVENT_NAVIGATOR:
            # Navigator event — need to check if encrypted or plain
            if isinstance(val, str) and val.startswith('['):
                # Plain JSON array — try to parse and modify
                try:
                    nav = json.loads(val)
                    if isinstance(nav, list) and len(nav) > 5:
                        # Format: [appVersion, ua, deviceMemory?, hardwareConcurrency, language, languages, platform, ...]
                        nav[0] = android_ua.split("Mozilla/")[-1] if android_ua.startswith("Mozilla/") else android_ua
                        nav[1] = android_ua
                        if len(nav) > 4:
                            nav[4] = "fr-FR"
                        if len(nav) > 5:
                            nav[5] = ["fr-FR", "fr", "en-US", "en"]
                        if len(nav) > 6:
                            nav[6] = "Linux armv8l"
                        new_events.append([eid, json.dumps(nav)])
                        continue
                except Exception:
                    pass
            # If it's encrypted event value (array of [str, hex, hex, key])
            # We can't easily re-encrypt without knowing the original plaintext
            # So we keep it as-is — the navigator in components is what matters most
            new_events.append([eid, val])

        elif eid == EVENT_GPU:
            # Plain-text GPU — patch to mobile GPU
            if isinstance(val, str) and val.startswith('['):
                try:
                    gpu = json.loads(val)
                    if isinstance(gpu, list) and len(gpu) >= 2:
                        gpu[0] = "Google Inc. (Qualcomm)"
                        gpu[1] = "ANGLE (Qualcomm, Adreno (TM) 730, OpenGL ES 3.2)"
                        new_events.append([eid, json.dumps(gpu)])
                        continue
                except Exception:
                    pass
            new_events.append([eid, val])

        elif eid == EVENT_GPU_ALT:
            # Encrypted GPU — DO NOT TOUCH. hsj.py will regenerate it
            # to match the patched plain-text GPU values.
            # Removing it so hsj.py generates a fresh consistent encrypted value.
            continue

        else:
            new_events.append([eid, val])

    profile["events"] = new_events
    return profile


if __name__ == "__main__":
    # Test: patch the first Android profile in foox1
    import glob
    foox1 = os.path.join(os.path.dirname(__file__), "profiles", "foox1")
    files = glob.glob(os.path.join(foox1, "*.json"))
    if files:
        p = json.load(open(files[0]))
        print(f"Original events: {len(p.get('events', []))}")

        # Check which events have plain vs encrypted values
        for ev in p.get("events", [])[:10]:
            eid = ev[0]
            val = str(ev[1])[:60]
            print(f"  {eid}: {val}")

        patched = patch_profile_events(p, {"device_model": "ELI-NX9", "device_brand": "HONOR", "smallest_screen_width": 434})
        print(f"\nPatched events: {len(patched.get('events', []))}")
        for ev in patched.get("events", [])[:10]:
            eid = ev[0]
            val = str(ev[1])[:60]
            print(f"  {eid}: {val}")
    else:
        print("No profiles in foox1")
