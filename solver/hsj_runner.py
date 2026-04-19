"""
Python wrapper for the Node.js HSJ runner.
Calls hsj_runner.js via subprocess.

Primary mode: hsj(jwt) → returns N token directly (includes encrypted fingerprint).
Bonus mode : also extracts AES key from HEAP8 if available (for custom fingerprints).
"""

import json
import os
import subprocess

_HERE = os.path.dirname(os.path.abspath(__file__))
_RUNNER_JS = os.path.join(_HERE, "hsj_runner.js")

# hsj.js lookup: bundled (PyInstaller _MEIPASS) first, then dev dir.
_HSJ_CANDIDATES = [
    os.path.join(_HERE, "HSJ reverse", "Hcaptcha-hsj-reverse-main", "hsj.js"),
    os.path.normpath(os.path.join(_HERE, "..", "..", "..", "HSJ reverse",
                                   "Hcaptcha-hsj-reverse-main", "hsj.js")),
]
_DEFAULT_HSJ_PATH = next((p for p in _HSJ_CANDIDATES if os.path.isfile(p)),
                        _HSJ_CANDIDATES[0])


def run_hsj(jwt: str, hsj_path: str = None, timeout: int = 25,
            profile_path: str = None) -> dict | None:
    """
    Execute hsj(jwt) in Node.js and return the result.

    Args:
        jwt          : The JWT from checksiteconfig response
        hsj_path     : Path to hsj.js (defaults to HSJ reverse/ directory)
        timeout      : Max seconds to wait
        profile_path : Optional path to a captured phone HSJ profile JSON.
                       When provided, hsj_runner.js merges its
                       components.navigator / screen / device_pixel_ratio /
                       href into the sandbox so the generated N matches the
                       real phone fingerprint.

    Returns:
        dict with keys:
            - "n_token": str — the N token for hCaptcha API (always present on success)
            - "key_hex": str | None — 64-char hex AES key (if extraction succeeded)
            - "source": str — how the key was found ("heap8", "crypto_subtle", etc.)
        or None on failure.
    """
    if not hsj_path:
        hsj_path = _DEFAULT_HSJ_PATH

    if not os.path.isfile(hsj_path) or not os.path.isfile(_RUNNER_JS):
        return None

    cmd = ["node", _RUNNER_JS, jwt, hsj_path]
    if profile_path and os.path.isfile(profile_path):
        cmd.append(profile_path)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=os.path.dirname(hsj_path),
        )

        stdout = result.stdout.strip()
        if not stdout:
            return None

        data = json.loads(stdout)

        # Success if we got an N token
        if data.get("n_token"):
            return data

        # Or if we got a key
        if data.get("key_hex") and len(data["key_hex"]) == 64:
            return data

        return None

    except subprocess.TimeoutExpired:
        return None
    except (json.JSONDecodeError, OSError):
        return None


def get_n_token(jwt: str, hsj_path: str = None, timeout: int = 25,
                profile_path: str = None) -> str | None:
    """
    Convenience: just get the N token string, with optional phone profile.
    """
    result = run_hsj(jwt, hsj_path, timeout, profile_path=profile_path)
    if result:
        return result.get("n_token")
    return None


def get_hsj_key(jwt: str, hsj_path: str = None, timeout: int = 25) -> str | None:
    """
    Convenience: just get the AES key hex (if available).
    """
    result = run_hsj(jwt, hsj_path, timeout)
    if result:
        key = result.get("key_hex")
        if key and len(key) == 64:
            return key
    return None
