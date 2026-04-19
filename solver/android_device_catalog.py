"""
Android device catalog.

The pool at solver/pools/hsj_components_pool.json was stripped of UA, hardware
concurrency, device memory and maxTouchPoints (all None in the dump). We need
those four fields to paint a coherent navigator block on top of each pool
entry — this table provides them.

Picked per-solve in phone_profile.load_profile(). Each record is a plausible
real Android device with a WebView UA string, Android major version, GPU
family hint (used to bias the pool-entry selection toward matching vendors),
and hardware caps.

All UAs here are real Android WebView strings of the form:
    Mozilla/5.0 (Linux; Android {AV}; {MODEL} Build/{BUILD}; wv) AppleWebKit/...
Version/4.0 Chrome/{CV} Mobile Safari/537.36

UA templates use '{CV}' as a placeholder — random_device() injects a recent
Chromium version so we don't telegraph a single build.
"""
import random
from typing import Dict, List, Tuple

# Recent Android WebView Chromium versions (as shipped with Google Play WebView
# stable channel between 2024-Q4 and 2026-Q1). Rotate so each solve picks one.
_CHROME_VERSIONS = (
    "146.0.7680.177", "146.0.7680.165", "146.0.7680.99", "146.0.7680.41",
    "145.0.7599.157", "145.0.7599.129", "145.0.7599.95", "145.0.7599.65",
    "144.0.7525.89",  "144.0.7525.54",  "143.0.7488.108", "143.0.7488.68",
    "142.0.7394.95",  "141.0.7300.94",  "140.0.7239.60",
)


# (model, android_version, build_tag, gpu_family, hw_concurrency, device_memory, max_touch_points)
# gpu_family must be one of: "mali", "adreno", "xclipse", "powervr"
# Matches the renderer substrings in the pool so we pair a Samsung UA with a
# Xclipse hash-tuple rather than a Mali one.
_DEVICES: List[Tuple[str, str, str, str, int, int, int]] = [
    # Samsung (Exynos → Xclipse, Snapdragon → Adreno)
    ("SM-S928B",  "15", "AP3A.240905.015.A2.S928BXXU4AXKA", "xclipse", 8, 12, 10),  # Galaxy S24 Ultra Exynos
    ("SM-S928U",  "15", "AP3A.240905.015.A2.S928USQU4AXKA", "adreno",  8, 12, 10),  # S24 Ultra Snapdragon
    ("SM-S921B",  "15", "AP3A.240905.015.A2.S921BXXU4AXKA", "xclipse", 8,  8, 10),  # S24
    ("SM-S911B",  "14", "UP1A.231005.007.S911BXXU3CXH3",    "xclipse", 8,  8, 10),  # S23
    ("SM-A546B",  "14", "UP1A.231005.007.A546BXXU7CXE7",    "mali",    8,  8, 10),  # A54 5G
    ("SM-A556B",  "14", "UP1A.231005.007.A556BXXU3BXK1",    "mali",    8,  8, 10),  # A55 5G
    ("SM-A525F",  "14", "UP1A.231005.007.A525FXXS5DXJ1",    "mali",    8,  6, 10),  # A52
    ("SM-A135F",  "13", "TP1A.220624.014.A135FXXU7CXH1",    "mali",    8,  4, 10),  # A13
    ("SM-A136B",  "14", "UP1A.231005.007.A136BXXU6CXK1",    "mali",    8,  4, 10),  # A13 5G

    # Google Pixel (Tensor → Mali/ARM)
    ("Pixel 9 Pro", "15", "AD1A.240530.047.U2",   "mali", 8, 12, 10),
    ("Pixel 9",     "15", "AD1A.240530.047.U2",   "mali", 8, 12, 10),
    ("Pixel 8 Pro", "15", "AP3A.241005.015.A1",   "mali", 9, 12, 10),
    ("Pixel 8",     "14", "AP2A.240905.003",      "mali", 9,  8, 10),
    ("Pixel 7 Pro", "14", "UP1A.231105.003",      "mali", 8, 12, 10),
    ("Pixel 7",     "14", "UP1A.231105.003",      "mali", 8,  8, 10),
    ("Pixel 6a",    "13", "TP1A.221105.002",      "mali", 8,  6, 10),

    # Xiaomi / Redmi / POCO (Snapdragon → Adreno, MediaTek → Mali)
    ("23129RAA4G",       "14", "UP1A.231005.007.V816IR.0.JNFEUXM", "adreno", 8, 12, 10),  # Xiaomi 13T Pro
    ("2311DRK48G",       "14", "UP1A.231005.007.V816IR.0.IKMEUXM", "adreno", 8, 12, 10),  # 14
    ("2201117TG",        "14", "UP1A.231005.007.V816MIDL.0.DKCEUXM","adreno",8,  8, 10),  # Note 11
    ("220733SG",         "14", "UP1A.231005.007.V816IDL.0.FMIEUXM","adreno", 8,  6, 10),  # Redmi Note 12
    ("M2103K19G",        "13", "TP1A.220624.014.V14.0.16.0",       "mali",   8,  6, 10),  # Redmi Note 10 5G
    ("21061119DG",       "13", "TP1A.220624.014.V816EUXM",         "adreno", 8,  8, 10),  # POCO X3 GT
    ("23049PCD8G",       "14", "UP1A.231005.007.V816IDL.0.KKMEUXM","mali",   8,  8, 10),  # POCO C65

    # OnePlus / OPPO / realme / Vivo (Snapdragon → Adreno, Dimensity → Mali)
    ("CPH2459",  "14", "UP1A.231005.007.V816IDL.0.GOEUXM", "adreno", 8,  8, 10),  # OnePlus Nord 3
    ("CPH2493",  "14", "UP1A.231005.007.V816IDL.0.HKEUXM", "adreno", 8, 12, 10),  # OnePlus 12
    ("CPH2643",  "14", "UP1A.231005.007.V816IDL.0.IDEUXM", "mali",   8,  8, 10),  # OnePlus Nord CE 4
    ("V2312",    "14", "UP1A.231005.007.V816IDL.0.FKEUXM", "mali",   8,  8, 10),  # vivo V30
    ("V2323",    "14", "UP1A.231005.007.V816IDL.0.JKEUXM", "mali",   8,  8, 10),  # vivo Y38 5G
    ("RMX3624",  "14", "UP1A.231005.007.V816IDL.0.GFEUXM", "adreno", 8,  8, 10),  # realme 12 Pro
    ("RMX3841",  "14", "UP1A.231005.007.V816IDL.0.FKEUXM", "mali",   8,  8, 10),  # realme 13

    # Honor / Huawei (Kirin → Mali, some have HUAWEI vendor in pool)
    ("ELI-NX9",  "16", "HONORELI-NX9",                      "mali", 8, 12, 10),  # HONOR Magic6 (matches our captured backbone)
    ("ELP-NX9",  "15", "HONORELP-NX9",                      "mali", 8, 12, 10),  # HONOR Magic6 Pro
    ("VNE-LX1",  "14", "HONORVNE-LX1",                      "mali", 8,  8, 10),  # HONOR 90
    ("ANG-LX1",  "14", "HONORANG-LX1",                      "mali", 8,  8, 10),  # HONOR X9b
    ("NTH-NX9",  "14", "HONORNTH-NX9",                      "mali", 8, 12, 10),  # HONOR Magic V2

    # Motorola
    ("motorola edge 50 ultra", "14", "U2UKS34.29-107-8", "adreno", 8, 16, 10),
    ("motorola edge 40",       "14", "U2URS34.12-107-3", "mali",   8,  8, 10),
    ("moto g84 5G",            "14", "U3URS34.35-107-6", "adreno", 8,  8, 10),

    # Nothing / Sony / Asus / ZTE (smaller share, keep a couple for variety)
    ("A142",      "14", "UP1A.231005.007.A142XXU1CXK1",     "adreno", 8, 12, 10),  # Nothing Phone 2
    ("XQ-EC54",   "14", "66.1.A.3.49",                      "adreno", 8,  8, 10),  # Sony Xperia 5 V
    ("ASUS_AI2401","14","UP1A.231005.007.ASUSAI24.33.44.11","adreno", 8, 16, 10), # ROG Phone 8
]


def _pick_chrome_version() -> str:
    return random.choice(_CHROME_VERSIONS)


def _build_ua(model: str, android_version: str, build_tag: str) -> str:
    """Produce a real Android WebView UA with a freshly-picked Chrome version."""
    cv = _pick_chrome_version()
    return (
        f"Mozilla/5.0 (Linux; Android {android_version}; {model} "
        f"Build/{build_tag}; wv) "
        f"AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 "
        f"Chrome/{cv} Mobile Safari/537.36"
    )


def pick_device(bias_gpu: str = None) -> Dict[str, object]:
    """Pick a random Android device. Optionally bias toward a GPU family
    ("mali" / "adreno" / "xclipse" / "powervr") so the chosen UA is coherent
    with the pool hash-tuple we're going to layer on top.

    Returns a dict with user_agent, android_version, model, build_tag,
    gpu_family, hardware_concurrency, device_memory, max_touch_points.
    """
    pool = _DEVICES
    if bias_gpu:
        matching = [d for d in _DEVICES if d[3] == bias_gpu]
        if matching:
            pool = matching
    model, av, build, gpu, hc, mem, tp = random.choice(pool)
    return {
        "user_agent": _build_ua(model, av, build),
        "model": model,
        "android_version": av,
        "build_tag": build,
        "gpu_family": gpu,
        "hardware_concurrency": hc,
        "device_memory": mem,
        "max_touch_points": tp,
    }


def gpu_family_from_renderer(renderer: str) -> str:
    """Map a pool entry's renderer string to a gpu_family key the catalog uses."""
    r = (renderer or "").lower()
    if "mali" in r:
        return "mali"
    if "adreno" in r:
        return "adreno"
    if "xclipse" in r:
        return "xclipse"
    if "powervr" in r:
        return "powervr"
    return "mali"  # default


def catalog_size() -> int:
    return len(_DEVICES)
