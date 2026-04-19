from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


FIREFOX_VERSION = "149"
FIREFOX_FULL_VERSION = "149.0"

CHROME_VERSION = FIREFOX_VERSION
CHROME_FULL_VERSION = FIREFOX_FULL_VERSION

REDUCED_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) "
    "Gecko/20100101 "
    f"Firefox/{FIREFOX_FULL_VERSION}"
)

PopularCaptcha_VERSION = "fd8f7b402bd625f3d6aa5600d2245de1bf487eb8"


# Fixed GPU — matches real Epic Games capture (AMD Radeon RX 6600 LE)
GPU_RENDERER = "ANGLE (NVIDIA, NVIDIA GeForce GTX 980 Direct3D11 vs_5_0 ps_5_0), or similar"
GPU_VENDOR = "Mozilla"


@dataclass
class Screen:
    avail_height: int = 1040
    avail_width: int = 1920
    height: int = 1080
    width: int = 1920
    color_depth: int = 32
    pixel_depth: int = 32


@dataclass
class SolveConfig:
    ua: str = REDUCED_UA
    lang: str = "en-US"
    sec_ch_ua: str = ""
    chrome_version: str = CHROME_VERSION
    chrome_full_version: str = CHROME_FULL_VERSION
    languages: List[str] = field(default_factory=lambda: ["en-US", "en"])
    hardware_concurrency: int = 8
    device_memory: int = 8
    device_pixel_ratio: float = 1.25
    screen: Screen = field(default_factory=Screen)
    renderer: str = GPU_RENDERER
    gpu_vendor: str = GPU_VENDOR
    max_touch_points: int = 0
    timezone_offset: int = -120
    timezone: str = "Africa/Cairo"
    dark_mode: bool = False
    platform: str = "Win32"
    sitekey: str = "019f1553-3845-481c-a6f5-5a60ccf6d830"
    host: str = "authenticate.riotgames.com"
    version: str = PopularCaptcha_VERSION
    href: str = ""
    fingerprint_type: Any = 0
    profile_data: dict = field(default_factory=dict)


@dataclass
class SolveRequest:
    proxy: str = ""
    rqdata: str = ""
    sitekey: str = ""
    host: str = ""


@dataclass
class SolveResult:
    success: bool = False
    token: str = ""
    xal: str = ""
    useragent: str = ""
    passed: bool = False
    elapsed: int = 0
    debug: List[dict] = field(default_factory=list)

