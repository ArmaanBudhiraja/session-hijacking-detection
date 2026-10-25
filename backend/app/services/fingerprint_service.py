import re
import json
import hashlib
from typing import Dict, Any, Optional
from app.schemas.auth import FingerprintPayload

def parse_user_agent_family(user_agent: str) -> str:
    """
    Extracts high-level browser family from raw User-Agent string.
    Privacy-conscious and resilient to minor build version bumps.
    """
    ua = user_agent.lower()
    if "edg/" in ua or "edge/" in ua:
        return "Edge"
    elif "chrome/" in ua and "safari/" in ua and "edg/" not in ua and "opr/" not in ua:
        return "Chrome"
    elif "safari/" in ua and "chrome/" not in ua:
        return "Safari"
    elif "firefox/" in ua:
        return "Firefox"
    elif "opr/" in ua or "opera/" in ua:
        return "Opera"
    return "Unknown/Other"

def parse_os_platform(user_agent: str, raw_platform: Optional[str]) -> str:
    """
    Cross-checks raw navigator.platform with User-Agent OS hints.
    """
    if raw_platform:
        plat = raw_platform.lower()
        if "mac" in plat:
            return "macOS"
        elif "win" in plat:
            return "Windows"
        elif "linux" in plat and "android" not in plat:
            return "Linux"
        elif "iphone" in plat or "ipad" in plat or "ipod" in plat:
            return "iOS"
        elif "android" in plat:
            return "Android"

    # Fallback to User Agent
    ua = user_agent.lower()
    if "macintosh" in ua or "mac os x" in ua:
        return "macOS"
    elif "windows" in ua:
        return "Windows"
    elif "linux" in ua and "android" not in ua:
        return "Linux"
    elif "iphone" in ua or "ipad" in ua:
        return "iOS"
    elif "android" in ua:
        return "Android"
    return raw_platform or "Unknown"

def normalize_fingerprint(payload: FingerprintPayload) -> Dict[str, Any]:
    """
    Normalizes incoming browser attributes into a canonical, structured format.
    Handles missing values gracefully and avoids brittle raw strings.
    """
    ua_family = payload.user_agent_family or parse_user_agent_family(payload.user_agent)
    os_platform = parse_os_platform(payload.user_agent, payload.platform)

    # Base language (e.g., 'en-US' -> 'en')
    norm_lang = None
    if payload.language:
        norm_lang = payload.language.split("-")[0].lower().strip()

    # Screen normalization
    norm_screen = None
    if payload.screen:
        w = max(payload.screen.width, 1)
        h = max(payload.screen.height, 1)
        aspect = round(w / h, 2)
        norm_screen = {
            "width": payload.screen.width,
            "height": payload.screen.height,
            "color_depth": payload.screen.color_depth or 24,
            "pixel_ratio": payload.screen.pixel_ratio or 1.0,
            "aspect_ratio": aspect
        }

    # Timezone canonicalization
    norm_tz = payload.timezone.strip() if payload.timezone else None

    # Canvas hash normalization (lowercase hex)
    norm_canvas = payload.canvas_hash.lower().strip() if payload.canvas_hash else None

    # WebGL vendor & renderer
    norm_webgl_vendor = payload.webgl_vendor.strip() if payload.webgl_vendor else None
    norm_webgl_renderer = payload.webgl_renderer.strip() if payload.webgl_renderer else None

    return {
        "user_agent_raw": payload.user_agent,
        "user_agent_family": ua_family,
        "platform": os_platform,
        "raw_platform": payload.platform,
        "language": norm_lang,
        "timezone": norm_tz,
        "timezone_offset": payload.timezone_offset,
        "screen": norm_screen,
        "hardware_concurrency": payload.hardware_concurrency,
        "device_memory": payload.device_memory,
        "canvas_hash": norm_canvas,
        "webgl_vendor": norm_webgl_vendor,
        "webgl_renderer": norm_webgl_renderer,
        "audio_fingerprint": payload.audio_fingerprint
    }

def generate_canonical_hash(normalized_fp: Dict[str, Any]) -> str:
    """
    Creates a deterministic cryptographic SHA-256 signature from canonicalized attributes.
    Key properties are sorted to ensure repeatability across requests.
    """
    # Select stable canonical fields for the signature
    signature_dict = {
        "user_agent_family": normalized_fp.get("user_agent_family"),
        "platform": normalized_fp.get("platform"),
        "timezone": normalized_fp.get("timezone"),
        "canvas_hash": normalized_fp.get("canvas_hash"),
        "hardware_concurrency": normalized_fp.get("hardware_concurrency"),
        "webgl_vendor": normalized_fp.get("webgl_vendor"),
        "webgl_renderer": normalized_fp.get("webgl_renderer")
    }
    encoded = json.dumps(signature_dict, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
