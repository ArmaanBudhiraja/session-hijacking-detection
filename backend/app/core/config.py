from typing import List, Dict
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="allow")

    APP_NAME: str = "Behavioral Fingerprint Session Hijacking Detection"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    SECRET_KEY: str = "insecure-dev-secret-key-change-in-production-only-use-32-bytes"

    # Database
    DATABASE_URL: str = "sqlite:///./data/session_security.db"

    # Session Management
    SESSION_COOKIE_NAME: str = "sid"
    CSRF_COOKIE_NAME: str = "csrf_token"
    CSRF_HEADER_NAME: str = "x-csrf-token"
    SESSION_LIFETIME_SECONDS: int = 3600
    COOKIE_SECURE: bool = False
    COOKIE_SAMESITE: str = "lax"
    COOKIE_HTTPONLY: bool = True

    # Fingerprint Detection Engine Thresholds (0.0 - 100.0)
    MISMATCH_FLAG_THRESHOLD: float = 35.0
    MISMATCH_REVOKE_THRESHOLD: float = 50.0
    SIMILARITY_MIN_THRESHOLD: float = 50.0
    MIN_EVIDENCE_COUNT: int = 5

    # Attribute Weights for Weighted Comparison
    # Higher weights reflect stronger, less mutable device/browser context signals
    ATTRIBUTE_WEIGHTS: Dict[str, float] = {
        "platform": 25.0,            # e.g., MacIntel, Win32, Linux x86_64
        "canvas_hash": 25.0,         # Deterministic 2D canvas rendering hash
        "user_agent_family": 20.0,   # Browser engine & major family
        "webgl_renderer": 15.0,      # GPU device / unmasked renderer
        "timezone": 15.0,            # IANA Timezone name & offset
        "hardware_concurrency": 10.0,# CPU thread count
        "language": 10.0,            # Primary system/browser language
        "screen": 10.0,              # Resolution & color depth (with tolerance)
        "device_memory": 8.0,        # RAM class (GB)
        "webgl_vendor": 8.0,         # GPU vendor string
    }

    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        "http://localhost:5175",
        "http://127.0.0.1:5175",
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ]

settings = Settings()
