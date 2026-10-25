from typing import Dict
from pydantic import BaseModel, Field

class SystemSettingsOut(BaseModel):
    app_name: str
    environment: str
    mismatch_flag_threshold: float = Field(..., ge=0.0, le=100.0)
    mismatch_revoke_threshold: float = Field(..., ge=0.0, le=100.0)
    min_evidence_count: int = Field(..., ge=1, le=10)
    session_lifetime_seconds: int = Field(..., ge=60, le=86400)
    attribute_weights: Dict[str, float]
    cookie_secure: bool
    cookie_samesite: str
    cookie_httponly: bool

class SystemSettingsUpdate(BaseModel):
    mismatch_flag_threshold: float = Field(..., ge=0.0, le=100.0, description="Mismatch threshold to flag/challenge session")
    mismatch_revoke_threshold: float = Field(..., ge=0.0, le=100.0, description="Mismatch threshold to permanently revoke session")
    min_evidence_count: int = Field(..., ge=1, le=10, description="Minimum number of comparable attributes")
    session_lifetime_seconds: int = Field(..., ge=60, le=86400, description="Session lifespan in seconds")
    attribute_weights: Dict[str, float] = Field(..., description="Weights assigned to individual fingerprint dimensions")
