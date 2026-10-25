from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, ConfigDict

class ScreenAttributes(BaseModel):
    width: int
    height: int
    color_depth: int = 24
    pixel_ratio: float = 1.0

class FingerprintPayload(BaseModel):
    user_agent: str = Field(..., description="Browser raw user agent string")
    user_agent_family: Optional[str] = Field(None, description="Normalized browser name (Chrome, Firefox, Safari, Edge)")
    platform: Optional[str] = Field(None, description="Operating system platform (MacIntel, Win32, Linux, etc.)")
    language: Optional[str] = Field(None, description="Primary language e.g. en-US")
    languages: Optional[List[str]] = Field(default_factory=list, description="Preferred language list")
    timezone: Optional[str] = Field(None, description="IANA Timezone name e.g. America/New_York, Asia/Kolkata")
    timezone_offset: Optional[int] = Field(None, description="Timezone offset in minutes")
    screen: Optional[ScreenAttributes] = Field(None, description="Display resolution and color depth")
    hardware_concurrency: Optional[int] = Field(None, description="CPU logical cores")
    device_memory: Optional[float] = Field(None, description="RAM in GB")
    canvas_hash: Optional[str] = Field(None, description="Deterministic 2D canvas drawing SHA-256 hash")
    webgl_vendor: Optional[str] = Field(None, description="WebGL GPU vendor")
    webgl_renderer: Optional[str] = Field(None, description="WebGL unmasked GPU renderer")
    audio_fingerprint: Optional[str] = Field(None, description="AudioContext oscillator signature hash")

class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    fingerprint: FingerprintPayload

class UserLogin(BaseModel):
    username_or_email: str
    password: str
    fingerprint: FingerprintPayload

class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    email: str
    is_active: bool
    created_at: datetime

class AuthResponse(BaseModel):
    message: str
    user: UserOut
    csrf_token: str
    session_id: str
