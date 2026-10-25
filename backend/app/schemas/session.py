from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, ConfigDict

class SessionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: str
    user_agent_summary: Optional[str]
    client_ip: Optional[str]
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    status: str
    is_current: bool = False
    is_demo: bool = False
    revocation_reason: Optional[str] = None
    trusted_fingerprint_summary: Optional[Dict[str, Any]] = None

class SessionRevokeRequest(BaseModel):
    reason: Optional[str] = "Manual user revocation"
