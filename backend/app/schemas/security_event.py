from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, ConfigDict

class SecurityEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    timestamp: datetime
    event_type: str
    user_id: Optional[str]
    session_id_ref: Optional[str]
    similarity_score: Optional[float]
    mismatch_score: Optional[float]
    risk_level: str
    decision: str
    diagnostic_details: Optional[Dict[str, Any]] = None
    client_ip: Optional[str] = None

class ScoreDataPoint(BaseModel):
    timestamp: str
    similarity_score: float
    mismatch_score: float
    event_type: str
    decision: str

class ScenarioCount(BaseModel):
    scenario: str
    count: int

class SecurityMetrics(BaseModel):
    total_logins: int
    active_sessions: int
    suspicious_events: int
    blocked_hijacks: int
    successful_verifications: int
    recent_scores: List[ScoreDataPoint]
    scenario_breakdown: List[ScenarioCount]
