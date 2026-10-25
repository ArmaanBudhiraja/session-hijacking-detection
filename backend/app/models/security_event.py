import uuid
import json
from datetime import datetime
from typing import Dict, Any, Optional
from sqlalchemy import Column, String, DateTime, Float, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.db.session import Base

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    event_type = Column(String(50), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    session_id_ref = Column(String(64), nullable=True, index=True)
    similarity_score = Column(Float, nullable=True)
    mismatch_score = Column(Float, nullable=True)
    risk_level = Column(String(20), default="LOW", nullable=False, index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    decision = Column(String(20), default="ALLOW", nullable=False)              # ALLOW, CHALLENGE, BLOCK_REVOKE
    diagnostic_details_json = Column(Text, nullable=True)
    client_ip = Column(String(45), nullable=True)

    user = relationship("User", back_populates="security_events")

    @property
    def diagnostic_details(self) -> Dict[str, Any]:
        if not self.diagnostic_details_json:
            return {}
        try:
            return json.loads(self.diagnostic_details_json)
        except Exception:
            return {}

    @diagnostic_details.setter
    def diagnostic_details(self, value: Dict[str, Any]):
        self.diagnostic_details_json = json.dumps(value, sort_keys=True)
