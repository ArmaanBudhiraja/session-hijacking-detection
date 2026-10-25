import uuid
import json
from datetime import datetime
from typing import Dict, Any, Optional
from sqlalchemy import Column, String, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.db.session import Base

class SessionModel(Base):
    __tablename__ = "sessions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String(64), unique=True, index=True, nullable=False)
    trusted_fingerprint_json = Column(Text, nullable=False)
    trusted_fingerprint_hash = Column(String(64), index=True, nullable=False)
    user_agent_summary = Column(String(255), nullable=True)
    client_ip = Column(String(45), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_activity = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    status = Column(String(20), default="active", nullable=False, index=True) # active, flagged, revoked, expired
    revocation_reason = Column(String(255), nullable=True)
    is_demo = Column(Boolean, default=False, nullable=False)

    user = relationship("User", back_populates="sessions")

    @property
    def trusted_fingerprint(self) -> Dict[str, Any]:
        """Parses stored JSON into dictionary."""
        try:
            return json.loads(self.trusted_fingerprint_json)
        except Exception:
            return {}

    @trusted_fingerprint.setter
    def trusted_fingerprint(self, value: Dict[str, Any]):
        self.trusted_fingerprint_json = json.dumps(value, sort_keys=True)

    @property
    def is_expired(self) -> bool:
        return datetime.utcnow() >= self.expires_at

    @property
    def is_valid(self) -> bool:
        return self.status == "active" and not self.is_expired
