import json
from datetime import datetime, timedelta
from typing import Tuple, Optional, List, Dict, Any
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.security import generate_session_token, hash_session_token
from app.models.session import SessionModel
from app.services.fingerprint_service import generate_canonical_hash

def create_session(
    db: Session,
    user_id: str,
    normalized_fp: Dict[str, Any],
    raw_user_agent: str,
    client_ip: Optional[str] = None,
    is_demo: bool = False
) -> Tuple[SessionModel, str]:
    """
    Creates a new server-side authenticated session.
    Stores the SHA-256 hash of the session token and the trusted canonical fingerprint.
    Returns the database session object and the raw token to set in the HttpOnly cookie.
    """
    raw_token = generate_session_token()
    token_hash = hash_session_token(raw_token)
    fp_hash = generate_canonical_hash(normalized_fp)

    ua_summary = f"{normalized_fp.get('user_agent_family', 'Browser')} on {normalized_fp.get('platform', 'OS')}"
    now = datetime.utcnow()
    expires_at = now + timedelta(seconds=settings.SESSION_LIFETIME_SECONDS)

    db_session = SessionModel(
        user_id=user_id,
        token_hash=token_hash,
        trusted_fingerprint_json=json.dumps(normalized_fp, sort_keys=True),
        trusted_fingerprint_hash=fp_hash,
        user_agent_summary=ua_summary,
        client_ip=client_ip,
        created_at=now,
        last_activity=now,
        expires_at=expires_at,
        status="active",
        is_demo=is_demo
    )
    db.add(db_session)
    db.commit()
    db.refresh(db_session)
    return db_session, raw_token

def get_session_by_token(db: Session, raw_token: str) -> Optional[SessionModel]:
    """
    Looks up a session by hashing the provided raw cookie token.
    Never searches or compares plaintext tokens directly.
    Checks and updates expiration status.
    """
    if not raw_token:
        return None

    token_hash = hash_session_token(raw_token)
    session_obj = db.query(SessionModel).filter(SessionModel.token_hash == token_hash).first()
    if not session_obj:
        return None

    # Check expiration
    if session_obj.status == "active" and session_obj.is_expired:
        session_obj.status = "expired"
        session_obj.revocation_reason = "Session expired by timeout policy"
        db.commit()
        db.refresh(session_obj)

    # Update last activity if active
    if session_obj.status == "active":
        session_obj.last_activity = datetime.utcnow()
        db.commit()

    return session_obj

def revoke_session(db: Session, session_id: str, reason: str = "Administrative revocation") -> Optional[SessionModel]:
    """
    Revokes an active session immediately, neutralizing any stolen token.
    """
    session_obj = db.query(SessionModel).filter(SessionModel.id == session_id).first()
    if session_obj:
        session_obj.status = "revoked"
        session_obj.revocation_reason = reason
        db.commit()
        db.refresh(session_obj)
    return session_obj

def revoke_session_by_token(db: Session, raw_token: str, reason: str = "Security policy violation") -> Optional[SessionModel]:
    """
    Revokes the session corresponding to the given raw token.
    """
    if not raw_token:
        return None
    token_hash = hash_session_token(raw_token)
    session_obj = db.query(SessionModel).filter(SessionModel.token_hash == token_hash).first()
    if session_obj:
        session_obj.status = "revoked"
        session_obj.revocation_reason = reason
        db.commit()
        db.refresh(session_obj)
    return session_obj

def list_user_sessions(db: Session, user_id: str) -> List[SessionModel]:
    """
    Lists all sessions associated with a specific user.
    """
    return db.query(SessionModel).filter(
        SessionModel.user_id == user_id
    ).order_by(SessionModel.created_at.desc()).all()
