from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.user import User
from app.models.session import SessionModel
from app.models.security_event import SecurityEvent
from app.schemas.session import SessionOut, SessionRevokeRequest
from app.services.session_service import list_user_sessions, revoke_session
from app.api.deps import get_current_user, get_current_session

router = APIRouter(prefix="/sessions", tags=["Session Management"])

@router.get("", response_model=List[SessionOut])
def get_my_sessions(
    current_user: User = Depends(get_current_user),
    current_session: SessionModel = Depends(get_current_session),
    db: Session = Depends(get_db)
):
    """
    Returns all sessions registered for the authenticated user.
    Cross-user isolation is strictly enforced.
    """
    sessions = list_user_sessions(db, current_user.id)
    out = []
    for s in sessions:
        trusted = s.trusted_fingerprint
        safe_fp = {
            "platform": trusted.get("platform", "Unknown"),
            "user_agent_family": trusted.get("user_agent_family", "Browser"),
            "timezone": trusted.get("timezone", "N/A"),
            "fingerprint_hash": s.trusted_fingerprint_hash[:12] + "..."
        }
        item = SessionOut(
            id=s.id,
            user_id=s.user_id,
            user_agent_summary=s.user_agent_summary,
            client_ip=s.client_ip,
            created_at=s.created_at,
            last_activity=s.last_activity,
            expires_at=s.expires_at,
            status=s.status,
            is_current=(s.id == current_session.id),
            is_demo=s.is_demo,
            revocation_reason=s.revocation_reason,
            trusted_fingerprint_summary=safe_fp
        )
        out.append(item)
    return out

@router.post("/{session_id}/revoke", response_model=SessionOut)
def revoke_specific_session(
    session_id: str,
    revoke_req: SessionRevokeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Allows a user to revoke any of their active sessions.
    Strictly verifies session ownership before revocation.
    """
    target = db.query(SessionModel).filter(SessionModel.id == session_id).first()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found."
        )

    # Authorization check: Prevent cross-user session tampering
    if target.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: You can only manage your own sessions."
        )

    revoked = revoke_session(db, session_id, reason=revoke_req.reason or "Manual revocation by user")

    # Record security audit event
    event = SecurityEvent(
        event_type="SESSION_REVOKED",
        user_id=current_user.id,
        session_id_ref=session_id[:8],
        similarity_score=None,
        mismatch_score=None,
        risk_level="LOW",
        decision="BLOCK_REVOKE",
        diagnostic_details={"reason": revoke_req.reason or "Manual revocation"},
        client_ip=target.client_ip
    )
    db.add(event)
    db.commit()

    trusted = revoked.trusted_fingerprint
    safe_fp = {
        "platform": trusted.get("platform", "Unknown"),
        "user_agent_family": trusted.get("user_agent_family", "Browser"),
        "timezone": trusted.get("timezone", "N/A"),
        "fingerprint_hash": revoked.trusted_fingerprint_hash[:12] + "..."
    }

    return SessionOut(
        id=revoked.id,
        user_id=revoked.user_id,
        user_agent_summary=revoked.user_agent_summary,
        client_ip=revoked.client_ip,
        created_at=revoked.created_at,
        last_activity=revoked.last_activity,
        expires_at=revoked.expires_at,
        status=revoked.status,
        is_current=False,
        is_demo=revoked.is_demo,
        revocation_reason=revoked.revocation_reason,
        trusted_fingerprint_summary=safe_fp
    )
