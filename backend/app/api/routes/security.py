import json
from typing import List, Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.db.session import get_db
from app.models.security_event import SecurityEvent
from app.models.session import SessionModel
from app.models.user import User
from app.schemas.fingerprint import (
    FingerprintVerificationRequest,
    FingerprintVerificationResponse,
    MismatchedAttributeDetail
)
from app.schemas.security_event import SecurityEventOut, SecurityMetrics, ScoreDataPoint, ScenarioCount
from app.schemas.settings import SystemSettingsOut, SystemSettingsUpdate
from app.services.fingerprint_service import normalize_fingerprint
from app.services.decision_engine import compare_fingerprints
from app.api.deps import get_current_session, get_current_user
from app.core.config import settings

router = APIRouter(prefix="/security", tags=["Security & Fingerprinting"])

@router.post("/verify", response_model=FingerprintVerificationResponse)
def verify_session_fingerprint(
    payload: FingerprintVerificationRequest,
    request: Request,
    response: Response,
    current_session: SessionModel = Depends(get_current_session),
    db: Session = Depends(get_db)
):
    """
    Per-request continuous verification endpoint.
    Compares the incoming live browser fingerprint against the session's trusted signature.
    If mismatch exceeds threshold, immediately blocks and revokes the session.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    normalized_current = normalize_fingerprint(payload.fingerprint)
    trusted_fp = current_session.trusted_fingerprint

    # Perform weighted comparison
    result = compare_fingerprints(trusted_fp, normalized_current)

    event_type = "FP_VERIFY_SUCCESS"
    session_status = current_session.status
    message = "Browser fingerprint matches trusted session."

    if result.decision == "BLOCK_REVOKE":
        event_type = "FP_HIJACK_BLOCKED"
        session_status = "revoked"
        message = (
            f"POTENTIAL SESSION HIJACKING DETECTED! Fingerprint mismatch score ({result.mismatch_score}%) "
            f"exceeded threshold ({settings.MISMATCH_REVOKE_THRESHOLD}%). Session has been permanently revoked."
        )
        # Enforce server-side revocation
        current_session.status = "revoked"
        current_session.revocation_reason = f"Hijacking detection: mismatch score {result.mismatch_score}%"
        db.commit()

        # Invalidate client cookies
        response.delete_cookie(key=settings.SESSION_COOKIE_NAME, path="/")
        response.delete_cookie(key=settings.CSRF_COOKIE_NAME, path="/")

    elif result.decision == "CHALLENGE":
        event_type = "FP_MISMATCH_SUSPICIOUS"
        session_status = "flagged"
        current_session.status = "flagged"
        db.commit()
        message = (
            f"Suspicious browser characteristics detected (mismatch: {result.mismatch_score}%). "
            f"Step-up challenge recommended."
        )

    # Record security event in database
    event = SecurityEvent(
        event_type=event_type,
        user_id=current_session.user_id,
        session_id_ref=current_session.id[:8],
        similarity_score=result.similarity_score,
        mismatch_score=result.mismatch_score,
        risk_level=result.risk_level,
        decision=result.decision,
        diagnostic_details={
            "mismatched_attributes": [m.model_dump() for m in result.mismatched_attributes],
            "comparable_attributes_count": result.comparable_attributes_count,
            "decision_metadata": result.diagnostic_details
        },
        client_ip=client_ip
    )
    db.add(event)
    db.commit()

    return FingerprintVerificationResponse(
        valid=(result.decision == "ALLOW"),
        decision=result.decision,
        similarity_score=result.similarity_score,
        mismatch_score=result.mismatch_score,
        risk_level=result.risk_level,
        mismatched_attributes=result.mismatched_attributes,
        comparable_attributes_count=result.comparable_attributes_count,
        message=message,
        session_status=session_status
    )

@router.get("/events", response_model=List[SecurityEventOut])
def get_security_events(
    limit: int = 50,
    offset: int = 0,
    event_type: Optional[str] = None,
    risk_level: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Returns audit trail of security and fingerprint events.
    Safe diagnostic details are included; secret tokens are never exposed.
    """
    query = db.query(SecurityEvent)
    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type)
    if risk_level:
        query = query.filter(SecurityEvent.risk_level == risk_level)

    events = query.order_by(SecurityEvent.timestamp.desc()).offset(offset).limit(limit).all()
    return events

@router.get("/metrics", response_model=SecurityMetrics)
def get_security_metrics(db: Session = Depends(get_db)):
    """
    Aggregates real system metrics from active database tables for the monitoring dashboard.
    """
    total_logins = db.query(SecurityEvent).filter(
        SecurityEvent.event_type.in_(["LOGIN_SUCCESS", "LOGIN_FAILED"])
    ).count()

    active_sessions = db.query(SessionModel).filter(
        SessionModel.status == "active",
        SessionModel.expires_at > datetime.utcnow()
    ).count()

    suspicious_events = db.query(SecurityEvent).filter(
        SecurityEvent.event_type == "FP_MISMATCH_SUSPICIOUS"
    ).count()

    blocked_hijacks = db.query(SecurityEvent).filter(
        SecurityEvent.event_type.in_(["FP_HIJACK_BLOCKED", "REPLAY_ATTACK_SIMULATED"])
    ).count()

    successful_verifications = db.query(SecurityEvent).filter(
        SecurityEvent.event_type == "FP_VERIFY_SUCCESS"
    ).count()

    # Time series of recent scores for Recharts
    recent_events = db.query(SecurityEvent).filter(
        SecurityEvent.similarity_score.isnot(None)
    ).order_by(SecurityEvent.timestamp.desc()).limit(15).all()

    recent_scores = [
        ScoreDataPoint(
            timestamp=e.timestamp.strftime("%H:%M:%S"),
            similarity_score=e.similarity_score,
            mismatch_score=e.mismatch_score,
            event_type=e.event_type,
            decision=e.decision
        )
        for e in reversed(recent_events)
    ]

    # Scenario breakdown counts
    scenarios = [
        ScenarioCount(scenario="Legitimate Logins", count=db.query(SecurityEvent).filter(SecurityEvent.event_type == "LOGIN_SUCCESS").count()),
        ScenarioCount(scenario="Normal Verifications", count=successful_verifications),
        ScenarioCount(scenario="Suspicious Anomalies", count=suspicious_events),
        ScenarioCount(scenario="Hijacks Blocked / Revoked", count=blocked_hijacks),
    ]

    return SecurityMetrics(
        total_logins=total_logins,
        active_sessions=active_sessions,
        suspicious_events=suspicious_events,
        blocked_hijacks=blocked_hijacks,
        successful_verifications=successful_verifications,
        recent_scores=recent_scores,
        scenario_breakdown=scenarios
    )

@router.get("/settings", response_model=SystemSettingsOut)
def get_system_settings():
    """
    Returns current active detection thresholds and session security configurations.
    """
    return SystemSettingsOut(
        app_name=settings.APP_NAME,
        environment=settings.ENVIRONMENT,
        mismatch_flag_threshold=settings.MISMATCH_FLAG_THRESHOLD,
        mismatch_revoke_threshold=settings.MISMATCH_REVOKE_THRESHOLD,
        min_evidence_count=settings.MIN_EVIDENCE_COUNT,
        session_lifetime_seconds=settings.SESSION_LIFETIME_SECONDS,
        attribute_weights=settings.ATTRIBUTE_WEIGHTS,
        cookie_secure=settings.COOKIE_SECURE,
        cookie_samesite=settings.COOKIE_SAMESITE,
        cookie_httponly=settings.COOKIE_HTTPONLY
    )

@router.put("/settings", response_model=SystemSettingsOut)
def update_system_settings(
    payload: SystemSettingsUpdate,
    db: Session = Depends(get_db)
):
    """
    Safely updates runtime detection engine thresholds, evidence minimums, and weights.
    Validates logical invariants (e.g., flag threshold must be <= revoke threshold).
    """
    if payload.mismatch_flag_threshold > payload.mismatch_revoke_threshold:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Suspicious flag threshold cannot exceed automatic revoke threshold."
        )

    settings.MISMATCH_FLAG_THRESHOLD = payload.mismatch_flag_threshold
    settings.MISMATCH_REVOKE_THRESHOLD = payload.mismatch_revoke_threshold
    settings.MIN_EVIDENCE_COUNT = payload.min_evidence_count
    settings.SESSION_LIFETIME_SECONDS = payload.session_lifetime_seconds
    settings.ATTRIBUTE_WEIGHTS = payload.attribute_weights

    # Record configuration update audit event
    event = SecurityEvent(
        event_type="SETTINGS_UPDATED",
        user_id=None,
        session_id_ref=None,
        similarity_score=None,
        mismatch_score=None,
        risk_level="LOW",
        decision="ALLOW",
        diagnostic_details={
            "flag_threshold": settings.MISMATCH_FLAG_THRESHOLD,
            "revoke_threshold": settings.MISMATCH_REVOKE_THRESHOLD,
            "min_evidence": settings.MIN_EVIDENCE_COUNT,
            "lifetime": settings.SESSION_LIFETIME_SECONDS
        },
        client_ip="127.0.0.1"
    )
    db.add(event)
    db.commit()

    return get_system_settings()

@router.post("/settings/reset", response_model=SystemSettingsOut)
def reset_system_settings(db: Session = Depends(get_db)):
    """
    Resets detection thresholds and attribute weights back to baseline research defaults.
    """
    settings.MISMATCH_FLAG_THRESHOLD = 35.0
    settings.MISMATCH_REVOKE_THRESHOLD = 50.0
    settings.MIN_EVIDENCE_COUNT = 5
    settings.SESSION_LIFETIME_SECONDS = 3600
    settings.ATTRIBUTE_WEIGHTS = {
        "platform": 25.0,
        "canvas_hash": 25.0,
        "user_agent_family": 20.0,
        "webgl_renderer": 15.0,
        "timezone": 15.0,
        "hardware_concurrency": 10.0,
        "language": 10.0,
        "screen": 10.0,
        "device_memory": 8.0,
        "webgl_vendor": 8.0,
    }

    event = SecurityEvent(
        event_type="SETTINGS_RESET",
        user_id=None,
        session_id_ref=None,
        similarity_score=None,
        mismatch_score=None,
        risk_level="LOW",
        decision="ALLOW",
        diagnostic_details={"action": "reset_to_academic_defaults"},
        client_ip="127.0.0.1"
    )
    db.add(event)
    db.commit()

    return get_system_settings()

