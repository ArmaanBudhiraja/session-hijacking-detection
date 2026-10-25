from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.user import User
from app.models.session import SessionModel
from app.models.security_event import SecurityEvent
from app.schemas.auth import FingerprintPayload
from app.schemas.fingerprint import FingerprintVerificationResponse
from app.services.fingerprint_service import normalize_fingerprint
from app.services.decision_engine import compare_fingerprints
from app.services.session_service import create_session, get_session_by_token
from app.core.security import hash_password, hash_session_token

router = APIRouter(prefix="/demo", tags=["Attack Simulation Lab"])

class CreateDemoSessionRequest(BaseModel):
    client_name: str = "Legitimate Student Browser"
    fingerprint: FingerprintPayload

class SimulateReplayRequest(BaseModel):
    session_token: str = Field(..., description="The stolen session token being replayed by attacker")
    attacker_fingerprint: FingerprintPayload

class VerifyRevocationRequest(BaseModel):
    session_token: str

@router.post("/create-session")
def create_demo_session(
    payload: CreateDemoSessionRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Step 1 & 2 of Simulation:
    Creates a dedicated demo user (if not already existing) and initializes
    a legitimate session bound to the provided baseline browser fingerprint.
    Returns the session token for the interactive lab.
    """
    demo_user = db.query(User).filter(User.username == "demo_victim").first()
    if not demo_user:
        demo_user = User(
            username="demo_victim",
            email="demo_victim@session-defense.local",
            password_hash=hash_password("LegitimateUser2026!"),
            is_active=True
        )
        db.add(demo_user)
        db.commit()
        db.refresh(demo_user)

    normalized_fp = normalize_fingerprint(payload.fingerprint)
    client_ip = request.client.host if request.client else "127.0.0.1"

    session_obj, raw_token = create_session(
        db=db,
        user_id=demo_user.id,
        normalized_fp=normalized_fp,
        raw_user_agent=payload.fingerprint.user_agent,
        client_ip=client_ip,
        is_demo=True
    )

    # Log initial demo event
    event = SecurityEvent(
        event_type="LOGIN_SUCCESS",
        user_id=demo_user.id,
        session_id_ref=session_obj.id[:8],
        similarity_score=100.0,
        mismatch_score=0.0,
        risk_level="LOW",
        decision="ALLOW",
        diagnostic_details={
            "scenario": "SIMULATION_INIT",
            "description": "Baseline legitimate session created for live demonstration",
            "fingerprint_summary": f"{normalized_fp.get('user_agent_family')} on {normalized_fp.get('platform')}"
        },
        client_ip=client_ip
    )
    db.add(event)
    db.commit()

    return {
        "message": "Demo session initialized with baseline fingerprint.",
        "session_id": session_obj.id,
        "session_token": raw_token,
        "trusted_fingerprint": normalized_fp,
        "status": session_obj.status,
        "expires_at": session_obj.expires_at
    }

@router.post("/normal-verification", response_model=FingerprintVerificationResponse)
def normal_verification(
    payload: CreateDemoSessionRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Scenario B: Same Browser, Subsequent Request
    Simulates a legitimate user visiting a protected endpoint with their original browser context.
    Demonstrates ~100% similarity and ALLOW decision.
    """
    demo_session = db.query(SessionModel).filter(
        SessionModel.is_demo == True,
        SessionModel.status == "active"
    ).order_by(SessionModel.created_at.desc()).first()

    if not demo_session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active demo session found. Please initialize a demo session first."
        )

    normalized_current = normalize_fingerprint(payload.fingerprint)
    result = compare_fingerprints(demo_session.trusted_fingerprint, normalized_current)

    client_ip = request.client.host if request.client else "127.0.0.1"
    event = SecurityEvent(
        event_type="FP_VERIFY_SUCCESS",
        user_id=demo_session.user_id,
        session_id_ref=demo_session.id[:8],
        similarity_score=result.similarity_score,
        mismatch_score=result.mismatch_score,
        risk_level=result.risk_level,
        decision=result.decision,
        diagnostic_details={
            "scenario": "LEGITIMATE_NORMAL_VERIFICATION",
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
        message="Legitimate request verified: Device context strictly matches trusted session.",
        session_status=demo_session.status
    )

@router.post("/simulate-replay", response_model=FingerprintVerificationResponse)
def simulate_session_replay(
    payload: SimulateReplayRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Scenario D: Stolen Session Cookie Replay
    Exercises the actual backend detection logic against an attacker who acquired
    a valid session cookie but presents a different browser/device context.
    Detects mismatch, calculates risk, blocks request, and REVOKES the session.
    """
    token_hash = hash_session_token(payload.session_token)
    session_obj = db.query(SessionModel).filter(SessionModel.token_hash == token_hash).first()

    if not session_obj:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Replayed session token does not exist in active session store."
        )

    if session_obj.status == "revoked":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Replay rejected: Session is already REVOKED ({session_obj.revocation_reason})"
        )

    # Normalize incoming attacker fingerprint
    attacker_fp = normalize_fingerprint(payload.attacker_fingerprint)
    trusted_fp = session_obj.trusted_fingerprint

    # Real backend comparator evaluation
    result = compare_fingerprints(trusted_fp, attacker_fp)

    client_ip = request.client.host if request.client else "127.0.0.1"

    # Revoke session immediately upon critical mismatch
    if result.decision == "BLOCK_REVOKE":
        session_obj.status = "revoked"
        session_obj.revocation_reason = (
            f"Automated Hijack Defense: Mismatch score of {result.mismatch_score}% "
            f"detected during simulated session replay"
        )
        db.commit()

    event = SecurityEvent(
        event_type="REPLAY_ATTACK_SIMULATED",
        user_id=session_obj.user_id,
        session_id_ref=session_obj.id[:8],
        similarity_score=result.similarity_score,
        mismatch_score=result.mismatch_score,
        risk_level=result.risk_level,
        decision=result.decision,
        diagnostic_details={
            "scenario": "STOLEN_COOKIE_REPLAY_ATTACK",
            "attacker_platform": attacker_fp.get("platform"),
            "trusted_platform": trusted_fp.get("platform"),
            "mismatched_attributes": [m.model_dump() for m in result.mismatched_attributes],
            "action_taken": "SESSION_REVOKED" if result.decision == "BLOCK_REVOKE" else "FLAGGED"
        },
        client_ip=client_ip
    )
    db.add(event)
    db.commit()

    return FingerprintVerificationResponse(
        valid=False,
        decision=result.decision,
        similarity_score=result.similarity_score,
        mismatch_score=result.mismatch_score,
        risk_level=result.risk_level,
        mismatched_attributes=result.mismatched_attributes,
        comparable_attributes_count=result.comparable_attributes_count,
        message=(
            f"ATTACK DETECTED! Stolen cookie replay from anomalous client context. "
            f"Mismatch score: {result.mismatch_score}%. Session {session_obj.id[:8]} has been REVOKED."
        ),
        session_status=session_obj.status
    )

@router.post("/verify-revocation")
def verify_revocation(
    payload: VerifyRevocationRequest,
    db: Session = Depends(get_db)
):
    """
    Scenario E: Validates that once revoked, subsequent requests using the stolen
    cookie token are completely denied by the server-side session validator.
    """
    token_hash = hash_session_token(payload.session_token)
    session_obj = db.query(SessionModel).filter(SessionModel.token_hash == token_hash).first()

    if not session_obj:
        return {
            "revoked": True,
            "status": "not_found",
            "access_granted": False,
            "message": "Token unrecognized."
        }

    return {
        "revoked": (session_obj.status == "revoked"),
        "status": session_obj.status,
        "access_granted": False if session_obj.status == "revoked" else session_obj.is_valid,
        "revocation_reason": session_obj.revocation_reason,
        "message": (
            "Session is permanently invalidated. Attacker and victim can no longer "
            "use this cookie token without re-authenticating."
            if session_obj.status == "revoked"
            else "Session is still active."
        )
    }
