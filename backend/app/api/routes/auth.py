import json
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.core.config import settings
from app.core.security import generate_csrf_token
from app.models.user import User
from app.models.security_event import SecurityEvent
from app.schemas.auth import UserRegister, UserLogin, UserOut, AuthResponse
from app.services.auth_service import register_user, authenticate_user, get_user_by_username, get_user_by_email
from app.services.session_service import create_session, revoke_session_by_token
from app.services.fingerprint_service import normalize_fingerprint
from app.api.deps import get_current_session, get_current_user, get_session_token_from_request

router = APIRouter(prefix="/auth", tags=["Authentication"])

def set_auth_cookies(response: Response, raw_token: str, csrf_token: str):
    """Configures secure cookie headers for session and CSRF protection."""
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=raw_token,
        httponly=settings.COOKIE_HTTPONLY,
        samesite=settings.COOKIE_SAMESITE,
        secure=settings.COOKIE_SECURE,
        max_age=settings.SESSION_LIFETIME_SECONDS,
        path="/"
    )
    # CSRF cookie is readable by frontend Javascript to send back in header
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=csrf_token,
        httponly=False,
        samesite=settings.COOKIE_SAMESITE,
        secure=settings.COOKIE_SECURE,
        max_age=settings.SESSION_LIFETIME_SECONDS,
        path="/"
    )

def clear_auth_cookies(response: Response):
    """Deletes authentication cookies from the client browser."""
    response.delete_cookie(key=settings.SESSION_COOKIE_NAME, path="/")
    response.delete_cookie(key=settings.CSRF_COOKIE_NAME, path="/")

@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
def register(
    user_in: UserRegister,
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """
    Registers a new user account, captures initial baseline browser fingerprint,
    binds it to a newly created session, and returns authentication cookies.
    """
    if get_user_by_username(db, user_in.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username is already registered."
        )
    if get_user_by_email(db, user_in.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email address is already registered."
        )

    # 1. Create User
    user = register_user(db, user_in)

    # 2. Normalize and bind baseline fingerprint
    normalized_fp = normalize_fingerprint(user_in.fingerprint)
    client_ip = request.client.host if request.client else "127.0.0.1"
    session_obj, raw_token = create_session(
        db=db,
        user_id=user.id,
        normalized_fp=normalized_fp,
        raw_user_agent=user_in.fingerprint.user_agent,
        client_ip=client_ip
    )

    # 3. Security Event Log
    csrf_token = generate_csrf_token()
    event = SecurityEvent(
        event_type="LOGIN_SUCCESS",
        user_id=user.id,
        session_id_ref=session_obj.id[:8],
        similarity_score=100.0,
        mismatch_score=0.0,
        risk_level="LOW",
        decision="ALLOW",
        diagnostic_details={
            "action": "registration_and_initial_session_binding",
            "platform": normalized_fp.get("platform"),
            "user_agent_family": normalized_fp.get("user_agent_family"),
            "fingerprint_hash": session_obj.trusted_fingerprint_hash[:16] + "..."
        },
        client_ip=client_ip
    )
    db.add(event)
    db.commit()

    # 4. Set Cookies
    set_auth_cookies(response, raw_token, csrf_token)

    return AuthResponse(
        message="User registered and logged in successfully.",
        user=UserOut.model_validate(user),
        csrf_token=csrf_token,
        session_id=session_obj.id
    )

@router.post("/login", response_model=AuthResponse)
def login(
    credentials: UserLogin,
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """
    Validates user credentials, records the current browser fingerprint as the trusted signature,
    issues a server-side session, and sets authentication cookies.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    user = authenticate_user(db, credentials.username_or_email, credentials.password)

    if not user:
        # Log failed attempt
        event = SecurityEvent(
            event_type="LOGIN_FAILED",
            user_id=None,
            session_id_ref=None,
            similarity_score=None,
            mismatch_score=None,
            risk_level="MEDIUM",
            decision="BLOCK_REVOKE",
            diagnostic_details={
                "attempted_user": credentials.username_or_email[:3] + "***",
                "reason": "Invalid credentials"
            },
            client_ip=client_ip
        )
        db.add(event)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password."
        )

    # Normalize fingerprint & create new session bound to this fingerprint
    normalized_fp = normalize_fingerprint(credentials.fingerprint)
    session_obj, raw_token = create_session(
        db=db,
        user_id=user.id,
        normalized_fp=normalized_fp,
        raw_user_agent=credentials.fingerprint.user_agent,
        client_ip=client_ip
    )

    csrf_token = generate_csrf_token()

    event = SecurityEvent(
        event_type="LOGIN_SUCCESS",
        user_id=user.id,
        session_id_ref=session_obj.id[:8],
        similarity_score=100.0,
        mismatch_score=0.0,
        risk_level="LOW",
        decision="ALLOW",
        diagnostic_details={
            "action": "authenticated_login",
            "platform": normalized_fp.get("platform"),
            "user_agent_family": normalized_fp.get("user_agent_family"),
            "fingerprint_hash": session_obj.trusted_fingerprint_hash[:16] + "..."
        },
        client_ip=client_ip
    )
    db.add(event)
    db.commit()

    set_auth_cookies(response, raw_token, csrf_token)

    return AuthResponse(
        message="Authentication successful.",
        user=UserOut.model_validate(user),
        csrf_token=csrf_token,
        session_id=session_obj.id
    )

@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """
    Revokes the current session and clears client authentication cookies.
    """
    token = get_session_token_from_request(request)
    if token:
        revoke_session_by_token(db, token, reason="User initiated logout")
    clear_auth_cookies(response)
    return {"message": "Logged out successfully."}

@router.get("/me")
def get_current_user_profile(
    current_user: User = Depends(get_current_user),
    current_session = Depends(get_current_session)
):
    """
    Restores user session state on page refresh.
    Returns safe user profile and summary of trusted session fingerprint.
    """
    trusted_fp = current_session.trusted_fingerprint
    safe_fp_summary = {
        "platform": trusted_fp.get("platform"),
        "user_agent_family": trusted_fp.get("user_agent_family"),
        "timezone": trusted_fp.get("timezone"),
        "language": trusted_fp.get("language"),
        "screen": f"{trusted_fp.get('screen', {}).get('width', 0)}x{trusted_fp.get('screen', {}).get('height', 0)}" if trusted_fp.get('screen') else "N/A",
        "canvas_hash_preview": current_session.trusted_fingerprint_hash[:16] + "..." if current_session.trusted_fingerprint_hash else "N/A",
        "hardware_concurrency": trusted_fp.get("hardware_concurrency"),
        "device_memory": f"{trusted_fp.get('device_memory')} GB" if trusted_fp.get('device_memory') else "N/A"
    }

    return {
        "user": UserOut.model_validate(current_user),
        "session": {
            "id": current_session.id,
            "status": current_session.status,
            "created_at": current_session.created_at,
            "expires_at": current_session.expires_at,
            "last_activity": current_session.last_activity,
            "user_agent_summary": current_session.user_agent_summary,
            "trusted_fingerprint_summary": safe_fp_summary
        }
    }
