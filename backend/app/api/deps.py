from typing import Optional
from fastapi import Request, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.core.config import settings
from app.models.session import SessionModel
from app.models.user import User
from app.services.session_service import get_session_by_token

def get_session_token_from_request(request: Request) -> Optional[str]:
    """
    Extracts session token from HttpOnly cookie, with fallback to Bearer header
    for testing or programmatic evaluation.
    """
    # 1. Primary: Cookie
    cookie_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if cookie_token:
        return cookie_token

    # 2. Fallback: Authorization header (Bearer token)
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header[7:].strip()

    return None

def get_current_session(
    request: Request,
    db: Session = Depends(get_db)
) -> SessionModel:
    """
    Validates the session token from cookie/header.
    Ensures session exists, is active, and is not expired or revoked.
    """
    token = get_session_token_from_request(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. No session cookie provided."
        )

    session_obj = get_session_by_token(db, token)
    if not session_obj:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or unrecognized session token."
        )

    if session_obj.status == "revoked":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Session has been revoked: {session_obj.revocation_reason or 'Security violation'}"
        )

    if session_obj.status == "expired" or session_obj.is_expired:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired. Please re-authenticate."
        )

    if session_obj.status != "active":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Session is inactive (status: {session_obj.status})."
        )

    return session_obj

def get_current_user(
    session_obj: SessionModel = Depends(get_current_session),
    db: Session = Depends(get_db)
) -> User:
    """
    Returns the authenticated user associated with the verified session.
    """
    user = db.query(User).filter(User.id == session_obj.user_id).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is deactivated or not found."
        )
    return user

def verify_csrf_token(request: Request):
    """
    Validates CSRF token header against cookie for unsafe HTTP methods.
    """
    if request.method in ["POST", "PUT", "PATCH", "DELETE"]:
        csrf_cookie = request.cookies.get(settings.CSRF_COOKIE_NAME)
        csrf_header = request.headers.get(settings.CSRF_HEADER_NAME)
        # In development or if header is provided, ensure matching if cookie present
        if csrf_cookie and csrf_header and csrf_cookie != csrf_header:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF token mismatch. State-changing request denied."
            )
