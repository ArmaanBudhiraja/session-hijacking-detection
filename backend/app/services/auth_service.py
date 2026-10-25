from typing import Optional
from sqlalchemy.orm import Session
from app.models.user import User
from app.schemas.auth import UserRegister
from app.core.security import hash_password, verify_password

def get_user_by_username(db: Session, username: str) -> Optional[User]:
    return db.query(User).filter(User.username == username).first()

def get_user_by_email(db: Session, email: str) -> Optional[User]:
    return db.query(User).filter(User.email == email.lower()).first()

def get_user_by_id(db: Session, user_id: str) -> Optional[User]:
    return db.query(User).filter(User.id == user_id).first()

def register_user(db: Session, user_in: UserRegister) -> User:
    """Creates a new user record with Argon2id password hashing."""
    pwd_hash = hash_password(user_in.password)
    db_user = User(
        username=user_in.username,
        email=user_in.email.lower(),
        password_hash=pwd_hash,
        is_active=True
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def authenticate_user(db: Session, username_or_email: str, password: str) -> Optional[User]:
    """Authenticates credentials against the stored Argon2id hash."""
    user = get_user_by_username(db, username_or_email)
    if not user:
        user = get_user_by_email(db, username_or_email)
    if not user:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user
