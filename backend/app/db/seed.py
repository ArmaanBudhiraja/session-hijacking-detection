"""
Database Seeding Script.
Ensures baseline demo accounts and initial state exist on startup
so evaluators can log in immediately with demo credentials.
"""
import logging
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.models.user import User
from app.core.security import hash_password

logger = logging.getLogger("app.db.seed")

DEMO_USERS = [
    {
        "username": "student_alice",
        "email": "alice@university.edu",
        "password": "SecurePassword123!",
        "role": "student"
    },
    {
        "username": "security_analyst",
        "email": "analyst@soc-defense.org",
        "password": "AnalystSecure2026!",
        "role": "analyst"
    }
]

def seed_default_users(db: Session = None):
    """Creates default evaluation accounts if they do not already exist."""
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        for user_data in DEMO_USERS:
            existing = db.query(User).filter(
                (User.username == user_data["username"]) | (User.email == user_data["email"].lower())
            ).first()

            if not existing:
                pwd_hash = hash_password(user_data["password"])
                new_user = User(
                    username=user_data["username"],
                    email=user_data["email"].lower(),
                    password_hash=pwd_hash,
                    is_active=True
                )
                db.add(new_user)
                db.commit()
                logger.info(f"Seeded demo account: {user_data['username']}")
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to seed demo accounts: {e}")
    finally:
        if close_db:
            db.close()

if __name__ == "__main__":
    seed_default_users()
    print("Database seeding completed.")
