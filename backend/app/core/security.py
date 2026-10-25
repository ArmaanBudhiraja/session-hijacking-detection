import secrets
import hashlib
from typing import Tuple
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

# Argon2id password hasher with secure parameters
ph = PasswordHasher(
    time_cost=2,
    memory_cost=65536,  # 64 MB
    parallelism=2,
    hash_len=32,
    salt_len=16
)

def hash_password(password: str) -> str:
    """Hashes a plaintext password using Argon2id."""
    return ph.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plaintext password against an Argon2id hash."""
    try:
        return ph.verify(hashed_password, plain_password)
    except (VerifyMismatchError, InvalidHashError):
        return False

def generate_session_token() -> str:
    """Generates a high-entropy cryptographically secure random session token."""
    return secrets.token_urlsafe(32)

def hash_session_token(token: str) -> str:
    """
    Computes SHA-256 hash of the session token.
    The database only stores this hash, never the raw cookie value,
    protecting against database leak compromise.
    """
    return hashlib.sha256(token.encode('utf-8')).hexdigest()

def generate_csrf_token() -> str:
    """Generates a CSRF token for state-changing operations."""
    return secrets.token_hex(24)

def safe_fingerprint_hash(payload_str: str) -> str:
    """Computes a deterministic SHA-256 signature of canonicalized fingerprint attributes."""
    return hashlib.sha256(payload_str.encode('utf-8')).hexdigest()
