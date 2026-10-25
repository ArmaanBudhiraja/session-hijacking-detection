from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from app.schemas.auth import FingerprintPayload

class FingerprintVerificationRequest(BaseModel):
    fingerprint: FingerprintPayload

class MismatchedAttributeDetail(BaseModel):
    attribute: str
    category: str
    weight: float
    expected: Any
    actual: Any
    reason: str

class FingerprintVerificationResponse(BaseModel):
    valid: bool
    decision: str  # "ALLOW", "CHALLENGE", "BLOCK_REVOKE"
    similarity_score: float
    mismatch_score: float
    risk_level: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    mismatched_attributes: List[MismatchedAttributeDetail] = []
    comparable_attributes_count: int
    message: str
    session_status: str

class FingerprintComparisonResult(BaseModel):
    similarity_score: float
    mismatch_score: float
    risk_level: str
    decision: str
    mismatched_attributes: List[MismatchedAttributeDetail]
    comparable_attributes_count: int
    total_weights_evaluated: float
    diagnostic_details: Dict[str, Any]
