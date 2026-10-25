import pytest
from datetime import datetime, timedelta
from app.models.session import SessionModel
from app.models.security_event import SecurityEvent
from app.services.decision_engine import compare_fingerprints
from app.services.fingerprint_service import normalize_fingerprint

# 1. Successful registration
def test_successful_registration(client, sample_fingerprint):
    resp = client.post("/api/auth/register", json={
        "username": "student_alice",
        "email": "alice@university.edu",
        "password": "SecurePassword123!",
        "fingerprint": sample_fingerprint
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["user"]["username"] == "student_alice"
    assert "session_id" in data
    assert "sid" in resp.cookies
    assert "csrf_token" in resp.cookies

# 2. Duplicate registration
def test_duplicate_registration_prevention(client, sample_fingerprint):
    resp = client.post("/api/auth/register", json={
        "username": "student_alice",
        "email": "alice_alt@university.edu",
        "password": "SecurePassword123!",
        "fingerprint": sample_fingerprint
    })
    assert resp.status_code == 400
    assert "already registered" in resp.json()["message"]

# 3. Successful login
def test_successful_login(client, sample_fingerprint):
    resp = client.post("/api/auth/login", json={
        "username_or_email": "student_alice",
        "password": "SecurePassword123!",
        "fingerprint": sample_fingerprint
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["user"]["username"] == "student_alice"
    assert "sid" in resp.cookies

# 4. Invalid credentials
def test_invalid_credentials_rejected(client, sample_fingerprint):
    resp = client.post("/api/auth/login", json={
        "username_or_email": "student_alice",
        "password": "WrongPassword999!",
        "fingerprint": sample_fingerprint
    })
    assert resp.status_code == 401
    assert "Incorrect" in resp.json()["message"]

# 5. Successful protected request
def test_successful_protected_me_request(client, sample_fingerprint):
    # Log in first
    login_resp = client.post("/api/auth/login", json={
        "username_or_email": "student_alice",
        "password": "SecurePassword123!",
        "fingerprint": sample_fingerprint
    })
    cookies = login_resp.cookies
    me_resp = client.get("/api/auth/me", cookies=cookies)
    assert me_resp.status_code == 200
    me_data = me_resp.json()
    assert me_data["user"]["username"] == "student_alice"
    assert me_data["session"]["status"] == "active"

# 6. Valid fingerprint comparison
def test_valid_fingerprint_comparison(client, sample_fingerprint):
    login_resp = client.post("/api/auth/login", json={
        "username_or_email": "student_alice",
        "password": "SecurePassword123!",
        "fingerprint": sample_fingerprint
    })
    cookies = login_resp.cookies

    # Send exact or similar fingerprint
    verify_resp = client.post("/api/security/verify", cookies=cookies, json={
        "fingerprint": sample_fingerprint
    })
    assert verify_resp.status_code == 200
    data = verify_resp.json()
    assert data["valid"] is True
    assert data["decision"] == "ALLOW"
    assert data["similarity_score"] == 100.0
    assert data["mismatch_score"] == 0.0

# 7. Mismatched fingerprint detection & revocation
def test_mismatched_fingerprint_detection(client, sample_fingerprint, attacker_fingerprint):
    login_resp = client.post("/api/auth/login", json={
        "username_or_email": "student_alice",
        "password": "SecurePassword123!",
        "fingerprint": sample_fingerprint
    })
    cookies = login_resp.cookies

    # Send attacker fingerprint with Alice's cookie
    verify_resp = client.post("/api/security/verify", cookies=cookies, json={
        "fingerprint": attacker_fingerprint
    })
    assert verify_resp.status_code == 200
    data = verify_resp.json()
    assert data["valid"] is False
    assert data["decision"] == "BLOCK_REVOKE"
    assert data["mismatch_score"] >= 50.0
    assert data["session_status"] == "revoked"

# 8. Session expiration
def test_session_expiration(client, sample_fingerprint):
    from tests.conftest import TestingSessionLocal
    # Register another user
    reg_resp = client.post("/api/auth/register", json={
        "username": "expired_user",
        "email": "expired@domain.com",
        "password": "Password123!",
        "fingerprint": sample_fingerprint
    })
    cookies = reg_resp.cookies
    session_id = reg_resp.json()["session_id"]

    # Force expiration in DB
    db = TestingSessionLocal()
    session_obj = db.query(SessionModel).filter(SessionModel.id == session_id).first()
    session_obj.expires_at = datetime.utcnow() - timedelta(minutes=5)
    db.commit()
    db.close()

    # Attempt protected request
    resp = client.get("/api/auth/me", cookies=cookies)
    assert resp.status_code == 401
    assert "expired" in resp.json()["message"].lower()

# 9. Session revocation
def test_session_revocation(client, sample_fingerprint):
    # Log in
    login_resp = client.post("/api/auth/login", json={
        "username_or_email": "student_alice",
        "password": "SecurePassword123!",
        "fingerprint": sample_fingerprint
    })
    cookies = login_resp.cookies
    session_id = login_resp.json()["session_id"]

    # Revoke session via API
    revoke_resp = client.post(f"/api/sessions/{session_id}/revoke", cookies=cookies, json={
        "reason": "Test manual revocation"
    })
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["status"] == "revoked"

# 10. Replay simulation
def test_replay_simulation(client, sample_fingerprint, attacker_fingerprint):
    # 1. Create demo session
    init_resp = client.post("/api/demo/create-session", json={
        "client_name": "Legitimate Mac Student",
        "fingerprint": sample_fingerprint
    })
    assert init_resp.status_code == 200
    demo_token = init_resp.json()["session_token"]

    # 2. Replay with attacker context
    replay_resp = client.post("/api/demo/simulate-replay", json={
        "session_token": demo_token,
        "attacker_fingerprint": attacker_fingerprint
    })
    assert replay_resp.status_code == 200
    data = replay_resp.json()
    assert data["decision"] == "BLOCK_REVOKE"
    assert data["session_status"] == "revoked"

# 11. Revoked-session rejection
def test_revoked_session_rejection(client, sample_fingerprint, attacker_fingerprint):
    init_resp = client.post("/api/demo/create-session", json={
        "client_name": "Victim",
        "fingerprint": sample_fingerprint
    })
    demo_token = init_resp.json()["session_token"]

    # Trigger attack replay to revoke
    client.post("/api/demo/simulate-replay", json={
        "session_token": demo_token,
        "attacker_fingerprint": attacker_fingerprint
    })

    # Subsequent check should confirm rejection
    verify_rev = client.post("/api/demo/verify-revocation", json={"session_token": demo_token})
    assert verify_rev.status_code == 200
    assert verify_rev.json()["revoked"] is True
    assert verify_rev.json()["access_granted"] is False

# 12. Unauthorized API access
def test_unauthorized_api_access(client):
    resp = client.get("/api/auth/me")
    assert resp.status_code == 401
    assert "Authentication required" in resp.json()["message"]

# 13. Cross-user access prevention
def test_cross_user_access_prevention(client, sample_fingerprint):
    # User B tries to revoke User A's session
    reg_a = client.post("/api/auth/register", json={
        "username": "user_a",
        "email": "a@domain.com",
        "password": "Password123!",
        "fingerprint": sample_fingerprint
    })
    session_a_id = reg_a.json()["session_id"]

    reg_b = client.post("/api/auth/register", json={
        "username": "user_b",
        "email": "b@domain.com",
        "password": "Password123!",
        "fingerprint": sample_fingerprint
    })
    cookies_b = reg_b.cookies

    # User B attempts to revoke User A's session
    attempt = client.post(f"/api/sessions/{session_a_id}/revoke", cookies=cookies_b, json={
        "reason": "Malicious revocation attempt"
    })
    assert attempt.status_code == 403
    assert "only manage your own sessions" in attempt.json()["message"]

# 14. Malformed fingerprint input
def test_malformed_fingerprint_input(client):
    # Missing required fields in fingerprint
    resp = client.post("/api/auth/register", json={
        "username": "malformed_user",
        "email": "malformed@domain.com",
        "password": "Password123!",
        "fingerprint": {"invalid_key": "not a valid payload"}
    })
    assert resp.status_code == 422

# 15. Missing or insufficient fingerprint evidence
def test_insufficient_fingerprint_evidence():
    trusted = {
        "user_agent_family": "Chrome",
        "platform": "macOS",
        "timezone": "America/New_York",
        "canvas_hash": "abc12345",
        "language": "en",
        "hardware_concurrency": 8
    }
    # Only 1 attribute provided
    sparse_current = {
        "user_agent_family": "Chrome"
    }
    result = compare_fingerprints(trusted, sparse_current)
    assert result.decision == "CHALLENGE"
    assert result.risk_level == "HIGH"
    assert result.comparable_attributes_count < 5

# 16. Security event creation
def test_security_event_creation(client):
    resp = client.get("/api/security/events")
    assert resp.status_code == 200
    events = resp.json()
    assert len(events) > 0
    # Verify events contain required fields and no raw tokens
    for ev in events:
        assert "event_type" in ev
        assert "risk_level" in ev
        assert "decision" in ev
        assert "timestamp" in ev

# 17. System settings retrieval
def test_get_system_settings(client):
    resp = client.get("/api/security/settings")
    assert resp.status_code == 200
    data = resp.json()
    assert "mismatch_flag_threshold" in data
    assert "mismatch_revoke_threshold" in data
    assert "attribute_weights" in data

# 18. System settings update (valid & invalid)
def test_update_system_settings(client):
    # Valid update
    valid_payload = {
        "mismatch_flag_threshold": 40.0,
        "mismatch_revoke_threshold": 60.0,
        "min_evidence_count": 6,
        "session_lifetime_seconds": 7200,
        "attribute_weights": {
            "platform": 30.0,
            "canvas_hash": 25.0
        }
    }
    resp = client.put("/api/security/settings", json=valid_payload)
    assert resp.status_code == 200
    assert resp.json()["mismatch_flag_threshold"] == 40.0
    assert resp.json()["mismatch_revoke_threshold"] == 60.0

    # Invalid update: flag threshold > revoke threshold
    invalid_payload = {
        "mismatch_flag_threshold": 70.0,
        "mismatch_revoke_threshold": 50.0,
        "min_evidence_count": 5,
        "session_lifetime_seconds": 3600,
        "attribute_weights": {}
    }
    bad_resp = client.put("/api/security/settings", json=invalid_payload)
    assert bad_resp.status_code == 400
    assert "cannot exceed" in bad_resp.json()["message"]

    # Reset back to defaults
    reset_resp = client.post("/api/security/settings/reset")
    assert reset_resp.status_code == 200
    assert reset_resp.json()["mismatch_flag_threshold"] == 35.0
    assert reset_resp.json()["mismatch_revoke_threshold"] == 50.0

# 19. Full End-to-End Security Demonstration Lifecycle
def test_complete_end_to_end_security_demonstration(client, sample_fingerprint, attacker_fingerprint):
    # Step 1: Create test user
    reg_resp = client.post("/api/auth/register", json={
        "username": "e2e_student",
        "email": "e2e_student@univ.edu",
        "password": "SecureStudentPass2026!",
        "fingerprint": sample_fingerprint
    })
    assert reg_resp.status_code == 201
    reg_data = reg_resp.json()
    assert reg_data["user"]["username"] == "e2e_student"

    # Step 2: Log in and establish initial session
    login_resp = client.post("/api/auth/login", json={
        "username_or_email": "e2e_student",
        "password": "SecureStudentPass2026!",
        "fingerprint": sample_fingerprint
    })
    assert login_resp.status_code == 200
    cookies = login_resp.cookies
    assert "sid" in cookies
    token = cookies.get("sid")

    # Step 3 & 4: Access protected resource using legitimate fingerprint & confirm accepted
    me_resp = client.get("/api/auth/me", cookies=cookies)
    assert me_resp.status_code == 200
    assert me_resp.json()["user"]["username"] == "e2e_student"

    verify_legit = client.post("/api/security/verify", cookies=cookies, json={
        "fingerprint": sample_fingerprint
    })
    assert verify_legit.status_code == 200
    assert verify_legit.json()["valid"] is True
    assert verify_legit.json()["decision"] == "ALLOW"
    assert verify_legit.json()["similarity_score"] == 100.0

    # Step 5, 6, 7: Simulate replay using stolen cookie from attacker context
    verify_attacker = client.post("/api/security/verify", cookies=cookies, json={
        "fingerprint": attacker_fingerprint
    })
    assert verify_attacker.status_code == 200
    atk_data = verify_attacker.json()
    assert atk_data["valid"] is False
    assert atk_data["decision"] == "BLOCK_REVOKE"
    assert atk_data["risk_level"] == "CRITICAL"
    assert atk_data["mismatch_score"] >= 50.0
    assert atk_data["session_status"] == "revoked"
    assert len(atk_data["mismatched_attributes"]) > 0

    # Step 8 & 9: Confirm that the session became unusable & subsequent request is denied
    blocked_me = client.get("/api/auth/me", cookies=cookies)
    assert blocked_me.status_code == 401
    assert "revoked" in blocked_me.json()["message"].lower()

    # Step 10: Confirm security events stored and visible in audit trail
    events_resp = client.get("/api/security/events?limit=10")
    assert events_resp.status_code == 200
    events = events_resp.json()
    event_types = [e["event_type"] for e in events]
    assert "FP_HIJACK_BLOCKED" in event_types

    metrics_resp = client.get("/api/security/metrics")
    assert metrics_resp.status_code == 200
    assert metrics_resp.json()["blocked_hijacks"] >= 1

    # Step 11: Log in again and verify legitimate access is restored
    relogin_resp = client.post("/api/auth/login", json={
        "username_or_email": "e2e_student",
        "password": "SecureStudentPass2026!",
        "fingerprint": sample_fingerprint
    })
    assert relogin_resp.status_code == 200
    new_cookies = relogin_resp.cookies
    assert new_cookies.get("sid") != token

    restored_me = client.get("/api/auth/me", cookies=new_cookies)
    assert restored_me.status_code == 200
    assert restored_me.json()["session"]["status"] == "active"


