# API Reference Documentation

All endpoints are hosted with the `/api` prefix. The backend returns standard JSON responses with appropriate HTTP status codes and structured error payloads.

---

## 1. System Health & Metadata

### `GET /api/health`
Checks backend operational status and environment.

**Response (200 OK):**
```json
{
  "status": "healthy",
  "app": "Behavioral Fingerprint Session Hijacking Detection",
  "environment": "development",
  "version": "1.0.0"
}
```

---

## 2. Authentication & Identity

### `POST /api/auth/register`
Creates a user account, records initial baseline fingerprint, establishes a session, and sets HttpOnly cookies.

**Request Body:**
```json
{
  "username": "student_alice",
  "email": "alice@university.edu",
  "password": "SecurePassword123!",
  "fingerprint": {
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...",
    "platform": "MacIntel",
    "language": "en-US",
    "timezone": "America/New_York",
    "screen": { "width": 1920, "height": 1080, "color_depth": 24, "pixel_ratio": 2.0 },
    "hardware_concurrency": 8,
    "canvas_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  }
}
```

**Response (201 Created):**
```json
{
  "message": "User registered and logged in successfully.",
  "user": {
    "id": "c1f7a0b3-9e45-42cf-9168-cfc8397a82b1",
    "username": "student_alice",
    "email": "alice@university.edu",
    "is_active": true,
    "created_at": "2026-10-24T18:00:00Z"
  },
  "csrf_token": "63f7b9e31d4e08c5b058a9e2",
  "session_id": "a9d7c812-70fb-4458-b648-95f08d5e9714"
}
```
**Headers:**
`Set-Cookie: sid=...; HttpOnly; Path=/; SameSite=lax`  
`Set-Cookie: csrf_token=...; Path=/; SameSite=lax`

---

### `POST /api/auth/login`
Validates credentials, binds the current browser fingerprint to a new session, and sets authentication cookies.

**Request Body:**
```json
{
  "username_or_email": "student_alice",
  "password": "SecurePassword123!",
  "fingerprint": { ... }
}
```
**Response (200 OK):** Same schema as `/api/auth/register`.

---

### `POST /api/auth/logout`
Revokes the current session in SQLite and clears authentication cookies.

**Response (200 OK):**
```json
{
  "message": "Logged out successfully."
}
```

---

### `GET /api/auth/me`
Restores user session state on page refresh. Protected by `sid` session cookie.

**Response (200 OK):**
```json
{
  "user": {
    "id": "c1f7a0b3-...",
    "username": "student_alice",
    "email": "alice@university.edu"
  },
  "session": {
    "id": "a9d7c812-...",
    "status": "active",
    "created_at": "2026-10-24T18:00:00Z",
    "expires_at": "2026-10-24T19:00:00Z",
    "user_agent_summary": "Chrome on macOS",
    "trusted_fingerprint_summary": {
      "platform": "macOS",
      "user_agent_family": "Chrome",
      "timezone": "America/New_York",
      "canvas_hash_preview": "e3b0c44298fc1c14..."
    }
  }
}
```

---

## 3. Continuous Verification & Security Telemetry

### `POST /api/security/verify`
Compares the incoming browser fingerprint against the trusted baseline of the active session. If mismatch exceeds 50%, revokes the session.

**Request Body:**
```json
{
  "fingerprint": { ... }
}
```

**Response (200 OK):**
```json
{
  "valid": true,
  "decision": "ALLOW",
  "similarity_score": 100.0,
  "mismatch_score": 0.0,
  "risk_level": "LOW",
  "mismatched_attributes": [],
  "comparable_attributes_count": 8,
  "message": "Browser fingerprint matches trusted session.",
  "session_status": "active"
}
```

**Hijack Detection Response (200 OK with Revocation):**
```json
{
  "valid": false,
  "decision": "BLOCK_REVOKE",
  "similarity_score": 24.5,
  "mismatch_score": 75.5,
  "risk_level": "CRITICAL",
  "mismatched_attributes": [
    {
      "attribute": "platform",
      "category": "Operating System",
      "weight": 25.0,
      "expected": "macOS",
      "actual": "Linux",
      "reason": "OS Platform changed from macOS to Linux"
    },
    {
      "attribute": "canvas_hash",
      "category": "Hardware/Rendering",
      "weight": 25.0,
      "expected": "e3b0c442...",
      "actual": "9f86d081...",
      "reason": "Deterministic 2D canvas drawing signature mismatch"
    }
  ],
  "comparable_attributes_count": 8,
  "message": "POTENTIAL SESSION HIJACKING DETECTED!...",
  "session_status": "revoked"
}
```

---

### `GET /api/security/events`
Returns audit trail of security events. Supports filtering and pagination.

**Query Parameters:**
- `limit` (int, default 50)
- `offset` (int, default 0)
- `event_type` (string, optional)
- `risk_level` (string, optional)

---

### `GET /api/security/metrics`
Aggregates real-time telemetry metrics for SOC dashboard and Recharts visualizations.

**Response (200 OK):**
```json
{
  "total_logins": 14,
  "active_sessions": 3,
  "suspicious_events": 1,
  "blocked_hijacks": 4,
  "successful_verifications": 22,
  "recent_scores": [
    {
      "timestamp": "18:24:10",
      "similarity_score": 100.0,
      "mismatch_score": 0.0,
      "event_type": "FP_VERIFY_SUCCESS",
      "decision": "ALLOW"
    }
  ],
  "scenario_breakdown": [
    { "scenario": "Legitimate Logins", "count": 14 },
    { "scenario": "Normal Verifications", "count": 22 },
    { "scenario": "Suspicious Anomalies", "count": 1 },
    { "scenario": "Hijacks Blocked / Revoked", "count": 4 }
  ]
}
```

---

## 4. Detection Engine Settings

### `GET /api/security/settings`
Returns current runtime detection thresholds and attribute weights.

### `PUT /api/security/settings`
Updates runtime thresholds and weights. Validates that `mismatch_flag_threshold <= mismatch_revoke_threshold`.

### `POST /api/security/settings/reset`
Resets engine policy back to baseline academic defaults (Flag: 35%, Revoke: 50%, Min Evidence: 5).

---

## 5. Session Management

### `GET /api/sessions`
Returns all active and past sessions for the authenticated user.

### `POST /api/sessions/{session_id}/revoke`
Manually terminates a specific session. Enforces user ownership check.

---

## 6. Attack Simulation Lab Endpoints

### `POST /api/demo/create-session`
Initializes a dedicated test user (`demo_victim`) and establishes a baseline test session.

### `POST /api/demo/normal-verification`
Executes normal verification from the legitimate browser context (demonstrating ~100% similarity).

### `POST /api/demo/simulate-replay`
Exercises the real comparison engine against an adversary presenting the stolen session token with synthetic attacker browser attributes. Revokes the session if mismatch $\ge 50\%$.

### `POST /api/demo/verify-revocation`
Tests that a revoked session token is permanently rejected by the server (yielding `access_granted: false`).
