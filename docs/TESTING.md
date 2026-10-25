# Testing & Verification Guide

This guide covers both automated test execution and the manual step-by-step verification procedure for academic evaluators.

---

## 1. Automated Test Suite Execution

The backend contains 19 automated tests validating every component: authentication, session hashing, fingerprint comparison, anomaly revocation, authorization isolation, and the complete end-to-end attack lifecycle.

### Running Pytest

```bash
cd backend
venv/bin/pytest
```

To run with verbose output displaying individual test names:
```bash
venv/bin/pytest -v
```

### Complete Test Catalog

| # | Test Function Name | Scenarios Verified | Expected Result |
|---|---|---|---|
| 1 | `test_successful_registration` | User registration with initial baseline fingerprint | 201 Created, `sid` and `csrf_token` cookies set |
| 2 | `test_duplicate_registration_prevention` | Attempt to register with existing username or email | 400 Bad Request with informative error message |
| 3 | `test_successful_login` | Argon2id credential verification and session issuance | 200 OK, new session cookie issued |
| 4 | `test_invalid_credentials_rejected` | Wrong password authentication attempt | 401 Unauthorized, failed login audit event |
| 5 | `test_successful_protected_me_request` | Access to `/api/auth/me` with valid active session | 200 OK, user profile and session metadata returned |
| 6 | `test_valid_fingerprint_comparison` | Subsequent request from identical browser context | 200 OK, 100% similarity, 0% mismatch, ALLOW |
| 7 | `test_mismatched_fingerprint_detection` | Replay of valid cookie from Linux/Windows attacker | 200 OK, mismatch $\ge 50\%$, BLOCK_REVOKE |
| 8 | `test_session_expiration` | Session past `expires_at` timestamp | 401 Unauthorized ("Session expired") |
| 9 | `test_session_revocation` | Manual revocation via `/api/sessions/{id}/revoke` | 200 OK, session marked revoked in SQLite |
| 10 | `test_replay_simulation` | Interactive attack lab replay simulation | Mismatch detected, decision = BLOCK_REVOKE |
| 11 | `test_revoked_session_rejection` | Subsequent request presenting revoked token | access_granted = False, revoked = True |
| 12 | `test_unauthorized_api_access` | Request to protected endpoints with no cookie | 401 Unauthorized |
| 13 | `test_cross_user_access_prevention` | User B attempts to revoke User A's session | 403 Forbidden ("You can only manage your own sessions") |
| 14 | `test_malformed_fingerprint_input` | Missing required payload keys in fingerprint | 422 Unprocessable Content |
| 15 | `test_insufficient_fingerprint_evidence` | Stripped fingerprint ($< 5$ comparable signals) | Decision = CHALLENGE, Risk = HIGH |
| 16 | `test_security_event_creation` | Audit log persistence and zero token exposure | Events stored in SQLite, tokens never rendered |
| 17 | `test_get_system_settings` | Inspection of detection engine thresholds | 200 OK with active thresholds and weights |
| 18 | `test_update_system_settings` | Threshold updates and invalid threshold validation | 200 OK on valid update, 400 on flag > revoke |
| 19 | `test_complete_end_to_end_security_demonstration` | Full 11-step end-to-end security demonstration | Complete threat and restoration lifecycle passes |

---

## 2. Frontend Build & Quality Verification

Verify that the frontend builds without TypeScript compiler errors or bundler issues:

```bash
cd frontend
npm run build
npm run lint
```

- **`npm run build`:** Executes TypeScript project reference compilation (`tsc -b`) followed by Vite production bundling. Must report zero errors.
- **`npm run lint`:** Executes `oxlint` across all source files.

---

## 3. Manual Step-by-Step Evaluator Walkthrough

Follow these steps in your browser to evaluate the complete defense system:

### Step 1: Open the Application
Navigate to **http://localhost:5173**. Observe the **Enterprise SOC Dashboard** with the deep navy navigation sidebar, warm neutral background, and real backend health heartbeat ("API Engine Online" in green).

### Step 2: Test Authentication & Session Creation
1. Click **"Sign In / Demo"** in the top navigation or navigate to **Overview**.
2. Click **"Fill Demo Credentials"** to populate `student_alice` and `SecurePassword123!`.
3. Click **"Sign In & Bind Session"**.
4. Observe the user indicator showing `student_alice` and the active session ID.

### Step 3: Verify Baseline Context
1. On the **Overview** page, click **"Verify Current Context"**.
2. Observe the green verification alert: **"Browser fingerprint matches trusted session (100% Match)"**.
3. Confirm that an audit event of type `FP_VERIFY_SUCCESS` appears in the Recent Events table.

### Step 4: Run the Attack Simulation Lab
1. Navigate to **Attack Simulation** in the sidebar.
2. In **Stage 1**, click **"1. Initialize Legitimate Session"**. A dedicated test session is bound to your browser's physical fingerprint.
3. In **Stage 2**, click **"2. Execute Normal Legitimate Request"**. Confirms ~100% similarity from the same browser.
4. In **Stage 3**, select **"Adversary Linux Workstation"** or **"Exfiltrator Windows Terminal"**.
5. Click **"3. Replay Stolen Cookie from Attacker Machine"**.
6. Observe the immediate **HIJACKING DETECTED & REQUEST BLOCKED** report card:
   - Mismatch score: **70–85%**.
   - Decision: **`BLOCK_REVOKE`**.
   - Attribute discrepancy table listing exact differences in OS, Canvas Hash, and Timezone.
7. In **Stage 4**, click **"Verify Permanent Invalidation"**.
8. Confirms that the server has marked the token revoked and rejects all subsequent access (401 Unauthorized).

### Step 5: Check Live Monitoring & Session Inventory
1. Click **Live Monitoring** to see updated real-time KPI counts and detection trend curves.
2. Click **Sessions** to inspect the session table. Confirm that the attacked session is marked as **REVOKED** with the exact mismatch score reason recorded in the database.
3. Click **Settings** to inspect or tune the 35% and 50% detection threshold boundaries.
