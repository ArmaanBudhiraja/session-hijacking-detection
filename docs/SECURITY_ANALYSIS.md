# Security Analysis & Threat Model

This document outlines the security architecture, threat model, MITRE ATT&CK mapping, failure modes, and mitigation strategies implemented in **SessionDefense**.

---

## 1. Threat Model & Attacker Capabilities

### Attacker Objective
An adversary seeks to gain unauthorized access to an authenticated web application session without knowing the victim's credentials (username, password, MFA).

### Attacker Capabilities Assumed
- **Cookie Theft (Exfiltration):** The adversary successfully acquires the victim's session cookie (`sid`) via:
  - Cross-Site Scripting (XSS) on the same origin or vulnerable subdomain.
  - Malicious browser extensions with host permissions.
  - Infostealer trojan malware dumping browser storage.
  - Session sniffing on unencrypted or misconfigured local networks.
- **Arbitrary Replay Context:** The adversary transmits HTTP requests bearing the stolen `sid` cookie from their own workstation, virtual machine, or scripted tool (`curl`, Python `requests`).
- **Knowledge of Verification Endpoints:** The adversary may inspect client JavaScript and attempt to forge or strip browser fingerprint headers.

---

## 2. MITRE ATT&CK Mapping & Mitigations

| Technique ID | Technique Name | Threat Scenario | SessionDefense Mitigation |
|---|---|---|---|
| **T1539** | Steal Web Session Cookie | Attacker exfiltrates session cookie from victim browser storage. | Even with the cookie, subsequent requests from attacker machine fail fingerprint comparison and trigger immediate session revocation. |
| **T1563.001** | Subvert Session Authentication: Web Hijacking | Attacker replays stolen bearer token to impersonate victim. | Continuous per-request context evaluation detects hardware/OS mismatch ($\ge 50\%$) and revokes the session server-side. |
| **T1185** | Browser Session Hijacking | Man-in-the-browser manipulation or rogue extension replaying requests. | Canvas hash, WebGL hardware renderer, and core concurrency discrepancies expose anomalous execution context. |
| **T1552** | Unsecured Credentials | Database leak exposes session table to unauthorized eyes. | Raw session tokens are never stored; database stores only SHA-256 hashes of tokens, preventing token replay from database dumps. |
| **T1059.007** | JavaScript Execution (Fingerprint Evasion) | Attacker blocks fingerprinting scripts or sends empty attributes. | Fail-safe evidence policy: requests with $< 5$ comparable attributes are automatically denied with a `CHALLENGE` decision. |

---

## 3. Defense-in-Depth Security Invariants

### 1. Zero Token Storage Exposure
In standard naive frameworks, session tables store the raw session cookie in plaintext:
$$\text{Compromised DB} \implies \text{Full User Takeover}$$

In SessionDefense:
1. The server generates a 32-byte cryptographically secure random token: `raw_token = secrets.token_urlsafe(32)`.
2. The server stores only its cryptographic digest: `token_hash = SHA-256(raw_token)`.
3. Incoming requests hash the presented cookie value before database lookup. A database compromise yields only SHA-256 hashes, from which the raw cookie cannot be recovered.

### 2. Strict Cross-User Authorization
Endpoint `/api/sessions/{session_id}/revoke` enforces ownership checks:
```python
if target_session.user_id != current_user.id:
    raise HTTPException(status_code=403, detail="Forbidden: You can only manage your own sessions.")
```
Users cannot revoke or manipulate sessions belonging to other accounts.

### 3. Fail-Safe Insufficient Evidence Rule
If an adversary attempts to evade comparison by stripping browser characteristics (e.g., submitting an empty `{}` fingerprint payload):
```python
if comparable_count < settings.MIN_EVIDENCE_COUNT: # Default: 5
    return Decision(decision="CHALLENGE", risk="HIGH", reason="Insufficient evidence")
```
The request is challenged and denied access to protected resources.

### 4. CSRF Protection
Mutation endpoints validate a CSRF token passed via custom header (`x-csrf-token`) against the client cookie value, preventing state-changing cross-site request forgery attacks.

---

## 4. False Positive vs False Negative Analysis

| Scenario | Risk Type | Behavior in SessionDefense | Mitigation Implemented |
|---|---|---|---|
| User connects external 4K monitor | Potential False Positive | Screen resolution shifts dramatically ($\Delta > 20\%$). | Screen weight is restrained to 10 points out of 146 total points. A screen resolution shift alone yields $\approx 6.8\%$ mismatch—well below the 35% challenge threshold. |
| User updates browser minor version | Potential False Positive | Build number in User-Agent changes. | User-Agent is normalized to broad browser engine family (`Chrome`, `Firefox`, `Safari`), ignoring minor build string churn. |
| Attacker uses same OS & Browser on different hardware | Potential False Negative | OS and User-Agent match. | Canvas signature ($w=25$) and WebGL unmasked GPU renderer ($w=15$) detect hardware differences, pushing mismatch over 50%. |
| Attacker on identical university lab workstation | Documented Limitation | Attacker uses same machine model, GPU, OS, and timezone. | Documented academic limitation. In identical lab hardware clones, behavioral typing cadence or IP geofencing would be required as complementary signals. |

---

## 5. Security Recommendations for Production Deployment

1. **Enforce HTTPS / HSTS:** In production, enable `COOKIE_SECURE = True` in `.env` to enforce TLS-only transmission.
2. **SameSite=Lax / Strict:** Prevent cross-site cookie leakage.
3. **Short Session Lifetimes:** Combine behavioral detection with a 15–60 minute rolling expiration window.
4. **Content Security Policy (CSP):** Restrict script execution to trusted nonces to eliminate the primary vector of token theft (XSS).
