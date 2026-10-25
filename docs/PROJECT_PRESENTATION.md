# Project Presentation: Review - 0 Evaluation

**Project Title:** Behavioral Fingerprint-Based Detection of Session Hijacking in Web Applications  
**Academic Phase:** Review - 0 (Working Prototype Demonstration)  
**Developers:**  
- **Anish Jaiswal** (23BCE0172)  
- **Armaan Budhiraja** (23BCE0507)  

---

## Slide 1: Introduction & Problem Statement

### The Problem: Silent Session Impersonation
- Modern web architectures rely universally on **bearer session tokens** (cookies, JWTs) stored in client storage.
- When an attacker steals a valid session cookie—via Cross-Site Scripting (XSS), malicious extensions, or endpoint infostealer trojans—they can replay it from any machine in the world.
- Current server frameworks (Express, Django, Spring, Flask, FastAPI) validate only:
  1. *Does the session ID exist in the database or cache?*
  2. *Has the session reached its timestamp expiration?*
- **Result:** The server executes unauthorized requests on behalf of the attacker, completely unaware that the physical machine hardware and browser engine have changed.

---

## Slide 2: Research Gap & Objectives

| Current Industry Standard | Proposed SessionDefense System |
|---|---|
| **Static Bearer Cookies:** Any client bearing the cookie is trusted. | **Bound Context Sessions:** The session token is cryptographically paired with hardware & browser characteristics. |
| **Coarse IP-Based Restrictions:** Rebinding to IP causes severe false positives on mobile towers and NAT proxies. | **Device-Level Fingerprint:** Evaluates 10 weighted dimensions (Canvas, WebGL GPU, OS, Screen, Timezone). |
| **Delayed Detection:** Hijacking is discovered only after fraudulent transactions occur. | **Per-Request Automated Defense:** Mismatches exceeding 50% immediately revoke the session server-side. |

---

## Slide 3: Proposed Architecture & Pipeline

```
[Client Authentication]
        │
        ▼ Captures: Canvas Hash, WebGL Renderer, Screen, OS, Timezone
[Canonical Normalization & Binding]
        │
        ▼ Stores: SHA-256(token) + Trusted Baseline JSON in SQLite
[Subsequent Protected Requests]
        │
        ▼ Compares Baseline vs Live Client Context
[Weighted Comparator & Tolerances]
        │
   ┌────┴─────────────────────────────┐
   ▼                                  ▼
Mismatch < 35%                Mismatch ≥ 50%
Decision: ALLOW               Decision: BLOCK_REVOKE
Protected Data Rendered       Session Permanently Invalidate in DB
                              Client Cookies Expunged (401 Rejection)
```

---

## Slide 4: Comparison Algorithm & Formulation

Each attribute $i$ is weighted based on hardware persistence:
- **`platform`** ($w = 25.0$) & **`canvas_hash`** ($w = 25.0$) — Critical hardware/OS signals.
- **`user_agent_family`** ($w = 20.0$) — Browser engine.
- **`webgl_renderer`** ($w = 15.0$) & **`timezone`** ($w = 15.0$) — GPU & Localization.
- **`hardware_concurrency`** ($w = 10.0$) & **`screen`** ($w = 10.0$ with $\pm 20\%$ tolerance).
- **`language`** ($w = 10.0$) & **`device_memory`** ($w = 8.0$).

### Formula
$$\text{Mismatch Score} = 100 \times \left( \frac{\sum_{j \in \text{Mismatches}} w_j}{\sum_{i \in \text{Comparable}} w_i} \right)$$
$$\text{Similarity Score} = 100.0 - \text{Mismatch Score}$$

---

## Slide 5: Key Security Invariants

1. **Zero Token Storage Exposure:**
   - Database stores solely `SHA-256(session_token)`, preventing token compromise from database breaches.
2. **Cross-User Authorization Isolation:**
   - Multi-tenant boundary checks prevent User A from terminating User B's sessions.
3. **Fail-Safe Policy for Stripped Evidence:**
   - If an adversary strips JavaScript signals ($< 5$ attributes), the engine fails safe to `CHALLENGE`.
4. **Explainable Anomaly Telemetry:**
   - Every security event records human-readable diagnostic explanations for security auditing.

---

## Slide 6: Working Prototype Features (Review-0 Deliverables)

- **Interactive Attack Simulation Lab:** A 4-stage guided testing environment demonstrating baseline establishment, legitimate access, stolen cookie replay from anomalous hardware, and revocation enforcement.
- **Enterprise SOC Dashboard:** Refined, human-designed interface with real-time KPI metrics, Recharts score trend area charts, and live database telemetry.
- **Session Inventory:** Complete visibility into active sessions with safe fingerprint summaries and confirmation-protected revocation actions.
- **Detection Settings:** Configurable mismatch thresholds (35% flag, 50% revoke) and attribute weight tuning backed by live FastAPI endpoints.
- **19 Automated Pytest Tests:** 100% passing automated test suite covering all functional and security scenarios.

---

## Slide 7: Live Demonstration Script for Evaluators

1. **Authentication:** Log in as `student_alice` using 1-click demo fill.
2. **Normal Verification:** Click **"Verify Current Context"** on Overview. Show **100% similarity (ALLOW)**.
3. **Simulation Lab:** Open **Attack Simulation Lab**.
   - Create baseline session on legitimate student browser.
   - Select **"Adversary Linux Workstation"** and execute **"Replay Stolen Cookie"**.
   - Show returned **75.5% mismatch score**, **`BLOCK_REVOKE`** decision, and discrepancy table.
4. **Revocation Enforcement:** Click **"Verify Invalidation"**. Show **401 Unauthorized** rejection of the compromised token.
5. **Audit Trail:** Open **Security Events** and show the newly logged `FP_HIJACK_BLOCKED` event with full JSON telemetry.

---

## Slide 8: Future Work & Roadmap

- **Review - 1 Milestone:** Implement behavioral keystroke timing dynamics (flight time and dwell time) and mouse trajectory entropy to augment hardware fingerprinting.
- **Review - 2 Milestone:** Machine-learning anomaly score refinement (Isolation Forests) and automated alerting integrations (webhooks, email notifications).
