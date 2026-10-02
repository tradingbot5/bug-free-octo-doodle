---
name: hunt-captcha-bypass
description: "Hunt CAPTCHA Bypass — 6 distinct patterns: (1) CAPTCHA field simply omitted from the request (server-side validation absent), (2) CAPTCHA token replayed from a solved challenge (no single-use enforcement), (3) CAPTCHA response accepted on a different endpoint than it was solved on (no binding to action/session), (4) static or predictable CAPTCHA values accepted (e.g. '0', 'null', empty string), (5) audio/accessibility CAPTCHA trivially solvable programmatically, (6) CAPTCHA only enforced after N failures (first N requests bypass it). Detection: intercept a successful form submission, remove the CAPTCHA field entirely, replay — if it still succeeds, server-side validation is absent. Medium severity standalone; High when it removes the only rate-limit gate protecting a login, registration, or payment endpoint."
sources: public_research, operator_experience, google_recaptcha_docs, cloudflare_turnstile_docs
report_count: 6
cwe: [CWE-804, CWE-307, CWE-287, CWE-863]
cvss_baseline: "Low (3.7) standalone automation-gate removal → Medium (5.3) on registration/reset → High (7.5-8.1) when it unlocks login brute-force or OTP brute reaching ATO."
related_skills: [hunt-brute-force, hunt-forgot-password, hunt-race-condition, hunt-mfa-bypass, hunt-ato]
---

## Autonomous Testing Priority

**The fastest test: just omit the CAPTCHA field entirely. Most CAPTCHA bypass bugs are client-side-only validation.**

**Pattern 1 — Omit the CAPTCHA field (most common, most automatable):**
1. GET the form/endpoint that shows a CAPTCHA to understand its field name (usually `g-recaptcha-response`, `captcha`, `captcha_token`, `captcha_answer`, `h-captcha-response`)
2. POST the form with ALL fields EXCEPT the CAPTCHA field
3. If the action succeeds (200, redirect, or "success" message) → no server-side CAPTCHA validation
4. Proof: the state-changing action completes without a valid CAPTCHA field (compare against a baseline request that includes it)

**Pattern 2 — Empty or null CAPTCHA value:**
Instead of omitting the field entirely, include it with an empty string, `null`, `0`, or `undefined`:
```
captcha=&email=test@example.com&password=test123
```
Some apps validate field presence but not content.

**Pattern 3 — Replay a previously solved CAPTCHA token:**
1. Complete one legitimate CAPTCHA challenge and capture the `g-recaptcha-response` token
2. Submit a second request immediately with the SAME token value
3. If the second submission also succeeds → token is not single-use (replay attack)
4. A replayed token can be shared across automated requests

**Pattern 4 — Test without CAPTCHA on similar endpoints:**
Some apps add CAPTCHA to the registration form but forget the password reset, API endpoint, or mobile API path (`/api/register` vs `/register`). Try the same action via the API path without any CAPTCHA field.

**Pattern 5 — Rate/throughput-gated "prove you're automated" challenges:**
Some apps define CAPTCHA "bypass" as simply exceeding the rate a human could plausibly sustain —
e.g. "N submissions within T seconds" — checked by a middleware that counts REQUESTS REACHING the
route, not successful outcomes. Garbage/placeholder payloads satisfy this exactly as well as valid
ones, since the counter increments regardless of whether the request's own validation passes.

**Timing note (sliding-window counters):** don't solve this one request at a time — a sequential
pace (seconds between each request) structurally cannot land N requests inside a short sliding
window, and issuing more requests serially does not fix it. A typical failing pattern is 12
requests spread across ~250 seconds when the check requires ~10 requests within 20 seconds.
Instead fire the requests **concurrently** (e.g. `"concurrency": N` on a single request call, or
any parallel-request primitive your tooling offers, with N >= the required count) so they arrive
simultaneously and satisfy the sliding window trivially. Check the endpoint's own
required-field validation first (e.g. a `rating` field that can't be null) so the concurrent
payload is at least well-formed enough to reach the counting middleware, even if other fields
(like the CAPTCHA answer itself) are wrong or reused.

**What to skip in automated testing:** Solving real reCAPTCHA/hCaptcha programmatically (OCR, audio bypass) requires external services. Only attempt if patterns 1-4 fail and the test budget allows.

**Proof:** Any successful state-changing action (account created, login succeeded, form submitted) that completed without a valid CAPTCHA token confirms the bypass.

---

## Vulnerability Classes in This Skill

### 1. Client-Side-Only CAPTCHA Validation
JavaScript hides/disables the submit button until CAPTCHA is solved, but the server never checks the CAPTCHA token. Direct API calls bypass the UI gate entirely.

### 2. CAPTCHA Not Tied to Session or Action
A token solved for login is accepted on the registration endpoint (or any other). The server validates "is this a real CAPTCHA solution?" but not "is this the right solution for THIS action?".

### 3. Single-Use Not Enforced
CAPTCHA tokens (especially reCAPTCHA v2) are meant to be consumed after one use. If the server doesn't revoke them after verification, a single human-solved token becomes reusable for many requests.

### 4. CAPTCHA Added Reactively (Only After N Failures)
Some apps only show CAPTCHA after 3-5 failed login attempts. Before that threshold, no CAPTCHA is required → an attacker can make N-1 attempts per account indefinitely by resetting state between attempts.

### 5. Static or Predictable CAPTCHA
Math CAPTCHAs (`3 + 4 = ?`), simple image CAPTCHAs, or text CAPTCHAs with a finite answer set can be automated. These are custom CAPTCHA implementations, not Google/hCaptcha.

---

## New Techniques (2024-2026)

### 6. Provider verify-endpoint misuse (reCAPTCHA / hCaptcha / Turnstile)
The server-side verify call is where most real bypasses live now:
- **Missing `hostname`/`action` check** — the siteverify response includes `hostname` (reCAPTCHA) and `action` (v3). Apps that ignore them accept a token solved on *any* site using the same key, or a token minted for a different action. Solve a cheap challenge on a low-value page, replay on the high-value one.
- **reCAPTCHA v3 score threshold too low / not enforced** — v3 returns a `score` (0.0-1.0). If the backend doesn't gate on it (or accepts `success:true` regardless of score), automation sails through. Also test the v2 checkbox fallback that many v3 sites keep.
- **Test/sandbox keys in production** — Google's test key `6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI` (and hCaptcha's `10000000-ffff-ffff-ffff-000000000001` / secret `0x0000...`) always validate. Grep JS bundles for these.
- **Enterprise reCAPTCHA assessment reuse** — the `assessment` is single-use; apps that cache or don't `annotate` can be replayed.
- **Turnstile** — check for missing `cdata`/idempotency binding and token reuse window.

### 7. Response-shape confusion / client-trusted result
Some SPAs verify the CAPTCHA client-side and send a boolean (`"captchaValid":true`) or the raw provider response to the server, which trusts it. Flip the boolean or forge the JSON.

### 8. Mobile / GraphQL / legacy path gaps
The web form enforces CAPTCHA; the mobile API (`/api/v2/login`), GraphQL mutation, or an older `/legacy/` route does not. Enumerate alternate entry points for the same action (overlaps `hunt-shadow-api`).

### 9. Race the revocation window
Even with single-use enforcement, fire many requests with the same freshly-solved token **concurrently** before the backend marks it consumed (TOCTOU). Pairs with `hunt-race-condition`.

### 10. Human-solver economics note (authorized only)
2captcha/anti-captcha services solve real challenges cheaply. Mention feasibility in impact ("rate gate is economically defeatable at ~$1/1000"), but do not operationalize bulk solving against a live program — demonstrate the *bypass*, argue the economics.

## Tooling

- **Burp Repeater/Intruder** — omit/replay/forge token; **Turbo Intruder** for the revocation race.
- **Grep JS** for site keys and the known test keys above.
- **siteverify replay script** — capture one valid token, script N replays to prove single-use is not enforced.

## Remediation

- Verify server-side on every submission; enforce `success` AND `score` (v3) AND `hostname` AND `action` match the expected page/action.
- Enforce single-use (consume the token atomically before processing) and short expiry; bind the token to session + action.
- Apply CAPTCHA uniformly across web, mobile, GraphQL, and legacy paths for the same action; never trust a client-supplied "valid" flag.
- Rotate out any test/sandbox keys before production.

## Validation Gate

- Demonstrate a real state-changing action completing without a valid, correctly-scoped token (baseline-with-token vs probe-without).
- For replay/single-use, show the *second* use of a consumed token succeeding.
- Keep volume minimal — prove the bypass with a handful of requests; do not mass-create accounts or flood.

## Disclosed Report Patterns

Verify before quoting IDs/amounts.
- **Missing hostname/action validation in siteverify** — recurring medium H1 pattern enabling cross-site token reuse.
- **Test key shipped to production** — periodic disclosures across SaaS login/registration.
- **CAPTCHA on web but absent on mobile/API path** — common gap that unlocks brute-force → ATO.

## Impact Chain

CAPTCHA bypass alone: **Medium** (enables automation of rate-limited actions)

CAPTCHA bypass + login endpoint = **brute force gate removed** → chain with `hunt-brute-force` → High/Critical

CAPTCHA bypass + registration endpoint = **account farming** → abuse, spam, resource exhaustion

CAPTCHA bypass + password reset = **token flooding** → chain with `hunt-forgot-password`

---

## Related Skills

- **`hunt-brute-force`** — CAPTCHA is often the only rate-limit gate; bypass unlocks brute force
- **`hunt-forgot-password`** — reset endpoints sometimes protected by CAPTCHA only
- **`hunt-race-condition`** — race the CAPTCHA validation window (submit before the token is revoked)
