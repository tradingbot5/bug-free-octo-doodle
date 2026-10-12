---
name: hunt-pii-exposure
description: Detect PII/sensitive-data exposure with minimal proof. Never bulk-harvest real user data.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires curl, python3
metadata:
  tags: [pii, sensitive-data, privacy, idor, exposure, cwe-359, cwe-200]
  category: redteam
  related_skills:
    - hunt-idor
    - hunt-source-leak
    - hunt-api-authz
    - hunt-google-dork
---

# HUNT-PII-EXPOSURE — Sensitive-Data Exposure Detection

PII exposure is when an application discloses personal or sensitive data to a
party that should not see it: another user's record via IDOR, a public API
returning more fields than the UI shows, a cached error page containing a user
object, a misconfigured export endpoint, or PII indexed by search engines. The
underlying weaknesses are CWE-200 (information exposure) and CWE-359 (exposure of
private information).

> These skills are for authorized security testing only. Only test targets you
> own or have explicit written permission to test.

## The one rule that defines this skill

**You are proving that PII *can* be exposed, not collecting it.** The finding is
the exposure path, not the data. So:

- Stop at the **first** confirmed record. One leaked record proves the bug; a
  thousand is a data breach you caused.
- **Prefer your own test accounts.** Create two accounts you control and prove
  account A can read account B's PII. No real user's data is touched.
- When real data is unavoidable (e.g. a public endpoint returns live records),
  capture the **minimum**: redact/truncate every value, record the field *names*
  and a count, not the contents.
- **Never** download, store, or exfiltrate PII in bulk, enumerate ID ranges to
  pull many records, or retain raw PII in notes, screenshots, or the repo.
- If you accidentally receive bulk PII, do not save it — report the endpoint and
  the single-record proof only.

Violating this turns an authorized test into the exact harm you're reporting.
The payout and the ethics both depend on restraint.

---

## When to Use

- After finding an IDOR, broken object/function authorization, or a verbose API —
  to characterize *what sensitive data* the flaw exposes (drives severity).
- When an endpoint returns user objects, exports, invoices, tickets, or profiles.
- To check whether error pages, caches, logs, or source leaks contain PII.
- To confirm PII indexed by search engines or left in client-side bundles.
- When triaging: "is this just an ID leak, or does it expose regulated data?"

---

## Prerequisites

- `curl`, `python3` (standard Linux).
- **Two test accounts you control** (A and B) wherever the app allows signup —
  the safest way to prove cross-user exposure.
- Written authorization, including whether real-user data may be viewed at all
  (many programs forbid accessing other users' real data — respect that; use test
  accounts only).
- Output location (store **only redacted** evidence here):
  ```bash
  export OUTPUT_DIR="${OUTPUT_DIR:-./output}"
  mkdir -p "$OUTPUT_DIR"
  export TS=$(date -u +%Y-%m-%d_%H-%M)
  export TARGET="app.example.com"
  ```

---

## How to Run

```bash
# Scan a single captured response body for PII patterns (redacts as it reports)
python3 pii_scan.py --file response.json --redact

# Or pipe a live response straight into the scanner (test-account traffic)
curl -s --max-time 10 -H "Authorization: Bearer $TOKEN_A" \
  "https://$TARGET/api/v1/users/$ACCOUNT_B_ID" | python3 pii_scan.py --redact
```

`pii_scan.py` is defined inline in **Procedure**. It reports PII *types* and
*counts* with redacted samples — it never prints full values.

---

## Procedure

### Step 1 — The PII detector (`pii_scan.py`)

Detection is pattern + context. The scanner flags candidate PII, redacts it on
output, and (for the high-FP classes like SSN/card) runs a checksum so you don't
report a random 16-digit order number as a credit card.

```python
#!/usr/bin/env python3
"""Scan a response body for PII. Reports TYPES and COUNTS with redacted samples.
Never prints full values. Validates card (Luhn) and SSN structure to cut FPs.
Usage: pii_scan.py --file resp.json [--redact]   OR   cat resp | pii_scan.py
"""
import argparse, re, sys, json
from collections import defaultdict

PATTERNS = {
    "email":        re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
    "phone_e164":   re.compile(r'\+?\d{1,3}[\s.-]?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}'),
    "ssn_us":       re.compile(r'\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'),
    "credit_card":  re.compile(r'\b(?:\d[ -]?){13,19}\b'),
    "ipv4":         re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "jwt":          re.compile(r'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'),
    "iban":         re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b'),
    "us_passport":  re.compile(r'\b[A-Z]\d{8}\b'),
    "dob_iso":      re.compile(r'\b(19|20)\d{2}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])\b'),
    "lat_long":     re.compile(r'\b-?\d{1,2}\.\d{4,},\s?-?\d{1,3}\.\d{4,}\b'),
    "api_key_like": re.compile(r'\b(sk_live_[0-9A-Za-z]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35})\b'),
}

# Field names that signal PII even when the value format is generic
PII_KEYS = re.compile(r'(?i)\b(ssn|social_?security|dob|date_?of_?birth|passport|'
                      r'national_?id|tax_?id|driver_?licen[sc]e|address|zip|postal|'
                      r'phone|mobile|salary|full_?name|first_?name|last_?name|'
                      r'card_?number|cvv|routing|account_?number|medical|diagnosis)\b')

def luhn_ok(num):
    d = [int(c) for c in re.sub(r'\D', '', num)]
    if not (13 <= len(d) <= 19):
        return False
    s, alt = 0, False
    for x in reversed(d):
        if alt:
            x *= 2
            if x > 9: x -= 9
        s += x; alt = not alt
    return s % 10 == 0

def redact(s):
    s = str(s)
    if len(s) <= 4:
        return "*" * len(s)
    return s[:2] + "*" * (len(s) - 4) + s[-2:]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file")
    ap.add_argument("--redact", action="store_true", default=True)
    args = ap.parse_args()
    body = open(args.file).read() if args.file else sys.stdin.read()

    counts = defaultdict(int)
    samples = {}
    for name, rx in PATTERNS.items():
        for m in rx.finditer(body):
            val = m.group(0)
            if name == "credit_card" and not luhn_ok(val):
                continue           # drop non-Luhn 13-19 digit noise
            if name == "ipv4" and all(0 <= int(o) <= 255 for o in val.split(".")) is False:
                continue
            counts[name] += 1
            samples.setdefault(name, redact(val))

    # Context: PII-signalling JSON keys present
    key_hits = sorted(set(k.lower() for k in PII_KEYS.findall(body)))

    print("=== PII EXPOSURE SCAN ===")
    if not counts and not key_hits:
        print("No PII patterns detected.")
        return
    for name in sorted(counts, key=lambda n: -counts[n]):
        print(f"  {name:14} count={counts[name]:<5} sample={samples[name]}")
    if key_hits:
        print(f"  [PII field names present]: {', '.join(key_hits)}")
    print("\nReminder: one record proves the bug. Do not pull more.")

if __name__ == "__main__":
    main()
```

### Step 2 — Prove cross-user exposure with test accounts (preferred path)

The cleanest, safest proof — no real user data involved:

```bash
# 1. Register/own accounts A and B. Capture B's object id and A's token.
# 2. As A, request B's resource. If A sees B's PII, that's the finding.
curl -s --max-time 10 -H "Authorization: Bearer $TOKEN_A" \
  "https://$TARGET/api/v1/users/$ACCOUNT_B_ID" \
  | tee "$OUTPUT_DIR/idor_proof_${TS}.json" \
  | python3 pii_scan.py --redact

# 3. Negative control: the same request with NO token (or A's own id) to show
#    the data is genuinely access-controlled elsewhere / the leak is real.
curl -s --max-time 10 "https://$TARGET/api/v1/users/$ACCOUNT_B_ID" -o /dev/null -w '%{http_code}\n'
```

If A retrieves B's email, address, phone, etc., you have a confirmed
authorization-driven PII exposure. **Stop here** — do not iterate IDs.

### Step 3 — Surface sweep (where PII leaks besides IDOR)

Check each surface with a single probe, scan the body, move on:

```bash
# a) Over-fetching APIs: does the endpoint return more fields than the UI shows?
curl -s --max-time 10 -H "Authorization: Bearer $TOKEN_A" \
  "https://$TARGET/api/v1/me" | python3 pii_scan.py --redact

# b) Export / report endpoints (often skip authz or over-share)
for P in /export /api/export /download/report /invoices /api/v1/orders; do
  curl -s --max-time 10 -H "Authorization: Bearer $TOKEN_A" \
    "https://$TARGET$P" | python3 pii_scan.py --redact
done

# c) Verbose errors: force an error, scan the stack/response for user objects
curl -s --max-time 10 "https://$TARGET/api/v1/users/%27" | python3 pii_scan.py --redact

# d) Client-side bundles & source maps (PII sometimes hardcoded in fixtures)
curl -s --max-time 10 "https://$TARGET/" | grep -oE 'src="[^"]+\.js"' | head -5
#    -> fetch each, pipe through pii_scan.py; see hunt-source-leak for map extraction

# e) Cache deception: can an attacker cache a victim's PII page under a public URL?
#    (see hunt-cache-poison — a cached /account.css-style path returning PII is Critical)
```

### Step 4 — Search-engine / public exposure (passive)

Use `hunt-google-dork` to find already-indexed PII — no target traffic:

```
site:{domain} filetype:xlsx OR filetype:csv (email OR phone OR ssn OR address)
site:{domain} filetype:pdf (confidential OR "patient" OR "personnel")
site:{domain} intext:"@{domain}" (password OR dob OR address)
site:pastebin.com "{domain}"
```

Indexed PII is a live exposure even if the app has since restricted the path —
confirm the cached copy, report the URL, store only a redacted sample.

### Step 5 — Classify what was exposed (drives severity)

Map the detected types to a sensitivity tier — this is what turns "an ID leaked"
into a severity a triager can rank:

| Tier | Data types | Typical severity |
|---|---|---|
| **Regulated / highly sensitive** | SSN, passport, national ID, full card + CVV, medical/diagnosis, biometric, government creds | Critical |
| **Financial / identity** | Full name + DOB + address combo, bank/IBAN, partial card, tax id, salary | High |
| **Direct identifiers** | Email, phone, home address, precise geolocation, auth tokens | Medium–High |
| **Indirect / low** | Internal user id, IP alone, username, coarse location | Low–Medium |

Severity rises with: number of people affected (prove *reachability* at scale
without actually pulling it — e.g. sequential IDs + no authz), whether data is
regulated (GDPR/HIPAA/PCI), and whether it's exposed unauthenticated.

---

## Pitfalls

- **Becoming the breach.** The single biggest risk: enumerating IDs to "show
  impact" and vacuuming thousands of real records. That is the crime you're
  reporting. Prove one, estimate reach by structure, stop.
- **Format FPs.** A 16-digit order number isn't a credit card (Luhn-check it). A
  9-digit id isn't an SSN (structure-check). A `uuid` isn't PII. Context + the
  checksum in `pii_scan.py` cut these, but eyeball high-tier hits.
- **Test data vs real data.** Staging often contains `test@test.com` / `John Doe`.
  That's not a reportable PII exposure. Confirm the data is real (or that the
  *production* endpoint behaves the same) before claiming impact.
- **Public-by-design PII.** Some fields are intentionally public (a seller's
  business email on a marketplace, a user's chosen public profile). Check the
  product's own privacy model before flagging.
- **Your own PII in reports.** Don't paste raw PII into the bug report, Slack,
  screenshots, or git. Redact. Triagers will reproduce from your steps.
- **Retention.** Delete any raw PII you incidentally captured once the redacted
  proof is written. Don't leave `response.json` full of real users in `output/`.
- **Rate/volume.** Even single-record probing across many endpoints adds up —
  rate-limit, and never loop an ID range.

---

## Verification

A PII-exposure finding is confirmed when **all** hold:

1. **Exposure path reproduces** from a clean session (fresh/unauth or a
   separate test account), not just your logged-in browser cache.
2. **The data is real PII**, not fixtures — or the production endpoint
   demonstrably returns the same structure for real users.
3. **An authorization boundary is actually crossed** — account A genuinely should
   not see account B's data (negative control: B's data is not public elsewhere).
4. **`pii_scan.py` identifies a real, high-signal type** (checksum-valid where
   applicable), with a redacted sample and the responsible field name.

Record per finding: the endpoint + method, UTC timestamp, the auth context
(which test account), the **redacted** single-record evidence, the negative
control (unauth/other-account result + status code), the PII tier from Step 5,
and a structural impact estimate ("ids are sequential and unauthenticated →
N records reachable") **without** having pulled them.

**Severity anchors:**
- Unauthenticated, regulated PII (SSN/medical/card), many users reachable: Critical
- Cross-user PII via IDOR, direct identifiers, authenticated: High
- Over-fetching API exposing email/phone beyond the UI: Medium–High
- Internal id / IP only, no direct identifier: Low
- Test/fixture data, or public-by-design fields: Informational
