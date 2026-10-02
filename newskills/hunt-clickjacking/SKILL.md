---
name: hunt-clickjacking
description: "Hunt Clickjacking / UI-Redressing — missing X-Frame-Options / CSP frame-ancestors lets an attacker embed the target in an invisible iframe and trick victims into clicking hidden controls. Covers classic overlay framing, DoubleClickjacking (2024, bypasses X-Frame-Options AND SameSite), drag-and-drop data exfil, prefilled-form clickjacking, and gesture-jacking. Targets: login flows, money transfers, account settings, OAuth consent, 2FA-disable. Confirm by proving it frames in a real browser AND a sensitive state-changing action survives the cross-site context — header-absence alone is not a finding."
sources: hackerone_public, public_research, portswigger_research, evil_blog_yibelo
report_count: 6
cwe: [CWE-1021, CWE-451]
cvss_baseline: "Low (3.5) read-only / theoretical → Medium (5.4-6.5) state-changing action → High (7.1+) when chained to ATO (OAuth consent, email change)"
related_skills: [hunt-csrf, hunt-oauth, hunt-ato, hunt-host-header, evidence-hygiene]
---

## What is Clickjacking

Clickjacking (UI Redressing) loads a target page inside a transparent/low-opacity iframe on a malicious site. The victim sees the attacker's decoy UI but clicks the hidden target UI beneath it. No JavaScript on the target is required — the browser sends the victim's authenticated session with the framed request.

**Highest-value targets:**
- OAuth / social-login "Authorize app" consent dialogs → account linking / ATO
- Account settings (email change, password change, 2FA disable, API-key creation)
- Money transfer / checkout / "confirm payment" / subscription-upgrade buttons
- Admin actions (delete, promote user, change role, invite member)
- Login / authentication pages (login-CSRF via framed login form)

## Why Clickjacking Still Pays in 2025

The conventional wisdom "SameSite=Lax killed clickjacking" is wrong. Three modern realities keep it alive:
1. **DoubleClickjacking** (Paulos Yibelo, Dec 2024) defeats `X-Frame-Options`, `frame-ancestors`, AND `SameSite=Lax/Strict` because the sensitive click lands in a *top-level* window the victim already owns — not in a cross-site frame.
2. Many OAuth consent and SSO pages are deliberately frameable or use lax CSP for embedding partners.
3. SameSite defaults are per-browser and per-cookie; legacy session cookies explicitly set `SameSite=None` (common on B2B/SSO apps) still ride cross-site frames.

## Protection Headers

```
X-Frame-Options: DENY                               # strongest — blocks all framing
X-Frame-Options: SAMEORIGIN                          # same-origin frames only
Content-Security-Policy: frame-ancestors 'none'      # CSP equivalent of DENY (takes precedence over XFO)
Content-Security-Policy: frame-ancestors 'self'      # CSP equivalent of SAMEORIGIN
```

If NEITHER is present, the page is frameable from any origin. Note `frame-ancestors` overrides `X-Frame-Options` where both appear — check the CSP first. `ALLOW-FROM` is dead (deprecated, ignored by modern browsers); a page relying on it is effectively unprotected.

---

## Attack Surface Signals

- Response lacks both `X-Frame-Options` and CSP `frame-ancestors` on an HTML page carrying a state-changing control.
- `frame-ancestors` present but over-broad: `*`, `https:`, a wildcard subdomain (`*.partner.com`), or reflects an attacker-influenced value.
- OAuth `/authorize`, `/consent`, `/oauth/decision` endpoints that render a consent button.
- Session cookies set `SameSite=None; Secure` (grep `Set-Cookie`) — these survive cross-site framing.
- Single-page apps where the sensitive action is one same-origin navigation away (DoubleClickjacking target).
- Framebusting that relies only on JS (`if (top !== self)`) rather than headers — often bypassable with `sandbox` / `csp` iframe attributes.

---

## Step-by-Step Methodology

1. **Screen headers (candidate detection, not a finding).**
   ```bash
   curl -sI https://target.example/account/transfer | grep -iE 'x-frame-options|content-security-policy'
   ```
   If both are absent, OR `frame-ancestors` is over-broad, it's a candidate. If either is restrictive (`DENY`/`SAMEORIGIN`/`'none'`/`'self'`), classic framing is out — jump to DoubleClickjacking (step 5).

2. **Confirm it actually renders framed.** Load the minimal PoC below in a real browser. Watch for JS framebusting that blanks or redirects the frame.

3. **Confirm the session survives cross-site.** Log in as the victim test account in the same browser profile, then reload the PoC. The framed action must execute *authenticated*. If the session cookie is `SameSite=Lax/Strict`, classic overlay fails here — pivot to DoubleClickjacking.

4. **Confirm a sensitive state change.** The framed click must trigger a real, irreversible/sensitive action and you must verify the state changed server-side (email updated, app authorized, funds moved in a test account).

5. **Try DoubleClickjacking when SameSite blocks the classic path** (see dedicated section).

6. **Record the differential** — screenshot/recording of the overlay, the hidden control position, and the confirmed server-side state change.

### Minimal overlay PoC
```html
<!doctype html>
<meta charset="utf-8">
<style>
  #decoy { position:absolute; z-index:1; font:700 28px sans-serif; }
  iframe { position:absolute; top:0; left:0; width:1000px; height:800px;
           opacity:0.05; z-index:2; border:0; }
</style>
<div id="decoy">🎁 Click "Claim" to win…</div>
<iframe src="https://target.example/account/transfer"></iframe>
<!-- Align the decoy so the hidden sensitive button sits under the victim's cursor.
     Set opacity:1 during development to position precisely, then drop to 0.05. -->
```

---

## DoubleClickjacking (2024 — defeats XFO + SameSite)

**Source:** Paulos Yibelo, *DoubleClickjacking: A New Era of UI Redressing* (Dec 2024). Demonstrated against Shopify, Slack, and Salesforce account-level actions.

**Why it bypasses everything:** the sensitive click does not land inside a cross-site iframe. The attacker exploits the timing gap between `mousedown` and the second `click` of a double-click. The target is opened as a **top-level** window the victim already controls, so `X-Frame-Options`, `frame-ancestors`, and `SameSite` cookies are all irrelevant — it's a first-party interaction.

**Mechanics:**
1. Attacker page opens a popup (`window.open`) showing a decoy, e.g. "Double-click to verify you're human."
2. On the victim's first `mousedown`, the popup's `onmousedown`/`onclick` closes itself (`window.close()`) and the *opener* (attacker page) uses `window.location` to redirect itself to the sensitive target URL (e.g. the OAuth authorize/consent page, or settings confirmation).
3. The victim's second click of the double-click now lands on the freshly-navigated sensitive button in a window they themselves initiated.

**PoC skeleton:**
```html
<!-- attacker.html -->
<button onclick="go()">Verify you are human</button>
<script>
function go() {
  const w = window.open('decoy.html', '_blank', 'width=400,height=300');
  // When victim starts the double-click on the popup, the popup closes itself
  // and redirects THIS window to the sensitive, same-site target.
  const t = setInterval(() => {
    if (w.closed) { clearInterval(t);
      location = 'https://target.example/oauth/authorize?client_id=ATTACKER&...';
    }
  }, 50);
}
</script>
```
```html
<!-- decoy.html (served from attacker origin) -->
<h2>Double-click to continue</h2>
<button ondblclick="window.close()">Verify</button>
```
Tune: the decoy button position must sit over where the sensitive confirm button will render after redirect, so the second click lands on it.

**Highest-impact DoubleClickjacking targets:** OAuth "Authorize", "Install app", "Add to workspace", 2FA-disable confirm, API-token generation — all one-click confirmations that lead to ATO or persistent access.

---

## Other Modern Variants

- **Drag-and-drop clickjacking / data exfil** — frame the target, overlay a draggable decoy; trick the victim into dragging a token/secret rendered in the frame into an attacker-controlled drop zone. Works even with some framebusting.
- **Prefilled-form clickjacking** — if the framed form accepts attacker-controlled prefill via URL params (`?email=attacker@evil`), the single framed click submits attacker-chosen data (e.g. adds attacker as recovery email).
- **Gesture-jacking / cursorjacking** — hide the real cursor with CSS, draw a fake one offset, so the victim's perceived click target differs from the real one.
- **Sandbox-bypass of JS framebusting** — `<iframe sandbox="allow-forms allow-scripts">` (omit `allow-top-navigation`) neuters `top.location` framebusting while still allowing the framed form to submit.
- **Nested/double-framing** — frame-within-frame to bust `X-Frame-Options: SAMEORIGIN` set on an inner embeddable widget that performs a sensitive action.

---

## Tooling

- **Burp Suite** → *Clickbandit* (built-in): record a clickjacking PoC visually against the live target.
- **Browser DevTools** — position the decoy with `opacity:1`, then drop to `0.05` for the final PoC.
- Manual HTML PoC (above) loaded in Chromium — the only reliable proof; scanners that report "missing X-Frame-Options" produce the #1 clickjacking false positive.

---

## Common Root Causes

1. Security headers applied at the app layer but stripped/omitted by a reverse proxy or CDN for specific routes.
2. OAuth/SSO consent pages intentionally frameable for partner embedding, with no per-action re-confirmation.
3. Legacy session cookie set `SameSite=None` for cross-domain SSO, re-enabling classic overlay framing.
4. Framebusting implemented only in JavaScript (bypassable via iframe `sandbox`), with no header fallback.
5. `frame-ancestors` built from a regex that is unanchored or allows wildcard subdomains an attacker can register/takeover.

## Remediation

- Send `Content-Security-Policy: frame-ancestors 'none'` (or `'self'`) on every HTML response carrying a state-changing control; keep `X-Frame-Options: DENY` as a legacy fallback.
- **Against DoubleClickjacking:** disable sensitive buttons by default and enable them only after a verified, in-context user gesture (e.g. a short delay + explicit mouse movement on the real page); or require a second, non-timing-based confirmation step. Yibelo's recommended pattern is a JS guard that keeps critical controls inert until a genuine interaction sequence is observed.
- Require step-up re-authentication for high-value actions (transfers, email change, OAuth grant).
- Prefer `SameSite=Lax` (or `Strict`) on session cookies; avoid `SameSite=None` unless genuinely cross-site.

---

## Validation Gate (do not report without all three)

1. **Framed render confirmed** — target page visibly renders inside an attacker-origin iframe (classic) OR a top-level redirect lands under a double-click (DoubleClickjacking), captured on screen.
2. **Authenticated cross-site action survives** — the sensitive action executes while the victim test account is logged in, and the cookie context actually carries (verify server-side state changed).
3. **Sensitive state change** — email/password/2FA/OAuth-grant/funds, not a read-only or marketing page.

Reporting missing headers with no working frame/double-click PoC is a documentation-quality issue, not a vulnerability. The 200-but-SameSite-blocks-it clickjack is the #1 N/A driver for this class.

---

## False Positives

- Public, read-only pages lacking frame protection → informational.
- JSON/API/image endpoints → not clickjacking targets.
- Classic overlay against a `SameSite=Lax/Strict` session with no DoubleClickjacking path → not exploitable; do not file.

---

## Disclosed Report Patterns

Describe the *pattern* accurately; verify the exact report before quoting an ID/amount.
- **DoubleClickjacking on major SaaS consent flows** — Yibelo's disclosure demonstrated account-level takeover primitives on Shopify, Slack, and Salesforce via the double-click OAuth/consent path (evil.blog, Dec 2024).
- **OAuth authorize-page clickjacking → account linking** — recurring HackerOne pattern where a frameable `/authorize` consent dialog lets an attacker silently link the victim's account to an attacker-controlled identity (ATO).
- **2FA-disable / email-change via framed settings** — medium-severity clickjacks that become High when chained to password reset on the changed email.

---

## Chains & Compositions

- **Clickjacking → OAuth consent → ATO:** frame (or double-click) the `/authorize` page so the victim grants an attacker app, then use the token for full account access. Cross-ref `hunt-oauth`, `hunt-ato`.
- **Prefill clickjacking → recovery-email change → password reset → ATO:** single framed click sets attacker as recovery email; then standard reset. Cross-ref `hunt-ato` Path 2.
- **Clickjacking as login-CSRF:** frame the login form to log the victim into an attacker account, then harvest what they enter. Cross-ref `hunt-csrf`.

## Related Skills

- `hunt-oauth` — frameable consent/authorize pages are the top DoubleClickjacking target.
- `hunt-csrf` — SameSite analysis overlaps directly; login-CSRF pairs with UI redressing.
- `hunt-ato` — the payout multiplier: clickjacking that reaches email/2FA/OAuth becomes account takeover.
- `hunt-host-header` — over-broad/reflected `frame-ancestors` values tie into host-header trust bugs.
- `evidence-hygiene` — recording a clean clickjacking PoC (overlay + confirmed state change) without leaking the victim test account's cookies.
