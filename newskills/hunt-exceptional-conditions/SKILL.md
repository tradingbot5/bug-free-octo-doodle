---
name: hunt-exceptional-conditions
description: "Hunt mishandling of exceptional conditions — feed an endpoint malformed/unexpected input (wrong type, broken JSON, oversized field, null byte) and make it fail OPEN or leak internals: a verbose stack-trace / framework error page that discloses ORM internals, server file paths, library versions, secrets, or a language traceback. Covers framework debug-mode disclosure (Werkzeug/Flask console PIN, Django DEBUG, Rails better_errors, Symfony profiler, Spring whitelabel+actuator), GraphQL error verbosity, type-confusion code-path divergence, and fail-open auth on exception. Use on any input-accepting endpoint (JSON APIs, forms, query params). Medium-High when the leak exposes internal structure that arms a deeper attack; Critical when debug mode yields RCE."
report_count: 0
sources: hackerone_public, owasp_top10_2021, public_research
cwe: [CWE-755, CWE-209, CWE-248, CWE-388, CWE-703]
cvss_baseline: "Low (3.7) generic 500 → Medium (5.3) stack trace / path / version disclosure → High-Critical (7.5-9.8) debug console RCE (Werkzeug PIN, Rails web-console) or fail-open auth."
related_skills: [hunt-sqli, hunt-lfi, hunt-source-leak, hunt-rce, hunt-graphql, triage-validation]
---

# HUNT-EXCEPTIONAL-CONDITIONS — Verbose Errors / Fail-Open (A10:2025)

## What actually pays

Well-built apps catch errors and return a clean, generic message. A broken app,
when handed input it didn't expect, throws an unhandled exception and renders a
**developer error page** straight to the client — leaking the stack trace, the
ORM/query internals, server-side file paths, and framework/library versions.
That disclosure is the finding (and it arms SQLi/RCE/path attacks next).

## Recon

Any endpoint that parses input is a candidate; the richest are:

```
JSON APIs that expect typed fields:  POST /api/* with {numbers, ids, enums}
Endpoints with numeric/id path or query params:  /item/{id}, ?page=, ?quantity=
Search / filter / sort params
File or content-type sensitive uploads
```

## Attack — send what the code didn't anticipate

Take a known-good request and break ONE assumption at a time:

- **Wrong type:** a field the app expects to be a number/string is sent as an
  array or object — `{"rating":"x","comment":[1,2,3]}`, `{"quantity":{}}`.
- **Malformed body:** truncated/!invalid JSON, an unterminated string, a stray
  brace, a wrong/missing Content-Type.
- **Boundary/oversized:** a very long string, a huge/negative/overflow number.
- **Null byte / control chars** embedded in a value.

```
POST /api/Feedbacks   {"rating":"notanumber","comment":[1,2,3]}
GET  /item/' OR /item/%00   (also exercises the error path)
```

Watch the RESPONSE BODY, not just the status: a 500 (or even a 200/400) whose
body contains a stack trace or framework error page is the signal.

## What counts as a leak (the success signal)

A finding is confirmed when the response body contains a cross-framework error-disclosure signature:

- **Node/Express + Sequelize:** `SequelizeDatabaseError`, `node_modules/sequelize`,
  a JS stack with internal paths.
- **PHP:** `<b>Warning</b> ... /var/www/.../file.php on line N`.
- **Python:** `Traceback (most recent call last)`, `werkzeug.exceptions`.
- **Java:** `at com.app.Foo(Foo.java:42)` stack frames.
- **.NET:** `Server Error in '/' Application`, a `[System.XxxException: ...]` YSOD.

A clean JSON error (`{"error":"Invalid input"}`) with no internals is NOT a
finding — that's correct handling. Disclosure of internal structure is.

## New Techniques (2024-2026)

### Framework debug-mode disclosure → sometimes RCE
A misconfigured `DEBUG`/development mode is the highest-impact version of this class. Fingerprint and escalate:
- **Flask / Werkzeug** — interactive traceback with the `/console` debugger. If reachable, the PIN is derivable from leaked machine data (MAC via `/sys`, username, module path) that the traceback itself often discloses → **RCE**. Signature: `Werkzeug Debugger`, `Traceback (most recent call last)` with a "console" link.
- **Django** — `DEBUG = True` yellow error page leaks settings (minus a few redacted), SQL, installed apps, env. Signature: `You're seeing this error because you have DEBUG = True`.
- **Rails** — `better_errors` / `web-console` gem in production gives a live REPL → **RCE**. Signature: a `>>` console in the error page.
- **Symfony** — `/_profiler`, `app_dev.php`, stack with full config. **Laravel** — `APP_DEBUG=true` Ignition page (CVE-2021-3129 chained to RCE). 
- **Spring Boot** — Whitelabel error page + exposed `/actuator/env`, `/actuator/heapdump` (secrets), `/actuator/mappings`. Signature: `Whitelabel Error Page`.
- **ASP.NET** — `customErrors mode="Off"` YSOD with full stack + source snippet.

### GraphQL error verbosity
Malformed queries, wrong types, or `aliases`/`@skip` abuse make resolvers throw; error messages often leak the full schema, internal field names, DB column names, and resolver file paths even when introspection is disabled. Send a field that doesn't exist and read the "Did you mean …" suggestion to reconstruct the schema. Cross-ref `hunt-graphql`.

### Type-confusion code-path divergence
Sending an array/object where a scalar is expected doesn't just error — it can route into an unguarded code path (NoSQL operator injection, mass-assignment, auth that evaluates a truthy object). Note *which* branch the exception exposes, not just the trace. Cross-ref `hunt-nosqli`, `hunt-api-misconfig`.

### Fail-OPEN on exception (the dangerous inverse)
Some error handlers default to *allow* when a check throws: a malformed token/role/tenant value crashes the authz check and the request proceeds authenticated. Probe auth/permission inputs with garbage and watch for a **200 with privileged data** instead of a 403. This is the critical case of this skill — far higher value than a stack trace. Cross-ref `hunt-auth-bypass`.

### Secrets in the trace
Modern traces frequently embed env vars, DB DSNs with passwords, API keys, and internal hostnames in the local-variable dump (Werkzeug, Sentry-style). Capture and treat as `hunt-source-leak` evidence.

## Tooling

- **Burp** — repeat a known-good request, mutate one assumption at a time; use the "Param miner" / content-type switch.
- **nuclei** — `exposures/` and `misconfiguration/` templates flag debug pages (Werkzeug, Django debug, actuator, Ignition) — authorized + rate-limited.
- **grep the response** for the framework signatures above.

## Remediation

- Disable debug/dev mode in production (`DEBUG=False`, `APP_DEBUG=false`, remove `better_errors`/`web-console`, `customErrors mode="On"`, Spring `server.error.include-stacktrace=never`, lock down `/actuator`).
- Return generic error bodies; log details server-side only; map all unhandled exceptions to a single 500 handler.
- Make authz/validation **fail closed** — any exception in a security check denies the request.
- Strip secrets from log/trace contexts; never render local variables to clients.

## Validation discipline / Gate

- Capture the exact leaked artifact (path, ORM class, version, stack frame, secret) — that's the evidence. "It returned 500" alone is not disclosure.
- For debug-console findings, demonstrate the console is reachable (and, only with explicit authorization and against your own test data, that it executes) — do not run destructive commands.
- For fail-open, show the 200+privileged-data vs the expected 403 differential.
- Note what the leak enables next (disclosed SQL error → `hunt-sqli`; absolute path → `hunt-lfi`; secret → `hunt-source-leak`; debug console → `hunt-rce`).

## Disclosed Report Patterns

Verify before quoting IDs/amounts.
- **Werkzeug debugger PIN derivation → RCE** — recurring when a Flask app ships with the debugger on in prod and the traceback leaks the machine fingerprint.
- **Laravel Ignition `APP_DEBUG=true` → RCE** (CVE-2021-3129 class).
- **Spring Boot actuator `/heapdump` secret exposure → credential reuse.**
- **Stack-trace path/version disclosure** — common medium-severity standalone, frequently chained.
