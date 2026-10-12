---
name: hunt-google-dork
description: Search-engine dorking for authorized recon. Finds exposed files, panels, and leaks via public indexes.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires curl, python3; optional Google/Bing API keys
metadata:
  tags: [recon, osint, dorking, passive, discovery]
  category: recon
  related_skills:
    - hunt-source-leak
    - hunt-subdomain
    - offensive-osint
---

# HUNT-GOOGLE-DORK — Search-Engine Dorking for Authorized Recon

Dorking uses advanced search operators to surface content that public search
engines have already crawled and indexed. It is **passive**: you query the
engine, not the target. No packet reaches the target's infrastructure until you
choose to visit a result — and that visit is the first point where scope and
authorization apply.

> These skills are for authorized security testing only. Only test targets you
> own or have explicit written permission to test. Dorking indexes public data,
> but acting on a result (visiting, downloading, logging in) is a test action
> and must stay inside your authorized scope.

---

## When to Use

- At the **start** of recon, to map the indexed attack surface before active scanning.
- When you have a confirmed in-scope root domain and want exposed files, panels, or leaks.
- To find forgotten subdomains, staging hosts, and shadow IT referencing the target.
- To locate credential/secret leakage on third-party paste and code sites.
- When active enumeration is rate-limited or noisy and you need quiet coverage first.

---

## Prerequisites

- `curl` and `python3` (standard Linux).
- A confirmed, **written** authorization scope: in-scope domains and permitted test classes.
- Optional, for automation at volume (manual dorking needs none):
  - Google Programmable Search Engine API key + CX id, **or**
  - Bing Web Search API key.
- A writable output location:

```bash
export OUTPUT_DIR="${OUTPUT_DIR:-./output}"
mkdir -p "$OUTPUT_DIR"
export TS=$(date -u +%Y-%m-%d_%H-%M)
```

**Scope guard — set these before anything else:**

```bash
export TARGET_DOMAIN="example.com"          # root domain, in scope
export COMPANY="Example Corporation"        # legal/brand name
```

---

## How to Run

```bash
# 1. Generate a dork list for the target
python3 gen_dorks.py --domain "$TARGET_DOMAIN" --company "$COMPANY" \
  > "$OUTPUT_DIR/${TARGET_DOMAIN}_dorks_${TS}.txt"

# 2a. Manual: open the top dorks in a browser, one at a time, and triage by hand.
# 2b. Automated (API): feed the list to the engine API with rate limiting.
python3 run_dorks.py --list "$OUTPUT_DIR/${TARGET_DOMAIN}_dorks_${TS}.txt" \
  --engine google --delay 3 \
  --out "$OUTPUT_DIR/${TARGET_DOMAIN}_dork_hits_${TS}.json"
```

Both helper scripts are defined inline in the **Procedure** section below — copy
them into your working directory (not into a downloaded-archive directory).

---

## Procedure

### Operator rules (read first)

- **Prefer the engine's official API** over scraping its HTML results page.
  Scraping Google's `/search` page violates its ToS and triggers CAPTCHAs and IP
  blocks. Use the Programmable Search API or Bing API for anything automated.
- **Rate-limit every engine call.** A human dorks a few queries a minute; match
  that. For API loops, `--delay 3` or more.
- **Dorking is read-only until you click.** Treat every result URL as untrusted
  and out-of-scope until you confirm its host is in your authorization.
- **Rotate engines.** Google, Bing, DuckDuckGo, Brave, Yandex index different
  corpora; the same dork returns different hits on each.

### Step 1 — Generate the dork list (`gen_dorks.py`)

```python
#!/usr/bin/env python3
"""Generate a prioritized dork list for one target. No network calls."""
import argparse

# Each template: (severity, category, query). {d}=domain {c}=company
TEMPLATES = [
    # --- Exposed files (highest value) ---
    ("CRIT", "files", 'site:{d} ext:env OR ext:ini OR ext:cfg OR ext:conf'),
    ("CRIT", "files", 'site:{d} ext:pem OR ext:key OR ext:p12 OR ext:pfx'),
    ("CRIT", "files", 'site:{d} ext:sql OR ext:dump OR ext:bak OR ext:old'),
    ("HIGH", "files", 'site:{d} inurl:.git OR inurl:/.git/'),
    ("HIGH", "files", 'site:{d} ext:log'),
    ("HIGH", "files", 'site:{d} intitle:"index of"'),
    ("MED",  "files", 'site:{d} ext:yml OR ext:yaml OR ext:properties'),
    ("MED",  "files", 'site:{d} ext:zip OR ext:tar.gz OR ext:tgz OR ext:rar'),
    # --- Admin / login panels ---
    ("HIGH", "panels", 'site:{d} inurl:admin OR inurl:login OR inurl:dashboard'),
    ("HIGH", "panels", 'site:{d} intitle:"phpMyAdmin"'),
    ("HIGH", "panels", 'site:{d} (intitle:"Jenkins" OR intitle:"GitLab" OR intitle:"Grafana")'),
    ("HIGH", "panels", 'site:{d} (intitle:"Kibana" OR intitle:"Splunk" OR intitle:"Sentry")'),
    ("MED",  "panels", 'site:{d} inurl:phpinfo OR inurl:server-status'),
    ("MED",  "panels", 'site:{d} (intitle:"Swagger" OR intitle:"OpenAPI" OR inurl:api-docs)'),
    # --- Secrets / credential leakage (third-party) ---
    ("CRIT", "secrets", '"{d}" "BEGIN RSA PRIVATE KEY"'),
    ("HIGH", "secrets", '"{d}" ("api_key" OR "apikey" OR "access_token")'),
    ("HIGH", "secrets", 'site:pastebin.com "{d}"'),
    ("HIGH", "secrets", 'site:gist.github.com "{d}"'),
    ("MED",  "secrets", 'site:rentry.co "{d}" OR site:hastebin.com "{d}"'),
    # --- Cloud / shadow IT ---
    ("HIGH", "cloud", 'site:s3.amazonaws.com "{d}"'),
    ("HIGH", "cloud", 'site:blob.core.windows.net "{d}"'),
    ("HIGH", "cloud", 'site:storage.googleapis.com "{d}"'),
    ("MED",  "cloud", 'site:trello.com "{d}" OR site:*.atlassian.net "{d}"'),
    ("MED",  "cloud", 'site:firebaseio.com "{d}" OR site:herokuapp.com "{d}"'),
    # --- Vulnerability indicators ---
    ("MED",  "vuln", 'site:{d} intext:"sql syntax" OR intext:"you have an error in your sql"'),
    ("MED",  "vuln", 'site:{d} intext:"stack trace" OR intext:"Traceback (most recent call last)"'),
    ("LOW",  "vuln", 'site:{d} inurl:wp-content OR inurl:wp-includes'),
    # --- Document / intel mining ---
    ("MED",  "docs", 'site:{d} filetype:pdf (confidential OR internal OR restricted)'),
    ("LOW",  "docs", 'site:{d} filetype:xlsx OR filetype:csv'),
    ("LOW",  "docs", 'site:scribd.com "{c}"'),
    # --- Subdomain / surface widening ---
    ("MED",  "surface", 'site:*.{d} -www'),
    ("MED",  "surface", 'site:{d} -site:www.{d}'),
]

ORDER = {"CRIT": 0, "HIGH": 1, "MED": 2, "LOW": 3}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain", required=True)
    ap.add_argument("--company", default="")
    args = ap.parse_args()
    rows = sorted(TEMPLATES, key=lambda t: ORDER[t[0]])
    for sev, cat, tmpl in rows:
        q = tmpl.format(d=args.domain, c=args.company)
        print(f"{sev}\t{cat}\t{q}")

if __name__ == "__main__":
    main()
```

### Step 2 — Run the dorks

**Manual (no API key, lowest friction):** open each query in a browser, work
top-down by severity, and record hits. This is the ToS-safe default and best for
small scopes.

**Automated via API (`run_dorks.py`):** use for large scopes. Requires an engine
API key — never scrape the HTML results page.

```python
#!/usr/bin/env python3
"""Run a dork list through an official search API with rate limiting.
Reads tab-separated SEV<TAB>CAT<TAB>QUERY lines on the dork list.
Env: GOOGLE_API_KEY + GOOGLE_CX  (engine=google)  |  BING_API_KEY (engine=bing)
"""
import argparse, json, os, sys, time, urllib.parse, urllib.request

def google(q):
    key, cx = os.environ["GOOGLE_API_KEY"], os.environ["GOOGLE_CX"]
    url = ("https://www.googleapis.com/customsearch/v1?"
           + urllib.parse.urlencode({"key": key, "cx": cx, "q": q, "num": 10}))
    with urllib.request.urlopen(url, timeout=15) as r:
        data = json.load(r)
    return [{"title": i.get("title"), "url": i.get("link"),
             "snippet": i.get("snippet")} for i in data.get("items", [])]

def bing(q):
    key = os.environ["BING_API_KEY"]
    url = "https://api.bing.microsoft.com/v7.0/search?" + urllib.parse.urlencode({"q": q, "count": 10})
    req = urllib.request.Request(url, headers={"Ocp-Apim-Subscription-Key": key})
    with urllib.request.urlopen(req, timeout=15) as r:
        data = json.load(r)
    return [{"title": i.get("name"), "url": i.get("url"),
             "snippet": i.get("snippet")} for i in data.get("webPages", {}).get("value", [])]

ENGINES = {"google": google, "bing": bing}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", required=True)
    ap.add_argument("--engine", choices=ENGINES, default="google")
    ap.add_argument("--delay", type=float, default=3.0)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    fn = ENGINES[args.engine]
    results = []
    for line in open(args.list):
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        sev, cat, q = (parts + ["", "", ""])[:3] if len(parts) >= 3 else ("?", "?", line)
        try:
            hits = fn(q)
        except Exception as e:
            print(f"[!] {q[:60]}... -> {e}", file=sys.stderr)
            time.sleep(args.delay)
            continue
        for h in hits:
            h.update({"severity": sev, "category": cat, "dork": q})
            results.append(h)
        print(f"[+] {sev:4} {cat:8} {len(hits):2} hits  {q[:50]}", file=sys.stderr)
        time.sleep(args.delay)
    json.dump(results, open(args.out, "w"), indent=2)
    print(f"[=] {len(results)} results -> {args.out}", file=sys.stderr)

if __name__ == "__main__":
    main()
```

### Step 3 — Classify and scope-filter hits

A dork hit is a **lead**, not a finding. Score each by URL signature, then
confirm the host is in scope before you ever open it.

```bash
python3 - "$OUTPUT_DIR/${TARGET_DOMAIN}_dork_hits_${TS}.json" "$TARGET_DOMAIN" <<'PY'
import json, sys, re
from urllib.parse import urlparse

hits = json.load(open(sys.argv[1]))
scope = sys.argv[2]

CRIT = re.compile(r'\.(pem|p12|pfx|key)$|id_rsa')
HIGH = re.compile(r'/\.env|/\.git/|\.(sql|dump|bak|old)$|phpmyadmin|phpinfo|jenkins')
MED  = re.compile(r'/admin|/login|/swagger|\.log$|/backup|\.DS_Store')

def sev(u):
    p = urlparse(u).path.lower()
    if CRIT.search(p): return "CRITICAL"
    if HIGH.search(p): return "HIGH"
    if MED.search(p):  return "MEDIUM"
    return "INFO"

for h in hits:
    host = urlparse(h["url"]).netloc.lower()
    in_scope = host == scope or host.endswith("." + scope)
    tag = "IN-SCOPE" if in_scope else "OUT-OF-SCOPE (third-party; do not test)"
    print(f"[{sev(h['url']):8}] {tag:40} {h['url']}")
PY
```

- **IN-SCOPE** hits on your authorized domain → queue for the matching hunt skill.
- **OUT-OF-SCOPE** hits (a leak on `pastebin.com`, an S3 bucket owned by a third
  party) → **do not test**. Report the exposure to the program as an observation;
  the act of exploiting a third-party host is not covered by your authorization.

### Step 4 — Hand off to active skills

| Dork category hit | Hand off to |
|---|---|
| `.env` / `.git` / source files | `hunt-source-leak` |
| `*.{domain}` new hostnames | `hunt-subdomain` |
| admin / login panels | `hunt-auth-bypass`, `hunt-brute-force` (within scope) |
| Swagger / OpenAPI / api-docs | `hunt-api-authz`, `hunt-shadow-api` |
| cloud buckets / Firebase | `hunt-cloud-misconfig` |
| paste/code secret leak | `offensive-osint` secret-validation flow |

---

## Pitfalls

- **Snippet ≠ confirmation.** A secret visible in a result snippet may be stale,
  redacted, or already rotated. Mark snippet-only matches TENTATIVE until the
  in-scope URL is confirmed.
- **Cached ≠ live.** Search caches lag. A dork hit may point to content the
  target already removed (404 live) — or the reverse, where content is live but
  not yet indexed. Dorking undercounts; it never proves absence.
- **Scraping gets you blocked.** Automated queries against the HTML results page
  trigger CAPTCHAs, 429s, and IP bans, and break the ToS. Use the official API.
- **`index of` false positives.** Many intentional public mirrors legitimately
  show `Index of /`. Confirm the listed files are actually sensitive before
  flagging.
- **Third-party hosts are a trap.** A bucket or paste that mentions your target
  is frequently owned by someone else. Testing it is unauthorized access against
  a non-target. Confirm ownership or treat as report-only.
- **Operator drift across engines.** `ext:` is Google syntax; Bing prefers
  `filetype:`. DuckDuckGo ignores some operators silently and returns broad
  results. Validate that the engine honored the operator before trusting zero
  results.
- **Parked / wildcard domains** answer every path with 200. Cross-check against
  `/robots.txt` and a random nonexistent path before trusting a hit.

---

## Verification

Every hit type needs a confirmation step before it becomes a finding:

- **Exposed file (`.env`, `.sql`, `.bak`):** fetch the in-scope URL and confirm
  it returns the sensitive body (not a soft-404 / login redirect). Record
  `http_code`, `content_type`, and the first non-empty, sensitive line.
  ```bash
  curl -s --max-time 10 -o /tmp/dork_hit -w '%{http_code} %{content_type} %{size_download}\n' "$HIT_URL"
  head -5 /tmp/dork_hit
  ```
- **`.git` exposure:** `curl .../.git/HEAD` returns a `ref:` line (not HTML).
- **Admin/login panel:** the page renders an authentication form on an in-scope
  host — confirmed exposure, not yet a vulnerability.
- **Swagger/OpenAPI:** the JSON parses and lists endpoints not visible in the UI.
- **Secret leak:** the credential is present AND validates against its service
  (see `offensive-osint` secret validators). A string that *looks* like a key
  but fails validation is INFO, not a finding.
- **Subdomain:** the host resolves and responds — then it enters `hunt-subdomain`.

**Severity guide:**
- Live `.env`/`.sql`/private key on an in-scope host, validated: Critical
- Exposed `.git` with secrets in history: Critical
- Validated secret in a paste/repo for an in-scope service: High
- Exposed admin panel (no bypass yet): Medium
- `index of` of non-sensitive files, robots.txt only: Informational

Record for each confirmed finding: the dork used, the engine, UTC timestamp,
the in-scope URL, the verification request/response (sanitized), and the
negative control that rules out a false positive.
