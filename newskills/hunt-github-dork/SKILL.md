---
name: hunt-github-dork
description: GitHub code-search dorking for authorized recon. Finds leaked secrets, endpoints, and configs.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires curl, python3, GitHub personal access token
metadata:
  tags: [recon, osint, dorking, github, secrets, passive]
  category: recon
  related_skills:
    - hunt-google-dork
    - hunt-source-leak
    - offensive-osint
---

# HUNT-GITHUB-DORK — GitHub Code-Search Dorking for Authorized Recon

GitHub code search indexes billions of public files. Developers routinely commit
secrets, internal hostnames, API routes, and config referencing their employer's
domain — often in personal repos outside the company's control. Dorking that
index surfaces those leaks. It is **passive against your target**: you query
GitHub's API, and nothing touches the target's own infrastructure.

> These skills are for authorized security testing only. Only test targets you
> own or have explicit written permission to test. A secret found in a public
> repo is an observation — validating it against a live in-scope service is a
> test action and must stay inside your authorization. Never commit, push, or
> modify a third-party repo, and never use a found credential beyond the minimal
> proof your scope permits.

---

## When to Use

- Early recon, to find credential and endpoint leakage referencing the target.
- When you have an in-scope root domain, org name, or product name to pivot on.
- To discover internal API routes, staging hostnames, and infra config in code.
- To find an organization's own repos and their committed secrets/history.
- Alongside `hunt-google-dork` — web dorking and code dorking surface different leaks.

---

## Prerequisites

- `curl`, `python3`, `git` (standard Linux).
- A **GitHub personal access token** — a fine-grained PAT with read-only public
  repo access is enough. Code Search API requires authentication.
  ```bash
  export GITHUB_TOKEN="ghp_...your_readonly_pat..."
  ```
- Optional secret scanners for validation: `trufflehog`, `gitleaks`.
- Written authorization scope: in-scope domains/services and permitted test classes.
- Output location:
  ```bash
  export OUTPUT_DIR="${OUTPUT_DIR:-./output}"
  mkdir -p "$OUTPUT_DIR"
  export TS=$(date -u +%Y-%m-%d_%H-%M)
  ```

**Scope guard:**
```bash
export TARGET_STEM="example"          # root domain stem (org/product keyword)
export TARGET_DOMAIN="example.com"    # full in-scope root domain
```

---

## How to Run

```bash
# 1. Generate GitHub code-search dorks for the target
python3 gen_gh_dorks.py --stem "$TARGET_STEM" --domain "$TARGET_DOMAIN" \
  > "$OUTPUT_DIR/${TARGET_STEM}_gh_dorks_${TS}.txt"

# 2. Run them through the GitHub Code Search API (rate-limited)
python3 run_gh_dorks.py --list "$OUTPUT_DIR/${TARGET_STEM}_gh_dorks_${TS}.txt" \
  --delay 6 --out "$OUTPUT_DIR/${TARGET_STEM}_gh_hits_${TS}.json"

# 3. Pull candidate files and scan for validated secrets
python3 scan_gh_hits.py --hits "$OUTPUT_DIR/${TARGET_STEM}_gh_hits_${TS}.json" \
  --out "$OUTPUT_DIR/${TARGET_STEM}_gh_secrets_${TS}.json"
```

All three helpers are defined inline in **Procedure**. Copy them into your
working directory.

---

## Procedure

### Operator rules (read first)

- **Authenticate; respect the limit.** The Code Search API caps at **10
  requests/minute** even authenticated. Use `--delay 6` or more. A 403 with
  `rate limit` means back off, not retry harder.
- **Read-only, always.** Never clone-and-push, never open issues/PRs, never fork
  into the target org. You are reading public code.
- **A match is a lead.** The search snippet is not proof. Fetch the file, then
  validate the secret against its service before calling it a finding.
- **Third-party repos are common.** A leak in `randomdev/dotfiles` referencing the
  target is still report-only — you may validate the key minimally if it unlocks
  an in-scope service, but you do not test the third party's repo or account.
- **Truncate evidence.** Record only the last 4 chars of any secret; never store
  full credentials in your notes or the repo.

### Step 1 — Generate dorks (`gen_gh_dorks.py`)

```python
#!/usr/bin/env python3
"""Generate GitHub code-search dorks for one target. No network calls."""
import argparse

# {s}=stem (e.g. 'example')  {d}=full domain (e.g. 'example.com')
TEMPLATES = [
    # --- Env / config files mentioning the target ---
    ("CRIT", "env",     '"{d}" filename:.env'),
    ("HIGH", "env",     '"{d}" filename:.env.example'),
    ("HIGH", "config",  '"{d}" filename:config'),
    ("HIGH", "config",  '"{d}" filename:credentials'),
    ("MED",  "config",  '"{d}" filename:settings.py'),
    ("MED",  "config",  '"{d}" filename:application.properties'),
    ("MED",  "config",  '"{d}" filename:docker-compose.yml'),
    # --- Cloud / provider keys in target context ---
    ("CRIT", "aws",     '"{s}" AWS_SECRET_ACCESS_KEY'),
    ("HIGH", "aws",     '"{s}" AWS_ACCESS_KEY_ID'),
    ("HIGH", "gcp",     '"{s}" "private_key" "service_account"'),
    ("HIGH", "azure",   '"{s}" AccountKey=  "blob.core.windows.net"'),
    # --- Generic secret patterns ---
    ("HIGH", "secret",  '"{s}" api_key'),
    ("HIGH", "secret",  '"{s}" secret'),
    ("HIGH", "secret",  '"{s}" "authorization: bearer"'),
    ("MED",  "secret",  '"{s}" password'),
    ("MED",  "secret",  '"{s}" token'),
    # --- Private keys ---
    ("CRIT", "key",     '"{d}" filename:id_rsa'),
    ("CRIT", "key",     '"{d}" "BEGIN RSA PRIVATE KEY"'),
    ("HIGH", "key",     '"{d}" filename:.git-credentials'),
    # --- Framework / CMS configs ---
    ("HIGH", "cms",     '"{d}" filename:wp-config.php'),
    ("MED",  "cms",     '"{d}" filename:.npmrc _authToken'),
    ("MED",  "cms",     '"{d}" filename:.pypirc'),
    # --- Internal endpoints / infra references ---
    ("MED",  "infra",   '"internal.{d}"'),
    ("MED",  "infra",   '"staging.{d}" OR "dev.{d}" OR "qa.{d}"'),
    ("MED",  "infra",   '"api.{d}" path OR route OR endpoint'),
    # --- Email + credential context ---
    ("HIGH", "email",   '"@{d}" password'),
    ("MED",  "email",   '"@{d}" smtp'),
]

ORDER = {"CRIT": 0, "HIGH": 1, "MED": 2, "LOW": 3}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stem", required=True)
    ap.add_argument("--domain", required=True)
    args = ap.parse_args()
    for sev, cat, tmpl in sorted(TEMPLATES, key=lambda t: ORDER[t[0]]):
        q = tmpl.format(s=args.stem, d=args.domain)
        print(f"{sev}\t{cat}\t{q}")

if __name__ == "__main__":
    main()
```

### Step 2 — Run the dorks (`run_gh_dorks.py`)

```python
#!/usr/bin/env python3
"""Run a dork list through the GitHub Code Search API, rate-limited.
Env: GITHUB_TOKEN. Reads SEV<TAB>CAT<TAB>QUERY lines.
"""
import argparse, json, os, sys, time, urllib.parse, urllib.request

API = "https://api.github.com/search/code"

def search(q, token):
    url = API + "?" + urllib.parse.urlencode({"q": q, "per_page": 20})
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.text-match+json",
        "User-Agent": "hunt-github-dork",
    })
    with urllib.request.urlopen(req, timeout=20) as r:
        data = json.load(r)
    out = []
    for i in data.get("items", []):
        frags = [m.get("fragment", "") for m in i.get("text_matches", [])]
        out.append({
            "repo": i["repository"]["full_name"],
            "path": i["path"],
            "url": i["html_url"],
            "raw": i["html_url"].replace("https://github.com/", "https://raw.githubusercontent.com/").replace("/blob/", "/"),
            "fragments": frags,
        })
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", required=True)
    ap.add_argument("--delay", type=float, default=6.0)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    token = os.environ["GITHUB_TOKEN"]
    results = []
    for line in open(args.list):
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        sev, cat, q = (parts + ["", "", ""])[:3] if len(parts) >= 3 else ("?", "?", line)
        try:
            hits = search(q, token)
        except Exception as e:
            print(f"[!] {q[:50]}... -> {e}  (backing off)", file=sys.stderr)
            time.sleep(args.delay * 3)
            continue
        for h in hits:
            h.update({"severity": sev, "category": cat, "dork": q})
            results.append(h)
        print(f"[+] {sev:4} {cat:7} {len(hits):2} hits  {q[:45]}", file=sys.stderr)
        time.sleep(args.delay)
    json.dump(results, open(args.out, "w"), indent=2)
    print(f"[=] {len(results)} results -> {args.out}", file=sys.stderr)

if __name__ == "__main__":
    main()
```

### Step 3 — Pull files and validate secrets (`scan_gh_hits.py`)

A search fragment is a lead. Fetch the raw file and run a secret catalog; only
patterns that match a known credential shape graduate to candidate findings.
Validation against the live service is a separate, scope-gated step.

```python
#!/usr/bin/env python3
"""Fetch raw files for GitHub hits and flag secret-shaped strings.
Does NOT call third-party services. Validation against live services is manual
and scope-gated. Env: GITHUB_TOKEN.
"""
import argparse, json, os, re, sys, time, urllib.request

CATALOG = {
    "aws_access_key":  re.compile(r'AKIA[0-9A-Z]{16}'),
    "aws_secret":      re.compile(r'(?i)aws_secret[^=:]*[=:]\s*["\']?([A-Za-z0-9/+=]{40})'),
    "google_api":      re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    "slack_token":     re.compile(r'xox[baprs]-[0-9A-Za-z-]{10,}'),
    "stripe_live":     re.compile(r'sk_live_[0-9A-Za-z]{24,}'),
    "github_pat":      re.compile(r'gh[pousr]_[0-9A-Za-z]{36,}'),
    "private_key":     re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    "jwt":             re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
    "generic_bearer":  re.compile(r'(?i)bearer\s+[A-Za-z0-9._\-]{20,}'),
}

def fetch(url, token):
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}", "User-Agent": "hunt-github-dork"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read(200_000).decode("utf-8", "replace")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hits", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--delay", type=float, default=1.5)
    args = ap.parse_args()
    token = os.environ["GITHUB_TOKEN"]
    findings = []
    for h in json.load(open(args.hits)):
        try:
            body = fetch(h["raw"], token)
        except Exception as e:
            print(f"[!] fetch {h['raw'][:50]}... -> {e}", file=sys.stderr)
            time.sleep(args.delay); continue
        for name, rx in CATALOG.items():
            m = rx.search(body)
            if m:
                tok = m.group(0)
                findings.append({
                    "type": name, "repo": h["repo"], "path": h["path"],
                    "url": h["url"], "severity": h["severity"],
                    "evidence": tok[:6] + "..." + tok[-4:],   # truncated
                    "status": "CANDIDATE - validate against service, in-scope only",
                })
                print(f"[SECRET] {name:16} {h['repo']}/{h['path']}", file=sys.stderr)
        time.sleep(args.delay)
    json.dump(findings, open(args.out, "w"), indent=2)
    print(f"[=] {len(findings)} candidate secrets -> {args.out}", file=sys.stderr)

if __name__ == "__main__":
    main()
```

### Step 4 — Scope decision and handoff

For each candidate secret, decide before acting:

| Where the leak lives | Who owns the credential's service | Action |
|---|---|---|
| Target org's own repo | In-scope service | Validate minimally, report as leak + working key |
| Third-party repo | In-scope service | Report-only; minimal validation if scope permits |
| Any repo | Out-of-scope / third-party service | Do not use; report the exposure as an observation |

| Candidate type | Hand off to |
|---|---|
| Live API key / cloud key | `hunt-cloud-misconfig`, `offensive-osint` validators |
| Internal hostname / staging URL | `hunt-subdomain`, `hunt-ssrf` (in scope) |
| API route / endpoint in code | `hunt-api-authz`, `hunt-shadow-api` |
| DB connection string | source-leak flow — do not connect unless scope permits |
| Private key / JWT signing key | report immediately; do not forge tokens unless authorized |

### Step 5 — Also enumerate the org's own repos

Beyond keyword dorks, enumerate the target organization directly and scan each
repo's **full history** (secrets are usually in old commits, not HEAD):

```bash
# List public repos for the org (paginate)
curl -s -H "Authorization: Bearer $GITHUB_TOKEN" \
  "https://api.github.com/orgs/$TARGET_STEM/repos?per_page=100&type=public" \
  | python3 -c 'import sys,json; [print(r["clone_url"]) for r in json.load(sys.stdin)]'

# For each repo, scan full git history (trufflehog finds rotated/old secrets)
trufflehog github --org="$TARGET_STEM" --only-verified 2>/dev/null | head -50
# or clone read-only and scan locally
git clone --mirror https://github.com/$TARGET_STEM/REPO.git /tmp/ghd_repo
gitleaks detect --source /tmp/ghd_repo --no-banner 2>/dev/null | head -50
```

---

## Pitfalls

- **Rate limit is brutal.** Code Search allows ~10 req/min. Hammering earns a
  403 and a cooldown. Space queries with `--delay 6+`.
- **Fragment ≠ live secret.** Most hits are placeholders (`API_KEY=your-key-here`),
  examples, or already-rotated keys. Only a service-validated key is a finding.
- **History hides the real leak.** Code Search indexes current file contents.
  A secret removed from HEAD but alive in history is invisible to the search API
  — that's why Step 5's full-history scan matters.
- **Namesake collisions.** A short stem (`acme`) matches unrelated projects.
  Pair the stem with the full domain or a unique internal hostname to cut noise.
- **Third-party repo trap.** Finding a key in someone's personal repo does not
  authorize you to touch that repo or their account. Report the exposure; only
  the in-scope service behind the key is (minimally) testable.
- **Secret scanners miss custom formats.** The catalog here covers common
  providers. A bespoke internal token won't match — read high-value files by eye.
- **Never write.** Forking, starring loudly, opening an issue "to notify them,"
  or pushing a PR all leave your identity on the target and can breach program
  rules. Report through the program channel instead.

---

## Verification

Each candidate needs a confirmation step before it is a finding:

- **Cloud key (AWS/GCP/Azure):** confirm it's live with a **read-only, benign**
  call for an in-scope service (e.g. `aws sts get-caller-identity`). A key that
  returns `InvalidClientTokenId` is dead → INFO. Record the identity returned,
  not the key.
- **Service token (Slack/Stripe/GitHub PAT):** confirm with the provider's
  lowest-privilege identity endpoint (e.g. token `auth.test` / `whoami`), never a
  write call. Stop at proof of validity.
- **Private key / JWT secret:** confirm the key material parses and matches an
  in-scope service's published public key or token. Do not forge tokens unless
  your authorization explicitly covers it.
- **Internal hostname / endpoint:** confirm it resolves/responds, then route to
  `hunt-subdomain` / `hunt-api-authz`.
- **DB connection string:** confirm format and host-in-scope; **do not connect**
  unless scope explicitly permits — a connection is active testing of data.

**Severity guide:**
- Validated live cloud/service key for an in-scope service: Critical
- Private key or token-signing secret for in-scope service: Critical
- Internal hostnames / undocumented API routes in code: Medium–High
- Placeholder/example/rotated keys, namesake matches: Informational

Record per confirmed finding: the dork used, UTC timestamp, repo URL + file path,
truncated evidence (last 4 chars), the validation request/response (sanitized),
and the negative control proving it isn't a dead/placeholder key.
