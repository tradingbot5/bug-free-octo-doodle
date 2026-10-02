# CLAUDE.md — Bug Bounty & Offensive Security Harness

This file is the operating guide for working in this repository. It defines how
reconnaissance is run, the best practices that govern it, and how to route from
a recon signal into the right hunting skill. It complements, and does not
override, [SOUL.md](SOUL.md) (principles), [STRICTRULES.MD](STRICTRULES.MD)
(pipeline + folder discipline), and [STYLE.md](STYLE.md) (skill quality
baseline).

---

## 0. Authorization & Rules of Engagement — read first, non-negotiable

Everything here is for **authorized security testing only**: targets you own,
or a bug-bounty/pentest program with written permission. Before a single
request:

1. **Confirm the asset is in scope** — the program policy / SOW decides, not a
   scanner's "owned" label. For dictionary-word brands, run
   `newskills/recon-scope-triage` first; ownership is guilty-until-proven.
2. **Confirm the vulnerability class is eligible** and not explicitly excluded.
3. **Respect program rules** — rate limits, test accounts only, no automated
   scanning where forbidden, honor the stop conditions.
4. **Minimal side effects** — prefer passive/read-only. Before any request that
   creates, changes, deletes, sends, purchases, publishes, authenticates as
   another user, or affects availability, get explicit authorization for that
   action. Prove with the least data and smallest state change.
5. **Never** perform DoS/stress testing, mass account creation, credential
   attacks against real users, access to other users' real data beyond a
   minimal proof, social engineering of staff outside RoE, or persistence/
   backdoors. Demonstrate the primitive; do not operationalize harm.
6. **Data minimization** — one record or a `totalCount` proves an access bug;
   never bulk-exfiltrate. Redact evidence (`newskills/evidence-hygiene`).

A technically valid probe outside scope is still an invalid test.

---

## 1. How to operate in this repo

**Folder discipline** (see STRICTRULES.MD for the full contract):

| Folder | Use |
|---|---|
| `recon/` | Discovery, enumeration, intelligence gathering skills |
| `newskills/` | The hunting-skill catalog: `hunt-*` vuln classes, platform playbooks, process/reporting skills |
| `chains/` | Multi-step attack-path construction |
| `auth/` | Authentication / SSO testing |
| `payloads/` | Wordlists and injection strings (SQLi/SSTI/SSRF/LFI/XSS/cmd, dirs, creds) |
| `nuclei-templates/` | Nuclei templates — source from here, not default paths |
| `${OUTPUT_DIR:-./output}` | **All** scan output, PoCs, logs, reports — timestamped (`target_YYYY-MM-DD_HH-MM_*.md`) |

```bash
export OUTPUT_DIR="${OUTPUT_DIR:-./output}"
mkdir -p "$OUTPUT_DIR"
```

**Skill conventions (established across `newskills/`):**
- Each `SKILL.md` carries frontmatter: `name`, `description`, `sources`, and
  for vuln classes `cwe`, `cvss_baseline` (a severity anchor), and
  `related_skills`. Vuln skills have **Attack Surface Signals**, a
  **step-by-step methodology**, **New Techniques (2024-2026)**, **Remediation**,
  and a **validation gate**.
- **Load the smallest set of skills** that explains the observed surface
  (SOUL.md "Focused Loading"). Route by signal; don't dump the whole catalog.
- **Evidence before severity.** Do not infer impact from a banner, version,
  status code, open port, or header. Confirm the behavior and record the
  negative control.
- **Never fabricate** endpoints, responses, callbacks, credentials, report IDs,
  bounty amounts, or impact. Label each claim **Confirmed / Strongly suspected
  / Needs verification / Not a vulnerability.**
- Concurrency is a risk control, not a default — start low, derive it from
  scope and target stability.

---

## 2. Engagement workflow (five phases)

```
Scope ─► Recon ─► Mapping ─► Hunting ─► Validation ─► Reporting
         (pipeline)          (route to newskills/)   (gate)
```

The workflow is **non-linear**: discovery creates hypotheses, enumeration adds
context, each hunting skill tests one hypothesis, and chains combine only
verified facts. Each stage must reduce uncertainty and decide the next. Do not
jump to exploitation before the attack surface is mapped (`Section 3`), unless a
pre-auth critical (e.g. an exposed admin/RCE surface) is already in hand.

---

## 3. Reconnaissance — step-by-step pipeline

Run from `recon/` (and `newskills/web2-recon`, `newskills/recon-scope-triage`).
Write every artifact to `${OUTPUT_DIR}`. This mirrors STRICTRULES.MD Phase 1,
organized by purpose and grounded in the public expert methodology bodies in
Section 9 (Jason Haddix's TBHM, Assetnote continuous recon, ProjectDiscovery
toolchain, tomnomnom's unix-pipe recon, OWASP WSTG/Amass).

**Recon is where bugs are won.** Depth of surface, not cleverness of payload,
decides the engagement — extract every subdomain, host, route, parameter,
object ID, and fingerprint before the first exploit. Prefer a wide, mature,
paid program with frequently-changing assets; new features and freshly-acquired
infrastructure are the least-tested surface.

### R0 — Scope, program selection & expansion (gate)
- Lock the canonical in-scope domains/apps, eligible classes, rate limits, and
  stop conditions. Establish the SSO tenant/brand as an ownership anchor.
- **Expand scope legitimately**: enumerate the org's acquisitions and
  subsidiaries (Crunchbase, press releases), reverse-WHOIS on registrant
  org/email (`whoxy`), and trademark/ASN pivots — then check each against the
  program policy before touching it.
- **ASN → CIDR**: `amass intel -asn <ASN>`, `asnmap -d <domain>`, `bgp.he.net`
  to recover owned IP ranges (a classic Haddix/Assetnote wide-recon move).
- Triage every ASM/recon feed for namespace collisions before testing
  (`newskills/recon-scope-triage`). Ownership is guilty-until-proven;
  quarantine anything not provably owned.

### R1 — Asset discovery (surface mapping)
- **Passive subdomains (breadth first):** `subfinder` (load API keys for all
  sources), `amass enum -passive`, `assetfinder`, `github-subdomains` /
  `gitlab-subdomains`, `chaos`; CT logs via `crt.sh` (filter by cert
  Organization) and `certspotter`. Aggregate + dedupe with `anew`.
- **Search-engine infra sources:** Shodan, Censys, FOFA, ZoomEye, Netlas,
  Quake — unify with `uncover`. Pull `ssl.cert`, `http.favicon.hash`, and
  `http.html` pivots to find siblings. SecurityTrails, VirusTotal, AlienVault
  OTX, DNSDumpster, Rapid7 FDNS for historical DNS.
- **Favicon-hash pivot:** compute the mmh3 favicon hash and pivot in
  Shodan/FOFA (`fav-up`) to find same-app hosts behind different names;
  **JARM** fingerprint to cluster infra.
- **Cloud asset enumeration:** `cloud_enum`, `cloudlist`, S3/GCS/Azure bucket
  brute (`S3Scanner`, `GCPBucketBrute`) seeded from the brand + permutations.
- **Active DNS brute + permutation (depth):** `puredns bruteforce` /
  `shuffledns` + `massdns` with Assetnote's `best-dns-wordlist`; permute with
  `gotator`/`dnsgen`/`alterx`; resolve and wildcard-filter with `dnsx`.
- Confirm ownership (ASN/BGP, RDAP registrant, DNS chain to an owned apex)
  before accepting an asset.

### R2 — Infrastructure & liveness
- ASN/CIDR mapping (`asnmap`, `bgp.he.net`) for IP ranges you own.
- Probe with `httpx` (`-title -tech-detect -sc -cl -hash` to dedupe); capture
  status, title, tech, TLS, redirects.
- Visual recon (`aquatone`/`gowitness`) to spot login portals, admin panels,
  default pages fast.

### R3 — Crawl & historical mining
- Crawl live hosts: `katana` (`-jc -jsl` jsluice mode), `hakrawler`.
- Historical URLs: `gau`, `waybackurls`, CommonCrawl, OTX.
- Extract parameters (`gf`, regex) into a master param list
  (`id= file= redirect= url= token= next= callback=`).

### R4 — Content & parameter discovery
- **Directory/file fuzzing:** `ffuf`/`feroxbuster` with **Assetnote wordlists**
  (`httparchive_directories`, `raft`, `commonspeak2`) and `payloads/`;
  recursive where sensible, add tech-appropriate extensions; always calibrate
  against a soft-404/junk-path control (per `newskills/recon-scope-triage`).
- **403/401 bypass** on discovered-but-blocked paths: `byp4xx`/`nomore403` and
  manual tricks — path-case, `//`, `/.`, `/%2e/`, `;/`, trailing `..;/`,
  `X-Original-URL`/`X-Rewrite-URL`, method swap, `X-Forwarded-For`. (Feeds
  `newskills/hunt-auth-bypass`, `newskills/hunt-host-header`.)
- **VHOST fuzzing** (`ffuf -H "Host: FUZZ.target"`) to reach internal apps on
  shared IPs.
- **Sensitive files/exposure:** `.env`, `.git/`/`.svn/` (`git-dumper`),
  backups (`~`/`.bak`/`.old`/`.swp`), `config.*`, `/debug`, `/actuator`,
  `/.well-known`, source maps, `DS_Store` (`ds_store_exp`).
- **Hidden parameters:** `arjun`/`x8`/Param Miner (headers + body + query);
  seed from the master param list built in R3.
- **API routes:** `kiterunner` (`kr` with route-kite wordlists) and
  bundle-derived routes (`newskills/hunt-shadow-api`, `newskills/hunt-spa-api`);
  pull Swagger/OpenAPI/GraphQL schemas.
- **Non-exploit Nuclei** (`tech-detect`, `misconfiguration`, `exposures`,
  `takeovers`) from `nuclei-templates/` with strict rate limits; chain
  `subfinder → httpx → nuclei` and **manually verify every hit.**

### R5 — Client-side / JS / source analysis (read JS like source code)
- **Harvest every bundle:** `subjs`/`getJS` + the R3 crawl; then extract
  endpoints/hosts/params/secrets with **`jsluice`** (parser-based, beats
  regex), `LinkFinder`/`xnLinkFinder`, and `SecretFinder` (`recon/js-secrets-extraction`,
  `newskills/hunt-source-leak`).
- **Reconstruct source from `*.js.map`** (`sourcemapper`/`unwebpack-sourcemap`)
  to read original TS/JSX — route names, auth logic, feature flags, hidden
  endpoints. Don't stop at HTML-referenced bundles: follow webpack async-chunk
  maps, `__NEXT_DATA__`/RSC (`self.__next_f`), `window.__ENV`, `/config.js`.
- **Secret scanning + validation:** `trufflehog`/`gitleaks` over the downloaded
  tree; classify before claiming impact (most `AIza*` are Maps/analytics —
  test `identitytoolkit`; `sk_live_`/`AKIA`/`ghp_`/`xoxb-` validate
  reachability). Check **git history**, not just HEAD.
- **Dependency-confusion leads:** internal package names in bundles/
  `package.json` not on the public registry → `newskills/supply-chain-attack-recon`.
- **Mobile feeds web:** pull endpoints/keys from APK/IPA
  (`apk-redteam-pipeline`, `ios-redteam-pipeline`) — mobile backends are often
  an older, less-guarded API version (`newskills/hunt-shadow-api`).

### R6 — Port & service discovery
- `naabu`/`nmap`/`masscan` for open ports (22, 3306, 6379, 9200, 5432, 3389,
  5900, 8080, 8443, 50051); cross-reference with discovered web hosts.
- Flag exposed services for the platform playbooks (`hunt-k8s`, `hunt-grpc`,
  `cloud-iam-deep`, `enterprise-vpn-attack`, `vmware-vcenter-attack`).

### R7 — Attack-surface correlation (gate → hunting)
- Produce a prioritized attack-surface report in `${OUTPUT_DIR}`: live hosts,
  tech stack, API surface, auth flows, roles/tenants, object IDs, parameters,
  trust boundaries.
- Map each signal to a hunting skill (Section 5 routing table). Prioritize by
  impact potential and duplication risk.

### R8 — Continuous recon & monitoring (the expert edge)
The highest-ROI assets are the ones that appeared *since the last hunter looked*.
- **Automate the pipeline** so it reruns on a schedule: `axiom`/`osmedeus`/
  `reconFTW`/`reNgine`, or a simple cron of
  `subfinder → dnsx → httpx → nuclei` piping new results through `anew` into
  `notify` (Slack/Discord/Telegram).
- **Diff over time** — alert on new subdomains, new live hosts, new JS bundles,
  changed `httpx -hash`/titles, and new open ports. Hit new assets first.
- **Monitor for subdomain takeover continuously** (`subzy`/`nuclei takeovers`)
  and for newly-disclosed CVEs affecting the target's fingerprinted stack
  (`cvemap`, vendor advisories).
- Keep a per-target **knowledge base** in `${OUTPUT_DIR}` (hosts, tech, params,
  IDs, auth flows) so every session builds on the last.

---

## 4. Reconnaissance — best practices

- **Scope and ownership first.** Keyword matches lie; anchor every asset to a
  concrete ownership signal. Never test a same-named third party.
- **Passive before active.** Exhaust passive sources before touching the target;
  throttle active discovery to the program's limits.
- **Breadth then depth.** Enumerate the whole surface before deep-diving one
  host — the highest-value bug is usually not on the obvious app.
- **Map trust boundaries, not just endpoints.** Note where auth is enforced
  (gateway vs route), tenant/org boundaries, roles, and object ownership —
  that's where authz bugs live.
- **Harvest identifiers for later.** Object IDs, UUIDs/GIDs, org/tenant IDs,
  emails, tokens in responses feed IDOR/BOLA and chaining.
- **Diff everything.** Status, length, headers, timing, redirects, and behavior
  across accounts/roles/versions reveal more than visible content.
- **Prefer multiple legitimate test accounts/roles** (A, B, admin, second
  tenant) so authorization boundaries can be tested systematically.
- **Every artifact persists, timestamped, in `${OUTPUT_DIR}`** — recon is
  evidence, and reruns must be comparable.
- **Verify, don't trust, tooling.** Manually confirm every scanner "finding";
  run a soft-404/junk-path control; retract echoed-input and lone status-code
  "hits".
- **Recon never fully stops.** New subdomains, versions, and parameters appear
  mid-engagement; keep the surface report live.
- **Minimal footprint.** Low-and-slow, no destructive probes, honor robots of
  engagement over robots.txt.
- **Automate the boring, think on the interesting.** Pipe tools together
  (tomnomnom-style: `httpx | gf | ffuf`), save everything, and spend human
  attention on logic and chaining — not on work a tool does better.
- **Wordlists are a force multiplier.** Use curated, target-shaped lists
  (Assetnote, SecLists, `commonspeak2`) over generic ones; build custom lists
  from the target's own JS/responses.
- **Hunt where others don't.** Mobile/legacy/`/v1/` APIs, staging/dev/preview
  hosts, GraphQL, webhooks, import/export, and brand-new features have the
  lowest duplication rate and the weakest controls.
- **Read JS as source.** The frontend ships the backend's route map, roles,
  and sometimes secrets — map the API from the bundle, then test the API, not
  the UI.
- **Keep the surface report live.** Recon never fully ends; re-run on a cadence
  and attack the delta first (R8).

---

## 5. Hunting skills (`newskills/`) — routing & catalog

After R7, load the skill whose **Attack Surface Signals** match. Each skill
documents methodology, current techniques, remediation, and a validation gate.
Use `newskills/bb-methodology` or `newskills/hunt-dispatch` to orient, and
`newskills/security-arsenal` for the payload bank.

### Expert operating model (how top hunters actually work)

Grounded in the public methodology of practitioners in Section 9 and the
HackerOne Hacktivity / PortSwigger "Top 10 Web Hacking Techniques" trend lines:

1. **Pick one feature and go deep.** Exercise a single feature end-to-end
   (create → read → update → delete → share → export → cancel), capturing every
   request. Map its **state machine** — the forgotten transition is the bug.
2. **Think like the developer.** Ask *where would they skip the check?* — a new
   endpoint added after the middleware, a mobile/legacy path, a bulk/export
   route, a second HTTP verb, a nested object. Authz bugs cluster at those
   seams.
3. **Baseline, then run "what-if" experiments.** Establish normal behavior,
   change exactly one thing (an ID, a role, a param, a method, a content-type),
   and diff status/length/timing/headers/behavior. One variable at a time.
4. **Always test with two accounts and across roles/tenants.** Replay A's
   requests as B (and as anon) — Burp **Autorize**/**AuthMatrix** make this
   systematic. Cross-user/cross-tenant is the #1 paid class.
5. **Test the API, not the UI.** The UI is a suggestion; the backend is the
   target. Hit the routes from R5 directly, unauthenticated and under-privileged.
6. **Chain primitives.** A lone open-redirect, info-leak, or read-IDOR is Low;
   composed into OAuth-token theft, ATO, or financial impact it's Critical.
   Every `hunt-*` skill has a **Chains & Compositions** section — use it, and
   `chains/cross-attack-chains`.
7. **Prioritize by real-world payout/signal** (highest first): broken access
   control (IDOR/BOLA/BFLA), SPA→hidden-API exposure, SSRF→cloud-metadata,
   business-logic/payment abuse, OAuth/SSO→ATO, injection→RCE, then the rest.
   Don't grind low-impact header findings.
8. **Verify before you believe.** A 200 isn't impact; confirm the crossed
   boundary, record the negative control, pass `newskills/triage-validation`.

**Access control & authorization**
- `hunt-idor` — object-level authz (IDOR/BOLA), cross-tenant, chaining.
- `hunt-api-authz` — BOLA/BFLA/privilege-escalation audit across REST/GraphQL.
- `hunt-auth-bypass` — cross-protocol auth bypass, forced-browsing, middleware gaps.
- `hunt-business-logic`, `hunt-payment-security`, `hunt-fintech-graphql` — logic/financial abuse.

**Authentication / identity / session**
- `hunt-oauth`, `hunt-saml`, `hunt-jwt-crypto`, `hunt-mfa-bypass`,
  `hunt-forgot-password`, `hunt-session`, `hunt-ato`, `hunt-brute-force`,
  `hunt-captcha-bypass`, `auth/saml-sso-attack`.

**Injection & code execution**
- `hunt-sqli`, `hunt-sqliv2`, `hunt-nosqli`, `hunt-ssti`, `hunt-rce`,
  `hunt-deserialization`, `hunt-lfi`, `hunt-xxe`, `hunt-ldap`,
  `hunt-prototype-pollution`.

**Client-side**
- `hunt-xss`, `xss-wafbypass`, `hunt-dom`, `hunt-html-injection`,
  `hunt-clickjacking`, `hunt-cors`, `hunt-csrf`.

**Server-side request / request handling**
- `hunt-ssrf`, `hunt-host-header`, `hunt-cache-poison`, `hunt-http-smuggling`,
  `hunt-open-redirect`, `hunt-websocket`.

**API surface**
- `hunt-api-misconfig`, `hunt-graphql`, `hunt-grpc`, `hunt-shadow-api`,
  `hunt-spa-api`, `recon/api-noauth-hunt`.

**Framework / platform specific**
- `hunt-nextjs`, `hunt-nodejs`, `hunt-laravel`, `hunt-springboot`,
  `hunt-aspnet`, `hunt-sharepoint`, `recon/flask-werkzeug-attack`.

**Infra / cloud / identity platforms**
- `hunt-cloud-misconfig`, `cloud-iam-deep`, `hunt-k8s`, `hunt-cicd`,
  `hunt-subdomain`, `hunt-tls-network`, `hunt-ntlm-info`,
  `enterprise-vpn-attack`, `vmware-vcenter-attack`, `m365-entra-attack`,
  `okta-attack`, `supply-chain-attack-recon`.

**AI / Web3**
- `hunt-llm-ai`, `hunt-rag-vector`, `web3-audit`, `meme-coin-audit`.

**Timing / misc**
- `hunt-race-condition`, `hunt-misc`, `hunt-exceptional-conditions`.

**Mobile**
- `apk-redteam-pipeline`, `ios-redteam-pipeline`.

**Recon / OSINT / meta**
- `recon-scope-triage`, `web2-recon`, `osint-methodology`, `offensive-osint`,
  `redteam-mindset`, `hunt-dispatch`, `bb-methodology`, `bug-bounty`,
  `bb-local-toolkit`.

**Chains**
- `chains/cross-attack-chains`, `chains/wordpress-full-compromise`, and each
  `hunt-*` skill's own "Chains & Compositions".

**Validation & reporting**
- `triage-validation`, `evidence-hygiene`, `report-writing`, `report-craft`,
  `bugcrowd-reporting`, `redteam-report-template`, `mid-engagement-ir-detection`.

### Recon-signal → skill routing

| Observed in recon | Load |
|---|---|
| JWT (`eyJ…`) in header/cookie/JS | `hunt-jwt-crypto`, then `hunt-auth-bypass` |
| SPA shell + big JS bundles / `*api*` host | `hunt-spa-api` → `hunt-api-misconfig`, `hunt-idor` |
| Versioned API paths / multiple specs | `hunt-shadow-api`, `hunt-api-authz` |
| GraphQL endpoint | `hunt-graphql` (fintech → `hunt-fintech-graphql`) |
| `redirect=`/`next=`/`url=` params | `hunt-open-redirect` → `hunt-ssrf`, `hunt-oauth` |
| Fetch-from-URL / webhook / PDF render | `hunt-ssrf`, `hunt-file-upload` |
| OAuth `/authorize`, SSO | `hunt-oauth`, `hunt-saml`, `hunt-clickjacking` |
| Forgot-password / reset flow | `hunt-forgot-password` → `hunt-host-header`, `hunt-ato` |
| Error page leaks stack/debug | `hunt-exceptional-conditions` → framework skill |
| `.env`/`.git`/`*.js.map`/secrets | `hunt-source-leak` → `hunt-cicd`, `supply-chain-attack-recon` |
| CDN + reflected Host/headers | `hunt-host-header`, `hunt-cache-poison`, `hunt-http-smuggling` |
| Cloud key / metadata reachable | `hunt-cloud-misconfig` → `cloud-iam-deep` |
| Exposed k8s/kubelet/etcd/CI | `hunt-k8s`, `hunt-cicd` |
| SSL-VPN / vCenter / SharePoint banner | `enterprise-vpn-attack` / `vmware-vcenter-attack` / `hunt-sharepoint` |
| LLM/chatbot/agent/MCP feature | `hunt-llm-ai`, `hunt-rag-vector` |
| Money/checkout/coupon/limit flow | `hunt-business-logic`, `hunt-payment-security`, `hunt-race-condition` |

---

## 6. Validation & triage gate

Before anything is reported, pass `newskills/triage-validation`:

1. **What can the attacker DO right now?** State it concretely.
2. **What does the victim LOSE?** Map to confidentiality/integrity/availability.
3. **Reproducible from scratch in ~10 minutes?** Fresh accounts, exact request,
   confirmed 200-with-data or state change, no reliance on pre-existing state.
4. **Negative control recorded?** Show the secure baseline (403/404/empty) that
   distinguishes the bug from a false positive.
5. **In scope, eligible, not a known/duplicate/intended behavior?**

Separate **Observed / Inferred / Confirmed / Not tested** (SOUL.md). A 200 with
no data, a reflected-but-not-executed payload, or a missing header with no
working PoC is **not** a finding.

---

## 7. Reporting standard

Use `newskills/report-writing` (+ `report-craft`, `bugcrowd-reporting`). Every
report contains: title; severity + rationale (CWE and CVSS — 4.0 where the
program accepts it, else 3.1, with the full vector string); affected asset;
endpoint/parameter; preconditions; reproduction steps; minimal safe PoC;
expected vs actual; security impact; attack scenario; redacted evidence
(`evidence-hygiene`); remediation. Structure for fast triage (human or
automated): impact + exact endpoint + copy-pasteable PoC up top. Do not inflate
severity — if something is informational, low-impact, duplicate-prone, or
intended, say so.

---

## 8. Hard "never" list

- Never test out of scope, or a same-named third party.
- Never run DoS/stress, mass registration, credential attacks on real users, or
  access real users' data beyond a minimal proof.
- Never fabricate evidence, report IDs, bounty figures, or impact.
- Never escalate a confirmed RCE/injection into destructive commands,
  persistence, or lateral movement beyond the minimal proof the program allows.
- Never push secrets or raw evidence into this repository — methodology only,
  evidence stays in `${OUTPUT_DIR}` and private stores.
- Never skip the validation gate to pad a report.

---

## 9. Grounding — expert sources

This harness distills publicly-available expert methodology and research. Use
these as the authoritative references; cite the specific write-up you actually
used, and **never fabricate a report ID, bounty amount, or quote.** When a
`hunt-*` skill references a disclosed HackerOne report, link the exact verified
URL — a missing citation beats a wrong one.

**Methodology & recon**
- Jason Haddix — *The Bug Hunter's Methodology (TBHM)* and recon talks (scope
  expansion, ASN/acquisition pivots, content discovery).
- Assetnote / Shubham Shah & Sean Yeoh — continuous recon, wordlists, Ground
  Control; "how we find bugs at scale."
- NahamSec, Ben Sadeghipour (`@nahamsec`/`@nahamsec`), Hakluke — recon workflow
  and JS/asset discovery.
- tomnomnom (Tom Hudson) — unix-pipe recon tooling (`gf`, `waybackurls`,
  `httprobe`, `anew`, `unfurl`, `meg`, `gron`).
- ProjectDiscovery — `subfinder`, `httpx`, `nuclei`, `katana`, `naabu`,
  `dnsx`, `notify`, `uncover`, `cvemap`, `interactsh`.
- OWASP — **Web Security Testing Guide (WSTG)**, **ASVS**, Amass.

**Vulnerability research**
- PortSwigger Research & **Web Security Academy**; James Kettle (albinowax) —
  HTTP desync/smuggling, web cache poisoning, Param Miner.
- Orange Tsai — SSRF, ProxyLogon/ProxyShell, request-routing attacks.
- Frans Rosén (Detectify) — subdomain takeover, postMessage, cloud/OAuth.
- Sam Curry, Corben Leo, and the broader HackerOne/Bugcrowd disclosed-report
  corpus (**Hacktivity**) for class patterns and real reproduction shapes.
- Well-written Medium/personal-blog write-ups **by recognized researchers** —
  use for technique, verify the primitive yourself before relying on it.

**How to use them here:** techniques enter a skill as *New Techniques
(2024-2026)* only after being validated and expressed as a reproducible,
responsibly-scoped procedure (SOUL.md). Expert write-ups inform the method; the
proof must still come from your own authorized test.
