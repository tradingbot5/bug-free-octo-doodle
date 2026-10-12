---
name: hunt-shodan-dork
description: Shodan dorking for critical infra leads. Confirm scope and ownership before touching any host.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires python3, curl, Shodan API key
metadata:
  tags: [recon, osint, shodan, infrastructure, exposure, passive]
  category: recon
  related_skills:
    - hunt-subdomain
    - hunt-cloud-misconfig
    - hunt-source-leak
    - hunt-pii-exposure
---

# HUNT-SHODAN-DORK — Shodan Dorking for Critical Infrastructure Leads

Shodan continuously scans the internet and indexes service banners, TLS certs,
open ports, and product fingerprints. Dorking that index surfaces a target's
exposed databases, admin panels, dev/staging hosts, leaked certs, and
misconfigured services — the highest-signal leads in external recon. Querying
Shodan is **passive**: you read Shodan's existing data; no packet reaches the
target. Scope and authorization apply the moment you connect to a host yourself.

> These skills are for authorized security testing only. Only test targets you
> own or have explicit written permission to test.

## The rule that keeps this safe

A Shodan result is a **lead about an IP**, and an IP is not automatically in your
scope. Before you interact with any host Shodan returns:

1. **Confirm ownership / scope.** The IP must belong to the target and fall
   inside your written authorization (verify via ASN, reverse-DNS, cert CN/SAN,
   or the program's asset list). Cloud IPs rotate — yesterday's target IP may be
   someone else's host today.
2. **An exposed datastore is proof-by-reachability, not by contents.** If Shodan
   shows an unauthenticated MongoDB/Elastic/Redis, confirm it answers
   unauthenticated — then **stop**. Do not read, dump, or enumerate the data.
   That crosses into `hunt-pii-exposure`'s one-record rule and, done wrong, is
   the breach you're reporting.
3. **Never act on out-of-scope hosts.** A juicy database on a third party's IP is
   report-only; you do not connect to it.

---

## When to Use

- Early external recon, to map internet-exposed services for an in-scope org.
- To find exposed databases, caches, and message queues (Mongo/Elastic/Redis/Kafka).
- To find admin panels, dev/staging hosts, and forgotten services by banner/cert.
- To pivot from a domain to its IP ranges/ASN and enumerate everything exposed.
- To find expired/misissued TLS certs and leaked internal hostnames in SANs.

---

## Prerequisites

- `python3`, `curl` (standard Linux).
- A **Shodan API key** (free tier works for basic search; paid unlocks filters/facets):
  ```bash
  export SHODAN_API_KEY="...your_key..."
  ```
- Optional: the official CLI (`pip3 install shodan`), `jq`.
- Written authorization scope: in-scope domains, **IP ranges/ASNs**, and permitted
  test classes. Shodan returns IPs — you need the IP scope to act on them.
- Output location:
  ```bash
  export OUTPUT_DIR="${OUTPUT_DIR:-./output}"
  mkdir -p "$OUTPUT_DIR"
  export TS=$(date -u +%Y-%m-%d_%H-%M)
  export TARGET_DOMAIN="example.com"
  export TARGET_ORG="Example Corporation"     # as it appears in Shodan 'org'/'asn'
  ```

---

## How to Run

```bash
# 1. Establish the target's IP footprint (ASN + org) — scope anchor
python3 shodan_dork.py --mode footprint --domain "$TARGET_DOMAIN" --org "$TARGET_ORG" \
  > "$OUTPUT_DIR/${TARGET_DOMAIN}_footprint_${TS}.txt"

# 2. Run the critical-lead dork pack, scoped to the org/ASN
python3 shodan_dork.py --mode hunt --org "$TARGET_ORG" --asn "AS12345" \
  --out "$OUTPUT_DIR/${TARGET_DOMAIN}_shodan_leads_${TS}.json"

# 3. Triage leads by severity; scope-filter before any host interaction
python3 shodan_dork.py --mode triage \
  --in "$OUTPUT_DIR/${TARGET_DOMAIN}_shodan_leads_${TS}.json"
```

`shodan_dork.py` is defined inline in **Procedure**.

---

## Procedure

### Operator rules (read first)

- **Scope first, always.** Anchor on the org's ASN(s) and known IP ranges, then
  constrain every dork with `org:`/`asn:`/`net:`/`ssl.cert.subject.cn:`. A bare
  product dork returns the whole internet — noise and out-of-scope hosts.
- **Reading Shodan is free of target impact. Touching a host is not.** Keep the
  two phases separate: dork → triage → (only in-scope) verify.
- **Respect Shodan's rate/credit limits.** Space queries; facets and filtered
  search consume query credits on the free tier.
- **Confirm the IP is still the target's** right before you connect — re-resolve
  the hostname and compare.

### Step 1 — Footprint: domain → IPs → ASN/org (the scope anchor)

```bash
# Resolve the domain and look up each IP's org/ASN via Shodan host API
for IP in $(python3 -c "import socket,sys; print('\n'.join(set(ai[4][0] for ai in socket.getaddrinfo('$TARGET_DOMAIN',443))))" 2>/dev/null); do
  curl -s "https://api.shodan.io/shodan/host/$IP?key=$SHODAN_API_KEY" \
    | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("ip_str"),"| org:",d.get("org"),"| asn:",d.get("asn"),"| ports:",d.get("ports"))'
  sleep 1
done
```

Record the **ASN(s)** and **org string** — these constrain every dork in Step 2.
Cross-check against the program's published asset list; an ASN that isn't the
target's (e.g. a shared CDN/cloud ASN) is not a scope boundary — fall back to
`ssl.cert.subject.cn:` and explicit `net:` ranges the program lists.

### Step 2 — The critical-lead dork pack (`shodan_dork.py`)

```python
#!/usr/bin/env python3
"""Shodan dorking for critical infra leads. Read-only against Shodan's API;
does NOT connect to any target host. Env: SHODAN_API_KEY.
Modes: footprint | hunt | triage
"""
import argparse, json, os, sys, time, urllib.parse, urllib.request

API = "https://api.shodan.io"

# (severity, label, query_fragment). Scope is appended at runtime via org/asn/net.
DORKS = [
    # --- Unauthenticated datastores (critical: reachable data) ---
    ("CRIT", "mongodb_open",      'product:MongoDB'),
    ("CRIT", "elastic_open",      'product:Elastic port:9200'),
    ("CRIT", "redis_open",        'product:Redis port:6379'),
    ("CRIT", "memcached_open",    'product:Memcached port:11211'),
    ("CRIT", "kafka_open",        'product:Kafka'),
    ("CRIT", "cassandra_open",    'port:9042 product:Cassandra'),
    ("CRIT", "couchdb_open",      'product:CouchDB'),
    ("CRIT", "mysql_exposed",     'port:3306 product:MySQL'),
    ("CRIT", "postgres_exposed",  'port:5432 product:PostgreSQL'),
    ("CRIT", "mssql_exposed",     'port:1433'),
    # --- Exposed admin / orchestration panels ---
    ("HIGH", "kibana",            'product:Kibana'),
    ("HIGH", "grafana",           'title:Grafana'),
    ("HIGH", "jenkins",           'title:Jenkins'),
    ("HIGH", "k8s_api",           'product:"Kubernetes" port:6443'),
    ("HIGH", "docker_api",        'port:2375 product:Docker'),
    ("HIGH", "rancher_portainer", 'title:Portainer OR title:Rancher'),
    ("HIGH", "phpmyadmin",        'title:phpMyAdmin'),
    ("HIGH", "jupyter_open",      'title:"Jupyter" "running"'),
    ("HIGH", "rabbitmq_mgmt",     'title:"RabbitMQ Management"'),
    # --- Remote access / infra ---
    ("HIGH", "rdp_exposed",       'port:3389'),
    ("HIGH", "vnc_noauth",        'port:5900 "RFB 003"'),
    ("HIGH", "smb_exposed",       'port:445'),
    ("MED",  "ftp_anon",          'port:21 "230 "'),
    # --- Web app / leak indicators ---
    ("HIGH", "env_banner",        'http.html:"DB_PASSWORD" OR http.html:"APP_KEY"'),
    ("HIGH", "git_exposed",       'http.title:"Index of /.git"'),
    ("MED",  "dir_listing",       'http.title:"Index of /"'),
    ("MED",  "default_creds",     'http.html:"default password"'),
    ("MED",  "actuator",          'http.html:"/actuator" OR http.title:"Whitelabel Error"'),
    # --- Dev / staging surface ---
    ("MED",  "dev_staging_cert",  'ssl.cert.subject.cn:"dev." OR ssl.cert.subject.cn:"staging."'),
    ("MED",  "self_signed",       'ssl.cert.issuer.cn:"localhost" OR ssl.cert.self_signed:true'),
    ("LOW",  "expired_cert",      'ssl.cert.expired:true'),
    # --- ICS/OT (flag, do NOT touch — specialist scope) ---
    ("CRIT", "ics_modbus",        'port:502'),
    ("CRIT", "ics_s7",            'port:102'),
    ("CRIT", "ics_bacnet",        'port:47808'),
]

def api_get(path, params):
    params = dict(params); params["key"] = os.environ["SHODAN_API_KEY"]
    url = f"{API}{path}?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=25) as r:
        return json.load(r)

def scope_suffix(args):
    bits = []
    if args.org: bits.append(f'org:"{args.org}"')
    if args.asn: bits.append(f'asn:{args.asn}')
    if args.net: bits.append(f'net:{args.net}')
    if args.cn:  bits.append(f'ssl.cert.subject.cn:"{args.cn}"')
    return " ".join(bits)

def hunt(args):
    scope = scope_suffix(args)
    if not scope:
        print("[!] Refusing to run unscoped. Provide --org/--asn/--net/--cn.", file=sys.stderr)
        sys.exit(2)
    results = []
    for sev, label, frag in DORKS:
        q = f"{frag} {scope}"
        try:
            data = api_get("/shodan/host/search", {"query": q, "minify": "true"})
        except Exception as e:
            print(f"[!] {label}: {e}", file=sys.stderr); time.sleep(2); continue
        matches = data.get("matches", [])
        for m in matches:
            results.append({
                "severity": sev, "label": label,
                "ip": m.get("ip_str"), "port": m.get("port"),
                "org": m.get("org"), "hostnames": m.get("hostnames"),
                "product": m.get("product"), "transport": m.get("transport"),
                "dork": q,
            })
        print(f"[+] {sev:4} {label:18} {len(matches):3} hosts", file=sys.stderr)
        time.sleep(1.5)
    json.dump(results, open(args.out, "w"), indent=2)
    print(f"[=] {len(results)} leads -> {args.out}", file=sys.stderr)

def footprint(args):
    print(f"# Footprint for {args.domain} / {args.org}")
    print("# Use the org string and ASN below to scope the hunt mode.")
    try:
        data = api_get("/shodan/host/search", {"query": f'hostname:{args.domain}', "facets": "asn,org,port"})
        for facet, rows in data.get("facets", {}).items():
            print(f"\n[{facet}]")
            for r in rows:
                print(f"  {r['value']:30} {r['count']}")
    except Exception as e:
        print(f"[!] {e}", file=sys.stderr)

def triage(args):
    rows = json.load(open(args.inp))
    order = {"CRIT":0,"HIGH":1,"MED":2,"LOW":3}
    rows.sort(key=lambda r: order.get(r["severity"],9))
    print("=== SHODAN LEAD TRIAGE (confirm scope/ownership before touching) ===")
    for r in rows:
        hn = ",".join(r.get("hostnames") or []) or "-"
        print(f"[{r['severity']:4}] {r['label']:18} {r['ip']}:{r['port']:<6} {r.get('product') or '':16} {hn}")
    print(f"\n{len(rows)} leads. CRIT datastores: confirm reachable, DO NOT read data.")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["footprint","hunt","triage"], required=True)
    ap.add_argument("--domain", default=""); ap.add_argument("--org", default="")
    ap.add_argument("--asn", default=""); ap.add_argument("--net", default="")
    ap.add_argument("--cn", default="")
    ap.add_argument("--out", default="shodan_leads.json")
    ap.add_argument("--in", dest="inp", default="shodan_leads.json")
    args = ap.parse_args()
    {"footprint":footprint, "hunt":hunt, "triage":triage}[args.mode](args)

if __name__ == "__main__":
    main()
```

### Step 3 — Scope-filter and verify (in-scope leads only)

For each CRIT/HIGH lead, confirm the IP is the target's **now**, then do the
minimal reachability check. Keep verification read-only and benign.

```bash
# Re-confirm ownership: does an in-scope hostname still resolve to this IP?
getent hosts "$TARGET_DOMAIN"
# Compare the Shodan IP to current resolution / program asset list before connecting.

# Minimal reachability proof — EXAMPLES, in-scope hosts only, authorize first:
# Unauth datastore reachable? (prove it answers; DO NOT read data)
redis-cli -h "$IP" -p 6379 PING            # expect PONG = unauth reachable -> STOP
curl -s --max-time 8 "http://$IP:9200/"    # Elastic root banner only, not _search/_cat
#   ^ capture the version/cluster banner as proof; do NOT query indices/documents.

# Exposed panel reachable?
curl -s --max-time 8 -o /dev/null -w '%{http_code} %{ssl_verify_result}\n' "https://$IP/"
```

**Hard stop on datastores and ICS:** reachability is the finding. Reading rows,
listing indices, dumping keys, or sending any ICS/OT command is out of bounds —
report the exposure, not its contents.

### Step 4 — Hand off

| Shodan lead | Hand off to |
|---|---|
| New in-scope hostnames in `hostnames`/cert SANs | `hunt-subdomain` |
| Exposed datastore (reachable, unauth) | report as Critical; `hunt-pii-exposure` rules apply if data is visible |
| Cloud-hosted bucket/service banners | `hunt-cloud-misconfig` |
| `.git` / env strings in banners | `hunt-source-leak` |
| Admin panel | `hunt-auth-bypass` (in scope, authorized) |
| ICS/OT (Modbus/S7/BACnet) | flag to program owner; specialist OT scope only |

---

## Pitfalls

- **IP ≠ scope.** The top mistake. Shodan returns IPs; cloud/CDN IPs are shared
  and rotate. Confirm ownership (ASN + cert + current DNS + asset list) before
  touching anything, and re-confirm right before you connect.
- **Stale index.** Shodan banners can be days-to-weeks old. A service shown open
  may be closed now (report nothing) — or recently opened and not yet indexed
  (Shodan undercounts). Always re-verify liveness against the in-scope host.
- **Becoming the breach (again).** An open Mongo/Elastic is a Critical *by
  reachability*. Dumping it to "show impact" is the harm itself. Prove it answers
  unauthenticated, capture the banner, stop.
- **ICS/OT is radioactive.** Modbus/S7/BACnet hosts can be safety-critical. Never
  send commands or even aggressive probes. Flag and escalate; many programs
  exclude OT entirely.
- **Honeypots.** Shodan is full of deliberate honeypots (open DBs, fake RDP).
  `tags:honeypot` and the `shodan/honeyscore` endpoint help; a too-perfect open
  datastore on an odd ASN is suspect.
- **Unscoped dorks = noise + trespass risk.** Never run a bare `product:MongoDB`;
  always append `org:`/`asn:`/`net:`/`ssl.cert.subject.cn:`. The script refuses to
  run `hunt` without a scope filter for this reason.
- **Credit burn.** Facets and filtered search cost query credits; batch and cache.

---

## Verification

A Shodan lead becomes a confirmed finding when:

1. **The host is in scope** — IP maps to the target via ASN/cert/DNS AND appears
   in (or is covered by) the authorization. Record how you established this.
2. **The exposure is live now** — re-checked against the host, not just the index.
3. **The minimal proof holds** — service answers as Shodan claimed:
   - Datastore: unauthenticated `PING`/banner response, **no data read**.
   - Panel: login/dashboard renders on the in-scope host.
   - Cert: SAN/CN exposes an internal hostname, or cert is expired/self-signed
     on a production host.
4. **A negative control** distinguishes it from a false positive (e.g. the same
   port on a sibling host requires auth; or the open DB is confirmed not a
   honeypot via honeyscore).

Record per finding: the dork, UTC timestamp, IP:port, how ownership/scope was
confirmed, the product/version banner (as proof), the **reachability** evidence
(not data contents), honeypot check, and severity.

**Severity anchors:**
- Unauthenticated production datastore (Mongo/Elastic/Redis), in-scope, reachable: Critical
- Exposed orchestration API (k8s/Docker/Jenkins) allowing control: Critical
- Admin panel / RDP / VNC exposed on an in-scope host: High
- Internal hostnames leaked via cert SAN, dev/staging exposed: Medium
- Expired/self-signed cert, directory listing of non-sensitive files: Low–Info
- ICS/OT exposure: escalate to program owner regardless of nominal severity
