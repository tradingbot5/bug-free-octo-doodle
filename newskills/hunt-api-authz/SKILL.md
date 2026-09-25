---
name: hunt-api-authz
description: Audit API broken object and function level authorization.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires curl, jq, python3
metadata:
  tags: [api, authz, idor, bola, bfla, privilege-escalation]
  category: auth
  related_skills:
    - hunt-idor
    - hunt-spa-api
    - hunt-shadow-api
    - triage-validation
---

# HUNT-API-AUTHZ — API Authorization & Access Control Assessment

Operational methodology for auditing authorization vulnerabilities across modern REST, GraphQL, and JSON APIs. Covers Broken Object Level Authorization (BOLA/IDOR), Broken Function Level Authorization (BFLA), Horizontal and Vertical Privilege Escalation, Tenant Isolation Failures, Workflow Stage Skipping, and Multi-Interface Discrepancies.

---

## When to Use

- Evaluating REST, GraphQL, or JSON APIs for cross-user or cross-tenant data leaks.
- Auditing multi-tenant SaaS platforms where organizations, workspaces, or accounts must remain isolated.
- Testing applications with distinct user roles (Anonymous, Standard User, Manager, Organization Admin).
- Assessing batch, bulk, export, or reporting endpoints for missing object-level validation.
- Verifying whether legacy versions (`/v1`), mobile-specific APIs, or internal gateways bypass edge authorization policies.

---

## Prerequisites

- Target within authorized scope with explicit testing permission.
- **Mandatory Role Matrix Accounts**: At least three distinct test identities provisioned:
  1. `User A` (Tenant 1 / Role: Standard User)
  2. `User B` (Tenant 2 / Role: Standard User — horizontal isolation control)
  3. `Admin / Manager` (Tenant 1 / Role: Elevated User — vertical isolation control)
- Tools: `curl`, `jq`, `python3`.
- Set writable output location:
  ```bash
  export OUTPUT_DIR="${OUTPUT_DIR:-./output}"
  mkdir -p "$OUTPUT_DIR"
  ```

---

## How to Run

```bash
TARGET="api.target.com"
OUTPUT_DIR="${OUTPUT_DIR:-./output}"
mkdir -p "$OUTPUT_DIR/$TARGET/authz"

# 1. Baseline Request (User A accesses own resource)
TOKEN_A="Bearer eyJhbGciOi..."
curl -sk --max-time 10 "https://$TARGET/api/v2/organizations/org_101/invoices/inv_5001" \
  -H "Authorization: $TOKEN_A" \
  -o "$OUTPUT_DIR/$TARGET/authz/userA_own_resource.json"

# 2. Horizontal BOLA Test (User B attempts to read User A's resource)
TOKEN_B="Bearer eyJhbGciOi..."
curl -sk --max-time 10 -w "HTTP: %{http_code} | Size: %{size_download} bytes\n" \
  "https://$TARGET/api/v2/organizations/org_101/invoices/inv_5001" \
  -H "Authorization: $TOKEN_B" \
  -o "$OUTPUT_DIR/$TARGET/authz/userB_probe.json"

# 3. Compare responses (Check if User B received User A's confidential invoice)
diff -u "$OUTPUT_DIR/$TARGET/authz/userA_own_resource.json" "$OUTPUT_DIR/$TARGET/authz/userB_probe.json"
```

---

## Procedure

### Investigation State Machine

The agent must execute authorization testing through a deterministic, state-tracked lifecycle:

```text
[1. DISCOVERED] ──► Map endpoints, verbs, parameters, and API versions.
        │
        ▼
[2. MAPPED] ──────► Extract object IDs, parent/child paths, and sensitive actions.
        │
        ▼
[3. AUTH-MODEL] ──► Define Users, Roles, Tenants, and Expected Access Matrix.
        │
        ▼
[4. CANDIDATE] ───► Prioritize endpoints by risk score (Financial, PII, Admin).
        │
        ▼
[5. EXECUTION] ───► Perform controlled differential testing (Horizontal / Vertical).
        │
        ▼
[6. VALIDATE] ────► Filter public data, self-access, caching, and false positives.
        │
        ▼
[7. REPORT] ──────► Document root cause, affected objects, and safe PoC.
```

---

### Step 1: Reconnaissance & Attack-Surface Discovery

Ingest existing recon datasets and uncover hidden or unmonitored API routes:

1. **Ingest Recon Datasets**:
   - Parse subdomains (`api.*`, `gateway.*`, `internal-api.*`, `graphql.*`).
   - Extract URLs from crawling, Wayback/archive logs, and client JavaScript bundles.
2. **Examine API Documentation & Schemas**:
   ```bash
   # Check common OpenAPI / Swagger discovery endpoints
   for path in /openapi.json /swagger.json /api-docs /v2/api-docs /v3/api-docs /swagger/v1/swagger.json; do
     curl -sk --max-time 5 "https://$TARGET$path" | grep -iE "(swagger|openapi|paths)" && echo "[+] Schema found at $path"
   done

   # Check GraphQL schema introspection
   curl -sk -X POST "https://$TARGET/graphql" \
     -H "Content-Type: application/json" \
     -d '{"query":"query { __schema { queryType { name } mutationType { name } } }"}' \
     -o "$OUTPUT_DIR/$TARGET/authz/graphql_schema.json"
   ```
3. **Analyze Client-Side JS & Source Maps**:
   - Extract routes using regex:
     ```bash
     grep -rEn "(axios|fetch|\$http)\.(get|post|put|delete|patch)\(\s*['\"][^'\"]+" ./js/
     ```
   - Look for internal versions (`/api/v1` vs `/api/v2`), administrative prefixes (`/admin/`, `/internal/`, `/manage/`), and bulk operations (`/batch`, `/bulk`, `/export`).
4. **Mobile & Alternate Client Mapping**:
   - Inspect decompiled APK/IPA manifests and strings for non-public API gateways or deprecated microservices lacking API gateway filters.

---

### Step 2: Establish the Authorization Model & Matrix

Never test authorization blindly. Model the application's entities before sending mutations:

1. **Entity Mapping**:
   - Identify: `Tenant` (Org, Workspace) $\rightarrow$ `User` (Account, Profile) $\rightarrow$ `Resource` (Invoice, Project, Document).
2. **Construct the Expected Access Matrix**:
   Document what *should* happen prior to probing:

   | Role / Identity | Resource A (Tenant 1) | Resource B (Tenant 2) | Admin Action (Tenant 1) |
   |---|---|---|---|
   | **User A (Tenant 1)** | **ALLOW (200)** | **DENY (403/404)** | **DENY (403)** |
   | **User B (Tenant 2)** | **DENY (403/404)** | **ALLOW (200)** | **DENY (403)** |
   | **Admin (Tenant 1)** | **ALLOW (200)** | **DENY (403/404)** | **ALLOW (200)** |

3. **Authentication vs. Authorization Separation**:
   - **Authentication**: "Who are you?" (Valid session, JWT signature, API key).
   - **Authorization**: "Are you allowed to touch *this specific object* or invoke *this specific function*?"
   - *Test Rule*: An endpoint returning 401 Unauthorized indicates an authentication failure; test with valid tokens from different privileges to evaluate authorization.

---

### Step 3: BOLA / IDOR Testing (Object-Level Authorization)

Test whether an authenticated identity can access objects owned by another identity:

#### 1. Target Identifier Types
- Direct integers: `1001`, `1002`
- UUIDs / GUIDs: `d3b07384-d113-4672-880e-4361e6878b27`
- Slugs & Hashes: `/users/john-doe`, `/contracts/c_9f8a2`
- Natural Keys: Emails, tax IDs, account numbers.

#### 2. Systematic Swap Methodology
```bash
# A. Read Operation (Horizontal Read)
curl -sk -X GET "https://$TARGET/api/v1/projects/$PROJECT_A_ID" \
  -H "Authorization: $TOKEN_B"

# B. State Modification (Horizontal Update / Overwrite)
curl -sk -X PUT "https://$TARGET/api/v1/projects/$PROJECT_A_ID" \
  -H "Authorization: $TOKEN_B" \
  -H "Content-Type: application/json" \
  -d '{"name": "Tampered Name"}'

# C. Deletion (Horizontal Destroy)
curl -sk -X DELETE "https://$TARGET/api/v1/projects/$PROJECT_A_ID" \
  -H "Authorization: $TOKEN_B"
```

#### 3. Nested-Resource Relationship Mismatches
Applications frequently validate the parent resource but fail to check if the child resource belongs to that parent:
```http
GET /api/v1/organizations/{USER_B_ORG}/invoices/{USER_A_INVOICE} HTTP/1.1
Host: api.target.com
Authorization: Bearer <TOKEN_B>
```
*If the backend verifies that User B belongs to `USER_B_ORG`, but fetches `USER_A_INVOICE` purely by invoice ID without joining the organization boundary, authorization fails.*

---

### Step 4: BFLA Testing (Function-Level Authorization)

Test whether standard users can access administrative, management, or maintenance endpoints:

1. **Privileged Function Extraction**:
   - Identify actions available only to Admin users (e.g., `/api/admin/users/invite`, `/api/v1/system/settings`, `/api/v1/billing/refund`).
2. **Execute Using Standard User Identity**:
   ```bash
   # Test privileged endpoint using low-privilege token
   curl -sk -X POST "https://$TARGET/api/v1/admin/users" \
     -H "Authorization: $TOKEN_STANDARD_USER" \
     -H "Content-Type: application/json" \
     -d '{"email":"attacker-added@test.com","role":"admin"}'
   ```
3. **HTTP Verb Tampering on Functions**:
   If `GET /api/admin/settings` returns 403 Forbidden, test:
   ```bash
   curl -sk -X POST "https://$TARGET/api/admin/settings" -H "Authorization: $TOKEN_USER"
   curl -sk -X PUT "https://$TARGET/api/admin/settings" -H "Authorization: $TOKEN_USER"
   curl -sk -X GET "https://$TARGET/api/admin/settings" -H "Authorization: $TOKEN_USER" -H "X-HTTP-Method-Override: POST"
   ```

---

### Step 5: Multi-Tenant SaaS Isolation Testing

Verify that strict organization and tenant boundaries cannot be crossed:

1. **Tenant ID Injection Vectors**:
   - URL Path: `/api/v1/tenants/{tenant_id}/...`
   - JSON Body: `{"tenant_id": "tenant_1", "data": "..."}`
   - Custom Headers: `X-Tenant-ID: tenant_1`, `X-Organization-ID: org_1`
   - Cookie attributes: `Cookie: current_org=org_1`
2. **The Cross-Tenant Probe**:
   Using `User B`'s valid session, inject `Tenant A`'s identifier across all known injection vectors:
   ```bash
   curl -sk -X GET "https://$TARGET/api/v1/analytics/dashboard" \
     -H "Authorization: $TOKEN_B" \
     -H "X-Tenant-ID: $TENANT_A_ID"
   ```
   *Verify if metrics, customer lists, or financial data belonging to Tenant A are returned.*

---

### Step 6: Batch, Bulk & Export Operations

Backends often implement robust object authorization for single-resource endpoints (`/item/{id}`) but forget to iterate checks over arrays in bulk endpoints:

1. **Mixed Batch Authorization Probe**:
   Combine an authorized object ID with an unauthorized object ID in a single payload:
   ```http
   POST /api/v1/documents/bulk-download HTTP/1.1
   Host: api.target.com
   Authorization: Bearer <TOKEN_B>
   Content-Type: application/json

   {
     "document_ids": [
       "DOC_B_AUTHORIZED",
       "DOC_A_UNAUTHORIZED"
     ]
   }
   ```
2. **Behavioral Evaluation**:
   - Secure: Returns 403 for the entire batch, or returns an array where `DOC_A` has status `"error": "Access Denied"`.
   - Vulnerable: Processes all requested IDs and returns `DOC_A` contents in the response.

---

### Step 7: Workflow Stage Skipping

Verify whether state transitions enforce role prerequisites at every step:

```text
Step 1: Draft (User) ──► Step 2: Submit (User) ──► Step 3: Approve (Manager) ──► Step 4: Payout (Finance)
```

- **Test**: Can `User A` skip directly to Step 3 or Step 4 via the API?
  ```http
  POST /api/v1/expense-reports/exp_1001/approve HTTP/1.1
  Host: api.target.com
  Authorization: Bearer <TOKEN_STANDARD_USER>
  ```
- *Observe whether the state changes without verification of the approver's role.*

---

### Step 8: Alternative Clients & Version Discrepancies

Compare authorization enforcement across different exposure routes:

1. **Version Downgrading (`/v2` vs `/v1`)**:
   ```bash
   # V2 endpoint correctly returns 403 Forbidden:
   curl -sk -X GET "https://$TARGET/api/v2/users/102" -H "Authorization: $TOKEN_B"
   
   # Check if deprecated V1 endpoint lacks object-level check:
   curl -sk -X GET "https://$TARGET/api/v1/users/102" -H "Authorization: $TOKEN_B"
   ```
2. **GraphQL Field-Level Bypass**:
   If the REST endpoint `/api/users/102` denies access, check GraphQL resolver authorization:
   ```graphql
   query {
     user(id: "102") {
       email
       billingAddress
     }
   }
   ```

---

## Pitfalls & False-Positive Elimination

Avoid reporting invalid authorization findings by validating against these common traps:

| Trap | Real Cause | Verification Method |
|---|---|---|
| **Publicly Visible Data** | The object is designed to be public (e.g. public seller profile, published blog post). | Log out completely. If `curl` without *any* authorization header returns the identical data, the resource is intentionally public, not an authorization vulnerability. |
| **Self-Access Mistake** | User A and User B tokens belong to the same user or organization. | Confirm using `id` endpoints (`GET /api/me`) that both tokens represent strictly distinct entities and tenants. |
| **Shared / Team Collaboration** | The resource was explicitly shared with User B through project member features. | Create a third account (`User C`) outside the organization and verify that access remains denied. |
| **Empty 200 OK Response** | API returns `200 OK` with `{ "data": [] }` or empty body. | An empty result set means the database filtered out the records properly. Not a BOLA. |
| **Cached Gateway Response** | The edge CDN returns a cached response from an earlier authorized test. | Add unique cache-busting query strings (`?cb=12345`) or test from a secondary egress IP. |

---

## Verification

Before declaring a verified authorization vulnerability, ensure all verification gates pass:

- [ ] **Dual-Account Reproduction**: Finding reproduces deterministically using two distinct, known test accounts (`User A` and `User B`).
- [ ] **Cross-Boundary Demonstration**: Clear proof that User B accessed or altered an object owned strictly by User A or Tenant A.
- [ ] **State-Change Confirmation**: For write/delete vulnerabilities, verify in User A's session that the resource was actually modified or deleted.
- [ ] **Unauthenticated Control Run**: Execute the exact probe without an `Authorization` header to prove whether the endpoint requires authentication versus being completely public.
- [ ] **No Unnecessary Data Harvesting**: Probe only the minimum number of records necessary to prove the flaw. Do not dump customer databases.

---

## Evidence Collection Standard

Capture and package these exact technical artifacts for reporting:

1. **Affected Surface**: Full URL, HTTP method, and affected parameter/path variable.
2. **Role & Identity Context**:
   - Attacker account details (User B, Tenant 2, Role: Standard).
   - Victim account details (User A, Tenant 1, Role: Standard).
3. **The Comparative Proof**:
   - **Request 1 (Authorized Baseline)**: User A accessing own resource + Response transcript.
   - **Request 2 (Unauthorized Exploit)**: User B requesting User A's resource + Response transcript demonstrating returned PII/confidential data.
   - **Request 3 (Unauthenticated Baseline)**: Anonymous request showing 401/403 (proving the endpoint is intended to be protected).
4. **Impact Summary**: Concise summary stating whether the vulnerability permits Unauthorized Read, Write, Delete, or Privilege Escalation.

---

## Architectural Remediation

Provide developers with direct, actionable engineering remediations:

### 1. Server-Side Object-Level Validation
Never trust client-supplied IDs without checking session ownership in the database query:
```javascript
// INSECURE: Directly fetching by user-supplied ID
const invoice = await db.Invoices.findOne({ where: { id: req.params.invoiceId } });

// SECURE: Enforcing tenant and user boundary at the database layer
const invoice = await db.Invoices.findOne({
    where: {
        id: req.params.invoiceId,
        organizationId: req.user.currentOrganizationId // Bound to authenticated session!
    }
});
if (!invoice) {
    return res.status(404).json({ error: "Invoice not found or access denied" });
}
```

### 2. Centralized Policy Enforcement (RBAC / ABAC)
Avoid ad-hoc `if (user.role === 'admin')` checks scattered across controllers. Implement centralized policy middleware (e.g. Casbin, OPA, or framework authorization guards) that evaluate permissions prior to controller execution.

### 3. Reject Client-Supplied Role and Tenant Identifiers
Derive user roles, permissions, and tenant IDs exclusively from verified server-side session stores or cryptographically signed JWT claims, never from client-controlled request bodies or custom headers.
