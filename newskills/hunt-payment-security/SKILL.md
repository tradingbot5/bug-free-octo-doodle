---
name: hunt-payment-security
description: Audit payment, checkout, subscription, and pricing flows.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires curl, jq, python3
metadata:
  tags: [payment, fintech, checkout, e-commerce, business-logic]
  category: redteam
  related_skills:
    - hunt-business-logic
    - hunt-api-authz
    - hunt-race-condition
    - triage-validation
---

# HUNT-PAYMENT-SECURITY — Payment & Financial Logic Security Assessment

Operational methodology for auditing application-level payment, checkout, subscription, and financial business-logic vulnerabilities across e-commerce, fintech, SaaS platforms, and multi-tenant marketplaces. Built for authorized bug bounty, penetration testing, and financial logic audits.

---

## When to Use

- Auditing web or mobile checkout flows, subscription upgrades, cart calculations, and payment gateway integrations (Stripe, PayPal, Adyen, Razorpay, Braintree).
- Testing coupon redemption, promo stacking, discount calculations, and loyalty/credit balance systems.
- Evaluating digital wallets, store credits, gift card redemptions, payouts, and marketplace seller settlements.
- Assessing payment webhook callbacks, order state machine transitions, and idempotency controls.
- Investigating cross-user financial object authorization (BOLA on orders, invoices, refunds, or saved payment methods).

---

## Prerequisites

- Target in authorized scope with explicit permission for financial flow testing.
- **Test / Sandbox Credentials Preferred**: Whenever possible, use sandbox environments, test card numbers, or minimal real transactions ($0.01 / 1 INR/cent) authorized by program guidelines.
- **Strict Safety Constraint**: Never cause real financial loss, deplete production inventories, charge unauthorized third parties, or initiate unauthorized refunds.
- Standard tools installed: `curl`, `jq`, `python3`.
- Set writable output directory:
  ```bash
  export OUTPUT_DIR="${OUTPUT_DIR:-./output}"
  mkdir -p "$OUTPUT_DIR"
  ```

---

## How to Run

```bash
TARGET="shop.target.com"
OUTPUT_DIR="${OUTPUT_DIR:-./output}"
mkdir -p "$OUTPUT_DIR/$TARGET/payment"

# 1. Establish Clean Checkout Baseline (Single item, authentic pricing)
# Capture checkout creation request and payment intent:
curl -sk --max-time 10 -X POST "https://$TARGET/api/v1/checkout/create" \
  -H "Authorization: Bearer $USER_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"items": [{"product_id": "prod_100", "quantity": 1}]}' \
  -o "$OUTPUT_DIR/$TARGET/payment/baseline_order.json"

# 2. Price Parameter Tampering Probe (Testing client-side price override)
curl -sk --max-time 10 -X POST "https://$TARGET/api/v1/checkout/create" \
  -H "Authorization: Bearer $USER_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"items": [{"product_id": "prod_100", "quantity": 1, "unit_price": 0.01}]}' \
  -o "$OUTPUT_DIR/$TARGET/payment/probe_price_override.json"

# 3. Compare backend order amount with payment gateway intent amount
cat "$OUTPUT_DIR/$TARGET/payment/probe_price_override.json" | jq '{order_id, total_amount, currency, payment_intent_id}'
```

---

## Procedure

### Investigation State Machine

Execute payment logic audits through a structured, state-tracked lifecycle:

```text
[1. DISCOVERED] ──► Map checkout, cart, pricing, coupon, webhook, and subscription routes.
        │
        ▼
[2. FLOW-MAPPED] ─► Model complete lifecycle (Cart ──► Intent ──► Auth ──► Fulfill ──► Refund).
        │
        ▼
[3. BOUNDARIES] ──► Identify Trust Boundaries: Client vs. API vs. Gateway Provider.
        │
        ▼
[4. CANDIDATE] ───► Select test vector (Price, Quantity, Currency, Coupon, State, Webhook).
        │
        ▼
[5. SAFE PROBE] ──► Execute non-destructive differential test using controlled values.
        │
        ▼
[6. VALIDATE] ────► Verify server-side database state and payment gateway reconciliation.
        │
        ▼
[7. REPORT] ──────► Document demonstrable financial impact, reproduction steps, and root cause.
```

---

### Step 1: Reconnaissance & Attack-Surface Mapping

Ingest existing recon datasets to identify the complete financial surface:

1. **Ingest Recon Datasets**:
   - Filter discovered URLs and endpoints for financial keywords:
     ```bash
     grep -iE "(checkout|cart|price|pricing|order|invoice|bill|subscription|upgrade|plan|refund|cancel|wallet|credit|giftcard|reward|coupon|discount|payout|settle|webhook|stripe|paypal|adyen|razorpay|braintree)" urls.txt > payment_endpoints.txt
     ```
2. **Client-Side JavaScript & Source Map Analysis**:
   - Inspect frontend bundles for client-side price calculation logic, plan IDs, and unreleased discount codes:
     ```bash
     grep -rEn "(createPaymentIntent|clientSecret|priceId|stripe\.confirmCardPayment|plan_id|discount_code|unit_amount)" ./js/
     ```
3. **Mobile Application Static Extraction**:
   - Inspect decompiled APK/IPA manifests for hidden in-app purchase endpoints, subscription verification routes, and custom API headers.
4. **Third-Party Payment Provider Identification**:
   - Identify active payment gateways (Stripe, PayPal, Adyen, Braintree) and public keys embedded in frontend code (e.g. `pk_live_...`).

---

### Step 2: Payment-Flow & State Machine Modeling

Map the multi-tier transaction pipeline and identify where values originate:

```text
User Cart (Client) ──► Application API ──► Payment Provider Gateway ──► Webhook Callback ──► Order Fulfillment
```

1. **Transaction State Machine**:
   Document allowed state transitions:
   - `created` $\rightarrow$ `pending` $\rightarrow$ `authorized` $\rightarrow$ `paid` $\rightarrow$ `fulfilled`
   - Secondary paths: `failed`, `cancelled`, `refunded`, `partially_refunded`.
2. **Trust Boundary Audit Matrix**:
   For every key parameter, determine who owns the value:

   | Parameter | Displayed (UI) | Submitted by Client | Authoritative Source | Exploit Risk |
   |---|---|---|---|---|
   | **Product Unit Price** | $50.00 | Yes (in JSON body) | Product Database | **High** (if API trusts client body) |
   | **Quantity** | 1 | Yes | Client selection | **High** (if negative/decimals permitted) |
   | **Currency** | USD | Yes | Store configuration | **High** (currency symbol confusion) |
   | **Payment Intent Status** | "paid" | Sent in callback | Gateway API verification | **Critical** (state forgery) |

---

### Step 3: Price, Quantity & Currency Manipulation

#### 1. Price & Subtotal Tampering
Test whether the backend recalculates line items or blindly accepts client-supplied totals:
```http
POST /api/v1/orders/checkout HTTP/1.1
Host: shop.target.com
Authorization: Bearer <TOKEN>
Content-Type: application/json

{
  "cart_id": "cart_123",
  "items": [
    {
      "item_id": "item_999",
      "price": 0.01,
      "custom_price": 0.00
    }
  ],
  "subtotal": 0.01,
  "total": 0.01
}
```
*Verification*: Inspect the payment intent returned by the gateway. If the gateway requests a charge of $0.01 for a $100 product, client input is trusted.

#### 2. Quantity & Decimal / Negative Manipulation
- **Negative Item Injection**: Add Item A (Price: $100, Quantity: 1) and Item B (Price: $40, Quantity: -2) to lower total cart price.
- **Fractional / Decimal Overflow**: Test fractional quantities (e.g. `0.001` or `0.5`) on items requiring integer fulfillment.
- **Zero Quantity Bypass**: Set `quantity: 0` while keeping the line item in the cart to check if fulfillment delivers free items.

#### 3. Currency Code Switching
Exploit exchange-rate discrepancies between client presentation and payment capture:
- If a product costs `100 USD`, change the currency attribute to a lower-value currency:
  ```json
  {"order_id": "ord_101", "amount": 100, "currency": "JPY"}
  ```
  *(100 JPY is approximately $0.65 USD. If the backend fulfills a 100 USD item upon receiving confirmation of a 100 JPY charge, currency confusion exists.)*

---

### Step 4: Coupon, Promotion & Discount Abuse

#### 1. Race-Condition Coupon Stacking (Turbo Intruder / Parallel Probes)
Single-use coupons are often validated, deducted, and saved in separate database transactions. Rapid concurrent requests can apply the coupon multiple times:
```python
# Concurrency probe concept (sending 15 simultaneous requests):
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=15)
    for i in range(15):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')
```
*Observe whether a 20% discount coupon applies multiple times, reducing order subtotal to $0.*

#### 2. Minimum-Spend & Eligibility Bypass
- Add items totaling $500 to satisfy a "$100 off on $500+ orders" promo.
- Apply the coupon code.
- Send an API request modifying cart items to remove the $500 items, leaving a $5 item:
  ```http
  POST /api/v1/cart/update HTTP/1.1
  {"items": [{"id": "cheap_item", "quantity": 1}]}
  ```
- *Observe whether the $100 flat discount persists on the $5 order.*

---

### Step 5: Direct Payment State Machine Transitions

Test whether internal order status can be advanced directly by the client without gateway confirmation:

1. **Client-Triggered State Updates**:
   ```http
   PATCH /api/v1/orders/ord_5001 HTTP/1.1
   Host: shop.target.com
   Authorization: Bearer <TOKEN>
   Content-Type: application/json

   {
     "status": "paid",
     "payment_status": "succeeded",
     "fulfillment_status": "processing"
   }
   ```
2. **Skipping Gateway Confirmation**:
   - Create order $\rightarrow$ Receive `order_id` in `pending` state.
   - Drop the third-party payment page entirely.
   - Directly call the post-checkout completion handler:
     ```http
     GET /checkout/success?order_id=ord_5001&payment_status=success HTTP/1.1
     ```
   - *Check order dashboard: If the order moves to "Processing / Paid" without an actual charge, the confirmation handler trusts query parameters rather than querying the payment gateway API.*

---

### Step 6: Subscription, Tier & Trial Security

1. **Plan ID / Price ID Swapping**:
   - Start an upgrade flow to the Enterprise Plan ($500/month).
   - In the payment intent creation request, replace the Enterprise plan ID with the Basic plan ID ($10/month) while keeping the target entitlement:
     ```json
     {"requested_tier": "enterprise", "stripe_price_id": "price_basic_10usd"}
     ```
2. **Trial Extension & Re-use**:
   - Test whether canceling and immediately re-activating subscriptions resets the 14-day trial period without charging the registered card.
3. **Seat Count / Metered Unit Bypasses**:
   - If pricing is based on active seats (`$15/seat/month`), test inviting 50 users via bulk API without triggering billing update endpoints.

---

### Step 7: Webhook & Asynchronous Callback Verification

Payment gateways send asynchronous HTTP POST requests (webhooks) to notify the application of completed charges (e.g. `checkout.session.completed`, `payment_intent.succeeded`):

1. **HMAC Signature Bypass**:
   - Replay an authentic webhook event without the signature header (`Stripe-Signature`, `X-Razorpay-Signature`).
   - Tamper with the webhook JSON body (changing `amount_total` or `order_id`) while preserving the old signature.
2. **Unauthenticated Webhook Injection**:
   ```http
   POST /api/webhooks/stripe HTTP/1.1
   Host: shop.target.com
   Content-Type: application/json

   {
     "type": "payment_intent.succeeded",
     "data": {
       "object": {
         "id": "pi_fake_12345",
         "amount": 10000,
         "currency": "usd",
         "status": "succeeded",
         "metadata": {
           "order_id": "ord_victim_101"
         }
       }
     }
   }
   ```
   *If the backend marks the order as paid without validating the cryptographic HMAC signature with the gateway secret key, anyone can forge payment confirmations.*

---

### Step 8: Digital Wallets, Credits & Refund Abuse

1. **Wallet Balance Race Conditions**:
   - Submit concurrent purchase requests spending a $10 wallet balance on two separate $10 items simultaneously.
2. **Cross-User Refund BOLA**:
   - Submit a refund request using User B's token for an order owned by User A:
     ```http
     POST /api/v1/orders/ord_user_a/refund HTTP/1.1
     Host: shop.target.com
     Authorization: Bearer <USER_B_TOKEN>
     Content-Type: application/json

     {"refund_destination": "user_b_wallet"}
     ```
3. **Negative Balance / Over-Refund Vulnerabilities**:
   - Request a partial refund where `refund_amount` exceeds the original purchase total (e.g. refunding $150 on a $100 purchase).

---

## Pitfalls

Avoid reporting invalid financial findings by validating against these common traps:

| Trap | Real Cause | Verification Method |
|---|---|---|
| **Display-Only Price Manipulation** | Modifying `unit_price` in the browser changes the cart UI, but the final gateway modal shows the real price. | Follow the transaction through to the payment intent creation step. If the gateway modal or charge intent reflects the original price, the server validated the price properly. |
| **Sandbox / Test Gateway Behavior** | Test gateways (e.g. Stripe test mode) behave differently from production configurations. | Verify whether the endpoint is running in live mode versus sandbox, and document which environment was tested. |
| **Intentionally Free / Promo Products** | Items with $0.00 price are intentional marketing promotions. | Confirm whether non-promotional items are affected by the same logic before declaring an unintended free purchase. |
| **Asynchronous Reconciliation** | Order initially displays "Pending / Paid", but background workers cancel it 60 seconds later due to gateway verification failure. | Wait 3–5 minutes and check the permanent database state before claiming a payment bypass. |

---

## Verification

Before declaring a verified payment security vulnerability, ensure all verification gates pass:

- [ ] **Authoritative State Verification**: Clear proof that the backend database, order dashboard, or fulfillment system marked the order as complete/paid.
- [ ] **Deterministic Reproducibility**: The pricing discrepancy or state transition reproduces reliably under controlled testing conditions.
- [ ] **Gateway Verification Checked**: Demonstrated that the payment provider either received the tampered amount or was bypassed entirely.
- [ ] **Minimal Financial Footprint**: Proved using test credentials or the smallest possible authorized transaction ($0.01). No production stock depleted.
- [ ] **Dual-Account BOLA Evidence**: For refund or invoice tampering, verified that User B accessed or altered an order owned strictly by User A.

---

## Evidence Collection Standard

Package these technical artifacts for engineering remediation:

1. **Transaction Lifecycle Flow**: Diagram or list showing the exact sequence of endpoints called (Cart $\rightarrow$ Checkout $\rightarrow$ Payment).
2. **Comparative Request & Response Transcripts**:
   - **Baseline Transaction**: Clean request and response showing authentic pricing/state.
   - **Tampered Transaction**: Request showing the injected price/quantity/state and the corresponding response.
3. **Gateway Discrepancy Evidence**:
   - Screenshot or JSON response showing the payment intent ID and amount charged by the payment processor versus the items fulfilled.
4. **State Machine Proof**: Proof that the order moved to a completed/fulfilled status without a corresponding payment.
5. **Redaction**: Redact real credit card numbers, personal addresses, and sensitive customer PII.

---

## Architectural Remediation

Provide developers with actionable architectural remediations:

### 1. Authoritative Server-Side Pricing
Never accept price, currency, or discount values from client requests. Derive all prices exclusively from the database:
```javascript
// INSECURE: Trusting client-supplied price
const total = req.body.items.reduce((sum, item) => sum + (item.price * item.quantity), 0);

// SECURE: Looking up authoritative prices from database
let total = 0;
for (const item of req.body.items) {
    const dbProduct = await db.Products.findByPk(item.productId);
    if (!dbProduct || item.quantity <= 0 || !Number.isInteger(item.quantity)) {
        throw new Error("Invalid product or quantity");
    }
    total += dbProduct.priceInCents * item.quantity;
}
```

### 2. Cryptographic Webhook Validation
Validate HMAC signatures on all webhook endpoints using raw request bodies before processing any state change:
```javascript
// Express + Stripe Webhook Validation
const sig = req.headers['stripe-signature'];
let event;
try {
    event = stripe.webhooks.constructEvent(req.rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET);
} catch (err) {
    return res.status(400).send(`Webhook Signature Verification Failed: ${err.message}`);
}
```

### 3. Database Idempotency & Atomic Transactions
- Enforce unique idempotency keys on payment creation and charge endpoints.
- Wrap balance deductions, coupon redemptions, and order status updates in atomic database transactions (`SELECT ... FOR UPDATE` or serializable isolation) to eliminate race conditions.
