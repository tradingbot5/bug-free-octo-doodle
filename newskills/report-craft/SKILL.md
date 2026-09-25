---
name: report-craft
description: >
  Master pipeline + quality bar for producing a bug-bounty / disclosure report that
  survives professional triage: a deterministic Validate -> Claim-Ledger -> Draft ->
  Adversarial-self-review -> Score -> Deliver loop. Owns the parts the other reporting
  skills do not: the evidence-to-claim ledger (every sentence traceable to a captured
  artifact), the triager red-team pass (every close-reason preempted), the demonstrated-
  vs-inferable severity split, and a 100-point ship rubric with a hard threshold. Use
  AFTER triage-validation's 7Q gate passes and BEFORE sending anything. Composes with
  report-writing (body templates/tone), bugcrowd-reporting (VRT), evidence-hygiene
  (redaction), redteam-report-template (client deliverables). Never ship a report that
  scores < 85 or has one unbacked claim.
sources: operator_experience, community
---

# REPORT-CRAFT — The Ship-Quality Pipeline

The other reporting skills give you templates, tone rules, VRT maps and redaction
protocol. This skill is the **process that binds them** and the **bar the output
must clear**. It exists because good raw material still ships bad reports when
there is no forcing function for: traceability, adversarial review, honest
severity, and concision.

> One rule above all others: **every factual sentence in the report is backed by
> an artifact you captured, or it does not go in the report.** No exceptions,
> no "should", no "typically", no "an attacker could then".

---

## 0. WHERE THIS SKILL SITS

```
recon → hunt → triage-validation (7Q gate)  ──►  REPORT-CRAFT  ──►  send
                                                    │
             pulls in: report-writing (body skeleton + tone + CVSS)
                       bugcrowd-reporting (VRT + severity-request)   [if Bugcrowd]
                       evidence-hygiene (cookie/PII redaction)
                       redteam-report-template (6-section format)    [if client red-team]
```

Do **not** start here until `triage-validation` says the finding is real, in
scope, and not on the never-submit list. If it failed the 7Q gate, there is no
report to write.

---

## 1. THE PIPELINE (run in order, do not skip)

### Step 1 — Restate the finding in one sentence

`<attacker, with what access> can <verb> <what> on <asset>, which <impact>.`

If you cannot write this sentence cleanly, you do not understand the finding well
enough to report it. Fix that first.

### Step 2 — Build the Claim Ledger (this is the core of the skill)

Before drafting prose, make a table. Left column: every claim the report will
make. Right column: the exact artifact that proves it.

| # | Claim the report makes | Backing artifact (file / request+response / hash / screenshot) | Status |
|---|---|---|---|
| 1 | `/x` returns 200 without auth | `curl -i` transcript, saved to `evidence/01.txt` | ✅ captured |
| 2 | `/x` content includes credential `Y` | `jq` extraction `evidence/02.json`, sha256 of source | ✅ captured |
| 3 | control page `/z` returns 401 | `curl -i` transcript `evidence/03.txt` | ✅ captured |
| 4 | credential `Y` still works on SSH | — | ❌ NOT tested → must not appear as fact |

Rules:
- A claim with no artifact is **cut**, or explicitly demoted to a clearly-labelled
  "not demonstrated" note that carries **zero** severity weight.
- "Impact" claims count as claims. "An attacker can pivot to full server
  compromise" needs either a captured pivot or the word **if** and a severity that
  does not depend on it.
- Re-run each backing command once, fresh, right before writing — stale evidence
  is the #1 cause of triage retraction. Record the timestamp.
- Hash any file you quote from (`sha256sum`) so the triager can verify they're
  looking at the same bytes.

### Step 3 — Draft the body

Use the platform skeleton from `report-writing` (H1 / Bugcrowd / Intigriti /
Immunefi) or the 6-section format from `redteam-report-template` for client work.
For an email VDP (no platform), use the Universal Section Spec in §4.

Write from the Claim Ledger: each sentence in Steps-to-Reproduce / PoC / Impact
maps to a ledger row. If you're typing a sentence that has no row, stop — either
add evidence or delete the sentence.

### Step 4 — Adversarial self-review (the triager red-team pass)

Put on the triager's hat. Their job is to **close your report**. Walk §2's
close-reason table and, for each, answer: "could a tired triager close my report
this way?" If yes, fix the report until they can't. This is not optional polish —
it is the step that changes outcomes.

### Step 5 — Score it (§3). Ship threshold is 85/100 with no zero-score dimension.

If it scores lower, the rubric tells you which section is weak. Fix, re-score.

### Step 6 — Redact + deliver

Route every artifact through `evidence-hygiene` (cookies, other-user PII, tokens).
Confirm delivery channel: platform submission, or for a VDP, the exact address +
encryption (PGP) the policy demands. Attach the redacted evidence, not the raw.

---

## 2. THE TRIAGER RED-TEAM PASS — every close-reason, preempted

| Triager closes as… | They do it when… | Preempt in the report by… |
|---|---|---|
| **Duplicate** | Bug is on a common endpoint / known class | State you searched hacktivity / disclosed reports / changelog and found none; name what you searched. |
| **Informative** | Impact reads as "info only, no attacker gain" | Lead with the concrete attacker gain sentence (§ below). Quantify: whose data, how much, what it unlocks. |
| **N/A – not reproducible** | Steps are vague, need their env, or rely on your session | Copy-paste `curl` with no cookies; fresh-session repro; include exact response bytes + a hash. |
| **N/A – theoretical** | Report says "could", "may", "an attacker could then" | Delete every hedge. Prove the step or move it to a labelled non-claim with no severity weight. |
| **Out of scope** | Asset / class matches an exclusion | Quote the scope text; show the asset is in it. Quote the exclusion; show why this isn't it. |
| **Intended behaviour / by design** | Feature looks deliberate | Show the countervailing control (a 401, a "private" label, a docs line) that proves intent was the opposite. |
| **Needs more info** | Missing account details, missing response, missing which field matters | Pre-answer: test-account IDs, full response, the one field that is the bug, called out. |
| **Severity downgrade** | Claimed severity > demonstrated impact | Use the demonstrated-vs-inferable split (§ below). Claim only what the ledger backs. Offer the CVSS vector — a valid vector is hard to argue with. |
| **Won't fix / low priority** | Fix cost looks high vs stated impact | Give a cheap, specific fix. Tie impact to something the org cares about (regulated data, credentials, customer trust). |

If your report answers all nine before they're asked, it triages fast and clean.

### The attacker-gain sentence (kills "Informative")

> "Before this bug, an attacker <could not do X>. With it, an attacker <who has Y>
> can <do X>, affecting <concrete scope>."

No attacker-gain sentence you can write with a straight face → it's not a
finding, it's an observation. File it as Informational or not at all.

### Demonstrated vs inferable severity split (kills "Downgrade" and "Overclaim")

Write impact in two explicitly separated buckets:

- **Demonstrated** — what your captured artifacts prove happened. Severity is
  scored **only** on this.
- **Inferable / not tested** — realistic next steps you did **not** execute
  (out of scope, would exceed minimum-necessary evidence, needs their env).
  Presented as a short "risk note", carries **no** severity weight, uses **if**.

Example: you read root SSH credentials out of a public file but did not log in.
Demonstrated = credential + infra disclosure (score this). Inferable = full host
compromise if the password is still valid (risk note, not scored). This is the
honest split that senior triagers respect and that stops a retraction later.

---

## 3. THE 100-POINT SHIP RUBRIC

Score each dimension. **Ship at ≥ 85 total AND no dimension at 0.**

| Dim | Max | 0 = | full marks = |
|---|---|---|---|
| **Traceability** | 20 | any sentence with no backing artifact | every claim ↔ a captured, timestamped artifact; quoted files hashed |
| **Reproducibility** | 20 | steps need your session or their internal env | fresh-session copy-paste `curl`; triager can run it in 60s |
| **Impact clarity** | 15 | generic CIA / "sensitive data exposed" | attacker-gain sentence + quantified scope + what it unlocks |
| **Severity honesty** | 15 | claimed > demonstrated, or hedge words carry weight | demonstrated/inferable split; CVSS vector; matches ledger |
| **Scope proof** | 10 | scope not mentioned | in-scope quote + exclusion-doesn't-apply quote |
| **Concision** | 10 | > 700 words, or 3 paragraphs before the first request | impact in sentence 1; request block in first screenful; < 600 words |
| **Remediation** | 5 | "follow best practice" / absent | specific, cheap, correct fix — config line or code diff |
| **Hygiene** | 5 | a live cookie / token / other-user PII visible | all redacted per evidence-hygiene; redaction noted in body |

Log the score in your notes with the finding. A 92/100 report and a 71/100 report
look similar at a glance — the rubric is what tells you the 71 will bounce.

---

## 4. UNIVERSAL SECTION SPEC (format-agnostic)

Every report, whatever the channel, contains these — reorder/rename per platform:

1. **Title** — `<class> in <exact asset/endpoint> lets <actor> <impact>`. No "possible", no "vulnerability found".
2. **Summary** — 2–4 sentences. Bug, location, attacker gain, required access. Impact in sentence 1.
3. **Affected asset / scope line** — exact host/URL + one line proving it's in scope.
4. **Preconditions** — account/role/config the attacker needs. "None" if none.
5. **Steps to reproduce** — numbered, deterministic, copy-paste. Fresh session. Real requests + real responses (redacted).
6. **Proof of concept** — the minimum evidence that proves it. Table form when there are several artifacts. Hashes for quoted files.
7. **Impact** — attacker-gain sentence, then **Demonstrated** bucket, then **Inferable / risk note** bucket.
8. **Severity** — CVSS 3.1 vector + score + one line of justification tied to the demonstrated bucket only.
9. **Remediation** — specific and ordered (what to do first). Rotate-secrets items go first if credentials leaked.
10. **Supporting material** — list of attached artifacts, each named, each redaction-checked.

Channel mapping:
- **HackerOne** — Summary / Steps / Impact / Severity / Suggested fix; narrative tone.
- **Bugcrowd** — severity-request paragraph FIRST, then VRT line, then the spec; see `bugcrowd-reporting`.
- **Intigriti** — Summary / PoC / Impact / Recommendation; video preferred.
- **Email VDP** — full spec, plain markdown, plus the policy's required delivery (address, PGP). No platform to set severity, so your CVSS vector carries it.
- **Client red-team** — swap to the 6-section format in `redteam-report-template`.

---

## 5. TONE & THE CUT LIST

Keep (from `report-writing`): impact-first, first person, present tense for the
flaw, past tense for observations, numbered steps, no jargon lectures.

**Cut on sight:**
- "could potentially", "may allow", "an attacker could then", "it appears that",
  "this might lead to" — prove it or delete it.
- Any sentence explaining what the bug class *is* (they know what IDOR is).
- Background paragraphs before the first HTTP request.
- Speculative chains you didn't execute (move to the one-line risk note).
- Restating the same impact three ways.
- Adjectives doing an evidence's job ("critical", "severe", "trivial") — let the
  vector and the repro speak.
- Screenshots that duplicate a text response you already pasted.

Target length: **under 600 words** of prose (evidence blocks don't count). If it's
longer, you're explaining, not proving.

---

## 6. FAILURE ARCHETYPES (seen in real reports) → FIX

| Archetype | Tell | Fix |
|---|---|---|
| The theoretical escalation | "…which could be chained to RCE" with no PoC | Demonstrated/inferable split; score only what you showed. |
| The one-account IDOR | "changed id, got 200" — one account, no victim data shown | Two accounts; show account B's actual data in account A's session (redacted). |
| The status-code finding | 200 vs baseline 403 but body is byte-identical | Diff the bodies; if identical, it's not a finding. |
| The soft-404 exposure | `/.env` returns 200 — so does `/zzz-random` | Junk-path control in the report; show the real path's body differs. |
| The scope-blind submit | never mentions scope | Add the in-scope quote + exclusion rebuttal. |
| The wall of text | 5 paragraphs before a request | Move the request up; cut background to one sentence. |
| The stale repro | evidence captured days ago, not re-run | Re-run fresh, timestamp, re-hash before sending. |
| The leaky PoC | live session cookie in a screenshot | `evidence-hygiene` pass; re-capture with `credentials:'include'` pattern. |
| The severity reach | "Critical" on an undemonstrated takeover | Score the demonstrated bucket; put takeover in the risk note with "if". |

---

## 7. FINAL PRE-SEND CHECKLIST

```
[ ] triage-validation 7Q gate passed (recorded)
[ ] Claim Ledger complete — every prose sentence maps to a row; no ❌ rows in the body as fact
[ ] Every backing command re-run fresh; timestamps + hashes recorded
[ ] Title = class + exact asset + impact; no hedge words
[ ] Impact stated in sentence 1 of the Summary
[ ] Attacker-gain sentence present
[ ] Demonstrated vs inferable split is explicit; severity scored on demonstrated only
[ ] CVSS 3.1 vector string included and valid
[ ] Steps reproduce from a FRESH session with no cookies (or a clearly stated free account)
[ ] Scope: in-scope quote + "exclusion X doesn't apply because…" both present
[ ] Remediation is specific; secret-rotation first if credentials leaked
[ ] Ran the §2 triager red-team pass — all 9 close-reasons preempted
[ ] Scored ≥ 85/100, no dimension at 0
[ ] < 600 words of prose; first HTTP request within the first screenful
[ ] evidence-hygiene pass done; redaction noted in the body; unredacted kept locally
[ ] Delivery channel confirmed (platform / VDP address + PGP)
```

---

## 8. WORKED MINI-EXAMPLE (structure only)

Finding: a static search index on a docs site serves the text of Basic-Auth-
protected pages, including plaintext root credentials.

- **Restate:** "An unauthenticated attacker can read every access-controlled
  `/private/` runbook on `wiki.example.com` — including a cleartext root password —
  by fetching one static JSON file the auth layer doesn't cover."
- **Ledger:** (1) `search_index.json` = 200 no-auth → `curl -i` transcript.
  (2) index contains the `/private/` page text → `jq` extract + sha256.
  (3) same pages = 401 direct → `curl -i` transcript. (4) creds valid on SSH →
  **not tested** → risk note only.
- **Impact:** Demonstrated = unauth disclosure of internal runbooks + a root
  credential + infra details (score this). Inferable = host takeover *if* the
  password is still valid (risk note, unscored).
- **Severity:** score the demonstrated bucket → High, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 7.5.
- **Remediation:** rotate the credential first; then exclude `/private/` from the
  index build; then put the auth in front of `/search/` too.
- **Triager pass:** "by design?" → no, the pages are 401, the path is named
  `private/`. "theoretical?" → no, one unauth GET, response bytes attached.
  "scope?" → host is in the program's domain scope, quoted.

---

## Related Skills & Chains

- **`triage-validation`** — the gate BEFORE this skill. If the 7Q gate fails, there is no report. This skill assumes it passed.
- **`report-writing`** — provides the per-platform body skeleton, tone rules, CVSS tables, downgrade counters. This skill orchestrates it and adds the ledger + rubric + triager pass.
- **`bugcrowd-reporting`** — layer on top for Bugcrowd: VRT selection, severity-request paragraph, OOS-clause rebuttals.
- **`evidence-hygiene`** — Step 6 of the pipeline. Every artifact routes through it before attach.
- **`redteam-report-template`** — swap the Universal Section Spec for the 6-section client format when the engagement is an external red team, not a bounty/VDP.
- **`bb-methodology`** — Phase 5 (Validate & Report) calls `/validate` then this skill.
