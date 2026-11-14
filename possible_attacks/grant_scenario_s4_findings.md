# Scenario S4 — Follow-up intents mint grants without new approval

**Plan reference:** `possible_attacks/grant_lifecycle_investigation_plan.md`
§7 (Phase 3, S4). Target: `hop-go/` @ `9a198a9` + the Phase-0 clock patch.

**Status:** adjudicated — INV-E and INV-G both falsified by a single
interleaving. Three tests pass in-tree; no crash. Finding type: dev bug
(discarded error; already issue-tracker-admitted as #201) + design residue
(approval-per-intent is unenforceable without a per-intent challenge).

---

## 1. Hypothesis under test

**H4 (approval coverage has holes).** Exactly one user-approval event covers
the *first* intent per principal instance; follow-up intents on the same
tube skip principal-side approval (error discarded, `principal.go:114-116`)
while the target instance loop keeps accepting `IntentCommunication` on
the still-open tube (`authgrants/target.go:54-73`), adding grants without
any new user approval.

**Invariants falsified:**

- **INV-E** — §7.3 "the authorization grant flow stops and the Principal
  requests **explicit approval** from the user." Operationalized: every
  `IntentCommunication` accepted by the target corresponds 1:1 to a
  *successful* principal-side approval event.
- **INV-G** — "no capability growth absent new approval." Operationalized:
  the set of actions the delegate holds credentials for never grows
  without a user approval that returned nil.

---

## 2. Experimental setup

- L1 role harness (`hop-go/authgrants/grants_harness_test.go`) — fake
  `net.Pipe`-wired principal, target, delegate per the existing
  `principal_test.go` idiom; event log recording `EvApprovalInvoked`,
  `EvApprovalReturned`, `EvGrantAdded`.
- New file: `hop-go/authgrants/grant_scenario_s4_test.go`.
- New companion audit: `hop-go/authgrants/grant_scenario_s4_v8_audit_test.go`.
- Scripted approver (`scriptedApprover`) — returns a per-invocation
  decision from a user-provided script and records both the invocation and
  the returned error into the event log.
- Delegate driven manually with `WriteIntentRequest` /
  `ReadConfOrDenial` so that per-intent delegate responses are observable
  (vs `StartDelegateInstance`, which only reports aggregate success).

---

## 3. Results

### 3.1 `TestS4_FollowUpIntentApprovalDiscarded` — core falsification

Two intents to the **same** `TargetURL`:
- intent-1: `cmd:echo one`; user approves (returns nil).
- intent-2: `shell`;         user **denies** (returns error).

**Observed event log (6 events):**

| # | Kind | Err | Phase |
|---|------|-----|-------|
| 0 | ApprovalInvoked  | — | intent-1 |
| 1 | ApprovalReturned | nil | intent-1 |
| 2 | GrantAdded       | — | intent-1 |
| 3 | ApprovalInvoked  | — | intent-2 |
| 4 | ApprovalReturned | `"user denies intent-2"` | intent-2 |
| 5 | **GrantAdded**   | — | **intent-2 ⚠** |

Event #5 is the smoking gun: the target stored a grant whose principal-side
approval just returned an error. The user denied; the target does not
know.

**Observed delegate wire view:** both intents received `IntentConfirmation`.
The denial was invisible — there is no "intent silently denied by
principal" message type in the AgMessage schema, and the error at
`principal.go:115` is discarded before any `WriteIntentDenied` could be
driven.

**Lifecycle state-machine delta (vs plan §3.1):**

```
PENDING_APPROVAL --checkIntent OK ---> STORED(agMap)         (intent-1)
PENDING_APPROVAL --checkIntent ERR -*> STORED(agMap)         (intent-2) ⚠
                                   ^
                                   `-- the discarded-error transition:
                                       code takes it anyway (principal.go:115 → 118)
```

The code takes the STORED edge for intent-2 unconditionally once the
target acknowledges — the principal has no "veto" transition on follow-up
intents.

### 3.2 `TestS4_FollowUpIntentCrossTarget` — scope guard

Documents the ONLY boundary that stops V8: a follow-up intent naming a
**different** `TargetURL` than intent-1 is rejected at
`principal.go:91-93` *before* reaching the else branch. intent-2 is denied
on the wire; no approval callback invoked; no grant added.

This scope boundary is important for the Phase-5 writeup: V8's radius is
"follow-up intents on the same (SNI, user, port)" — it is not universal.
For an attacker, the practical implication is that a compromised delegate
can only chain additional grants that share target coordinates with the
first; cross-target follow-ups require a separate principal-session or a
cross-target routing exploit (see Candidate 2).

### 3.3 `TestS4_V8_AuditFollowUpIntentCheckIntentReturnDiscarded` — AST invariant

Parses `principal.go`, locates `doIntentRequestChecks`, finds the
`if !p.targetConnected { ... } else { ... }` statement, and asserts the
else body contains the call `p.checkIntent(...)` as a **bare `ExprStmt`**
whose return value is thrown away. Any refactor that:

- wraps the call with `if err := ...; err != nil { ... return ... }`
- assigns the return into a named variable that is subsequently inspected
- moves the call outside the else branch entirely

will trip this test and force re-adjudication of S4. This converts the V8
*static fact* into a test-suite invariant so the finding's life-cycle is
tracked alongside the rest of the suite.

---

## 4. Phase-5 classification (three-question triage, plan §9)

| Q | Answer |
|---|--------|
| 1. What does the paper commit to? | §7.3: "the authorization grant flow **stops** and the Principal requests **explicit approval** from the user" and "**Each intent**, and its corresponding action, is authorized **only once**." These together mandate approval-per-intent. |
| 2. Does the paper/spec specify the behavior the code got wrong? | **Yes.** The paper says each intent gets its own approval. The code's else-branch at `principal.go:114-116` elides the gate. This is a dev bug and is already admitted upstream as issue #201. |
| 3. Would a faithful from-scratch implementation following the paper still be vulnerable? | **Partially.** Fixing #201 closes the approval-gate hole. But there is a *design-level* residue: the paper names no mechanism for how the Principal is to tell the user which intent is being re-approved mid-session — if the UI shows only "approve?" with intent text, a compromised delegate can request a visually-similar intent that the user habit-approves. That is a Candidate-2 question (chain-of-authority), not a Candidate-1 (capability composition). |

**Verdict split:**

1. **Dev bug** (upstream-issue-ready — complements #201):
   - **D-S4-α** `principal.go:114-116` must consume `checkIntent`'s error.
     Minimum patch:
     ```go
     } else {
         if err := p.checkIntent(i, p.targetCert); err != nil {
             return WriteIntentDenied(p.delegateConn, err.Error())
         }
     }
     ```
     Impact: closes the primary INV-E violation.
   - **D-S4-β** Target's `handleIntentCommunication` (target.go:54-73) does
     not need a fix in isolation — once D-S4-α holds, the principal stops
     forwarding denied follow-ups. But if we want defence in depth, the
     target's `checkIntent` callback at line 61 (which is server-side
     `(*hopSession).checkIntent`, NOT the principal-side one) could carry
     a "fresh-approval" token that the principal signs on each approval.
     This is scope for a larger spec change; mark deferred.

2. **Design residue** (feeds `design_oversights.md` Candidate 2 —
   chain-of-authority):
   - The paper leaves unspecified *what the user is actually shown* at
     approval time. A per-intent approval callback is necessary but not
     sufficient: a habituated user clicking "yes" to a plausible-looking
     intent is the real attack surface. S4 shows the code path is wider
     than the paper imagined; even a faithful fix leaves the UX-level
     question open.

3. **No crash.** All assertions pass; no `HOP_POC` skip-guard.

---

## 5. Interaction with S1 and S6

- **S1 + S4 chain:** a compromised delegate that already holds a
  (possibly-expired) first grant can — before any TTL — chain a follow-up
  intent of a different `GrantType` (e.g. shell → PFControl) into the
  same principal-session. S1's zombie footprint is WIDER if S4 is chained
  first: the zombie session's `authorizedActions` set can be grown before
  expiry sets in. Document this in the Candidate-1 writeup as the "V8
  inflates V3's blast radius" interaction.
- **S4 → S6 (bearer):** S4 is agnostic to who holds the delegate key; the
  principal has no identity check on intent-2 beyond "same TargetURL." If
  S6 confirms bearer semantics, then the attacker-with-key at a different
  host can also benefit from V8's elided gate.

---

## 6. Deliverables (this scenario)

| ID | Path | Purpose |
|----|------|---------|
| S4-T1 | `hop-go/authgrants/grant_scenario_s4_test.go` → `TestS4_FollowUpIntentApprovalDiscarded` | 6-event falsification of INV-E/G |
| S4-T2 | same file → `TestS4_FollowUpIntentCrossTarget` | scope guard: V8 is bounded by `principal.go:91` |
| S4-T3 | `hop-go/authgrants/grant_scenario_s4_v8_audit_test.go` → `TestS4_V8_AuditFollowUpIntentCheckIntentReturnDiscarded` | AST-level invariant that `p.checkIntent` return is still discarded in the else branch |
| S4-F | this file | adjudication + Phase-5 triage with file:line anchors |

All three tests pass under
`go test ./authgrants/ -run 'TestS4'`.
Full module test (`go test ./...`) passes with zero failures.

---

## 7. Open follow-ons / notes for the next scenarios

- **S6 (bearer)** next. S4 showed the principal has no per-intent identity
  verification beyond TargetURL; S6 will show the target has no delegate
  identity verification beyond possession of the ephemeral key. The two
  findings compound into "once the first approval happens, the delegate
  and whoever has the key can both grow the grant set at will, bounded
  only by TargetURL."
- **S7** (grant-type composition) can lean on S4 to establish the
  interleaving — follow-up PF intent into a session that opened for shell
  — without needing a multi-session bearer step.
- **If upstream fixes #201 before we write up**, S4-T1's event #5 flips
  from GrantAdded to no-event, and the delegate's intent-2 response flips
  to IntentDenied. S4-T3's AST audit trips, signalling the shape change
  so the paper writeup lands against the then-current semantics.
