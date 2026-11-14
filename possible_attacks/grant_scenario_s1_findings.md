# Scenario S1 — Expire-before-connect (zombie session)

**Plan reference:** `possible_attacks/grant_lifecycle_investigation_plan.md`
§7 (Phase 3, S1). Target: `hop-go/` @ `9a198a9` + the Phase-0 clock patch
documented in `memory/project_grant_harness_phase0.md`.

**Status:** adjudicated — INV-B falsified in strong form. Three tests pass
in-tree; no crash. Finding type: dev bug (missing expiry filter) + design
residue (Candidate 1 — capability composition).

---

## 1. Hypothesis under test

**H1 (expiry is advisory).** An expired, unconsumed grant still (a) passes
transport auth, (b) mints a delegate session, (c) is rejected by `checkCmd`
for its named action, but (d) leaves a *zombie headless session* whose
non-Exec tubes (PF, AuthGrant, WinSize) are not grant-gated — so the
delegate reaches a session state with ungated PF capability on the target.

**Invariant falsified:** INV-B, §7.3 "immediately invalidated after use or
timeout." Operationalized as: after `ExpTime`, no capability derived from
the grant is exercisable.

---

## 2. Experimental setup

- L2 session harness (`hop-go/hopserver/grants_harness_test.go`) — fake
  clock via `thunks.TimeNow`, `addTestGrant` plants directly into
  `agMap`+`keyStore` (mirrors `AddGrantFromIntentCommunication`'s effect).
- Three new tests in
  `hop-go/hopserver/grant_scenario_s1_test.go` and
  `hop-go/hopserver/grant_scenario_s1_v11_audit_test.go`.
- Clock anchor: `2026-01-01T12:00:00Z`; grant TTL = 1s; advance 2s.
- Harness patch dependency (V1→V2 unification): `hopserver/target.go` now
  uses `thunks.TimeNow()` in `checkIntent` as well as `checkCmd` — the
  single-line patch from Phase 0.

---

## 3. Results

### 3.1 `TestS1_ExpireBeforeConnect` — core zombie walk

Timeline and per-step adjudication:

| Step | Observable | Result | Static fact |
|------|-----------|--------|-------------|
| T0 | `addTestGrant` → `agMap.AddAuthGrant` + `keyStore.AddKey` | OK | V5 (`hopserver.go:329,332`) |
| T0 | `keyStore.VerifyLeaf(delegateCert)` | **success** — key trusted | V5 |
| T0+2s | clock advanced past `ExpTime` | — | — |
| T0+2s | **(a)** `keyStore.VerifyLeaf(delegateCert)` | **STILL success** — key is **still** in the transport trust pool after expiry | V5 observable as a bug: **no expiry-driven RemoveKey anywhere** |
| T0+2s | **(b)** `AuthorizeKeyAuthGrant(user, pub)` | **succeeds, returns 1 grant** whose `ExpTime < thunks.TimeNow()` | V3 confirmed: `RemoveAuthgrants` has **no expiry filter** (`authgrants/authgrants.go:52-64`); drain-then-return (`hopserver/target.go:28-33`) is expiry-agnostic |
| T0+2s | post-drain `keyStore.VerifyLeaf(delegateCert)` | fails ("not found") | removal is **tied to consumption, not expiry** (`hopserver/target.go:31`) |
| T0+2s | **(c)** `sess.checkCmd("date", false)` | **denied** — "no auth grant for cmd: date" | V2 (`hopserver/target.go:81`): checkCmd is the **only** per-action expiry gate |
| T0+2s | **(d)** `len(sess.authorizedActions)` after denial | **= 1** — the expired `Authgrant` lingers | V2 only deletes on success (`target.go:85,90`); session is alive and still carries the grant |

**Verdict:** INV-B falsified. Expiry invalidates **only** `checkCmd`'s
per-action string match. The grant's other derived capabilities (transport
key, drain, session mint, lingering `authorizedActions`) survive the TTL
boundary.

### 3.2 `TestS1_StaleGrantLeakAgMap` — V4 confirmation

Plant 5 cmd grants with distinct delegate keys and TTL=1s; advance clock 1
hour; drain each individually. All 5 drain successfully and all 5 returned
grants have `ExpTime < thunks.TimeNow()`. Confirms V4 (no TTL sweeper on
`agMap`) and shows the leak is **one entry per unconsumed expired grant**,
persistent across arbitrary wall-clock gaps.

### 3.3 `TestS1_V11_AuditPFDispatchUngated` — V11 code-structure audit

Parses `hopserver/session.go`, locates the `switch tube.Type()` inside
`(*hopSession).start`, and asserts the following case clauses contain no
call to `checkCmd`:

- `common.PFControlTube` (session.go:132)
- `common.PFTube` (session.go:134, and the Unreliable branch at 144)
- `common.AuthGrantTube` (session.go:130)
- `common.WinSizeTube` (session.go:136)

Only `common.ExecTube` (session.go:118-129) routes through `checkCmd`, via
`startCodex` → `sess.checkCmd` (session.go:224). All other tube handlers
accept with no inspection of `sess.authorizedActions` at all. This is V11
expressed as a test-suite invariant: if someone later adds the gate
(upstream fix), this test will trip and signal that S1 must be
re-adjudicated.

---

## 4. Lifecycle state-machine adjudication

Per the plan §3.1 state diagram, S1 traces:

```
STORED(agMap) + KEY_ADDED  --clock advance past ExpTime-->  (no transition — no sweeper)
                           --AuthorizeKeyAuthGrant------->  ATTACHED(session, authorizedActions)
                           --checkCmd match on expired --->  DENIED (returns, slice unchanged)
                                                              |
                           sess alive, authorizedActions = [expired ag] (zombie)
```

The missing edges are the finding:
- **No STORED → EXPIRED edge** triggered by clock advance (V4).
- **No STORED → EXPIRED edge** triggered at drain time (V3).
- **No ATTACHED → CLOSED edge** triggered by action denial (`checkCmd`
  denial does not close the session — session.go:104-157 continues the
  Accept loop).

---

## 5. Zombie session — residual capability surface

What the delegate holds in the zombie state (session is alive,
`authorizedActions = [expired cmd:date]`):

| Capability | Gated by anything? | Location |
|------------|--------------------|---------|
| ExecTube (named cmd/shell) | **yes**, `checkCmd` enforces string+expiry | `session.go:118-129` → `session.go:224` → `target.go:78-96` |
| PFControlTube (open PF control channel) | **no** | `session.go:132` |
| PFTube (reliable + unreliable) | **no** | `session.go:134, 144` |
| AuthGrantTube (accept more intent communications) | **config-level only** (`EnableAuthgrants`); not per-session, not grant-expiry | `session.go:130` → `session.go:179-186` |
| WinSizeTube | **no** | `session.go:136` |

The ⚠ payoff: the delegate can request a `PFControlTube` and then an
unreliable `PFTube` to `127.0.0.1:5432` (or anywhere the hopd process can
route). **Every one of these tubes is reachable from a session whose only
grant-of-record has expired.**

---

## 6. Phase-5 classification (three-question triage, plan §9)

| Q | Answer |
|---|--------|
| 1. What does the paper commit to? | §7.3: "immediately invalidated **after use or timeout**." Req. 5: "must not be reusable beyond their intended scope." |
| 2. Does the paper/spec specify the behavior the code got wrong? | **Partially.** The *literal sentence* mandates invalidation after timeout; the code's `checkCmd` is the only enforcement. The spec does not decompose "invalidated" into {transport key / session mint / per-action}. |
| 3. Would a faithful from-scratch implementation following the paper still be vulnerable? | **For the per-action check: no** (the spec requires it — this is a dev bug: missing sweeper + missing drain filter + missing expiry-driven key removal). **For the zombie-capability composition: yes** — the paper never says *which* capabilities timeout invalidates, and gating only `ExecTube` is a reading consistent with the text. |

**Verdict split:**

1. **Dev bugs** (upstream-issue-ready per Appendix B convention):
   - **D-S1-α** `AuthorizeKeyAuthGrant` must filter expired grants before
     returning them. Root: `hop-go/hopserver/target.go:26-35`; call into
     `agMap.RemoveAuthgrants` and post-filter.
   - **D-S1-β** `agMap` needs a TTL sweeper (or at minimum an
     expiry filter inside `RemoveAuthgrants`). Root:
     `hop-go/authgrants/authgrants.go:52-64`. The code comment at
     `hopserver/target.go:21` already admits the sweeper is TODO.
   - **D-S1-γ** `keyStore.RemoveKey(publicKey)` must fire when the last
     grant for `(user, publicKey)` expires, not only on successful drain.
     Root: `hop-go/hopserver/hopserver.go:332` has the add; the paired
     removal (`hopserver/target.go:31`) only runs on `nil` drain error.

2. **Design residue** (feeds `design_oversights.md` Candidate 1 —
   capability composition):
   - The *paper-level* question "what does invalidation mean when a grant
     is a composite capability (transport key + agMap entry + session
     affordances)?" is not answered by §7.3. S1 is the concrete
     demonstration that the composition decomposes into {one gated path,
     four ungated paths}. The Candidate-1 writeup needs the S1 trace as
     its primary example alongside S3 (duplicate actions) and S7
     (shell→localPF).

3. **No crash.** All assertions pass without panic; no `HOP_POC` skip-guard
   needed.

---

## 7. Deliverables (this scenario)

| ID | Path | Purpose |
|----|------|---------|
| S1-T1 | `hop-go/hopserver/grant_scenario_s1_test.go` → `TestS1_ExpireBeforeConnect` | core zombie walk (steps a–d) |
| S1-T2 | same file → `TestS1_StaleGrantLeakAgMap` | V4 leak measurement |
| S1-T3 | `hop-go/hopserver/grant_scenario_s1_v11_audit_test.go` → `TestS1_V11_AuditPFDispatchUngated` | AST-level invariant that PF/AG/WinSize branches are ungated |
| S1-F | this file | adjudication + file:line anchors for report extension |

All three tests pass under `go test ./hopserver/ -run 'TestS1'`. Full
module test (`go test ./...`) passes with zero failures.

---

## 8. Open follow-ons / notes for the next scenarios

- **S7 (grant-type composition demo)** is the natural next step from §5's
  capability table — it packages the zombie's PF reach into a concrete
  "shell grant implicitly permits local-pf" walkthrough. S1's §5 table is
  the input to S7's scope statement.
- **S3 (duplicate actions)** will consume the same `authorizedActions`
  shape — its INV-A/F question ("at most once per grant vs per action")
  can reuse this harness verbatim.
- **Upstream-issue drafts** for D-S1-α/β/γ can be composed from §6's root
  pointers; the tests here serve as regression fixtures.
- **If upstream adds the drain-time expiry filter first**, S1-T1 step (b)
  will start failing — at which point the finding collapses to "PF
  non-gating only" (S1-T3 remains the single-line survivor) and the
  Candidate-1 residue stands alone. Record expected post-fix shape so
  future-us can re-evaluate without re-deriving.
