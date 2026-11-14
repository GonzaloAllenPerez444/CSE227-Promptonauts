# Scenario S6 — Grant theft / bearer semantics

**Plan reference:** `possible_attacks/grant_lifecycle_investigation_plan.md`
§7 (Phase 3, S6). Target: `hop-go/` @ `9a198a9` + the Phase-0 clock patch.

**Status:** adjudicated — INV-D holds only *vacuously*. Five tests pass
in-tree; no crash. Finding type: **primary design-level finding** (plan
§9: "the pure design-level candidate" and "candidate for the strongest
design-level finding of the batch"). Not a dev bug — a faithful
implementation of the paper's §7.3 as written would exhibit the same
property.

---

## 1. Hypothesis under test

**H3 (delegate binding is bearer).** "Possession of the ephemeral keypair
+ the intent is sufficient to consume the grant from any host. §3
explicitly grants the adversary 'previously issued intent-grant
credentials' — so the paper's §7.3 'bound to a specific … Delegate' is,
as deployed, binding-to-a-bearer-key."

**Invariant under test:** INV-D — §7.3 "bound to a specific … Delegate."
Operationalized as: consuming the grant requires MORE than possession of
a copy of the grant material + the delegate ephemeral keypair.

---

## 2. Experimental setup

- L2 session harness (`hop-go/hopserver/grants_harness_test.go`).
- New file: `hop-go/hopserver/grant_scenario_s6_test.go`.
- New companion AST audit:
  `hop-go/hopserver/grant_scenario_s6_binding_audit_test.go`.
- `plantGrantAsProd(srv, user, pub, cmd)` — faithful mirror of
  `hopserver.go:328-332` using `PrincipalID(NoSession)` (the production
  sentinel) rather than the Phase-0 harness's `PrincipalID(0)`. This
  matters because S6's finding is sensitive to what the target stores as
  the grant's principal-session reference.

---

## 3. Results

### 3.1 `TestS6_BearerConsumptionByAttackerBeforeDelegate` — the money shot

Timeline:

| T | Actor | Action | Result |
|---|-------|--------|--------|
| T0 | legitimate flow | `plantGrantAsProd` adds (user, pub, cmd) to agMap + keyStore | OK |
| T0 | — | `keyStore.VerifyLeaf(delegateLeaf)` | pass (V5) |
| T1 | **attacker** (holds intent + ephemeral keypair, no other state) | `srv.AuthorizeKeyAuthGrant(user, pub)` | **SUCCESS** — returns the grant |
| T1 | — | drained Authgrant's `PrincipalID` | `NoSession` (0xFFFFFFFF) |
| T2 | legitimate delegate | `srv.AuthorizeKeyAuthGrant(user, pub)` | fail: `no authgrant` |
| T2 | attacker's synthetic `hopSession` | `checkCmd(cmd, false)` | **SUCCESS** |

**Verdict:** the attacker, holding only the credential set §3 assumes they
can obtain, drained a grant the legitimate flow intended for the real
delegate. The target distinguished nothing: both callers present the same
`(user, pubkey)` tuple; neither carries a principal-session back-reference;
`AuthorizeKeyAuthGrant` takes no caller-identity argument; VerifyLeaf
would accept either one at the transport layer.

### 3.2 `TestS6_CertChainNotVerifiedOnConsumption` — scope of "cert"

Shows that `DelegateCert` is a container for a public key at the target's
consumption-time gate, not a verifiable identity assertion:

- `authkeys/verify.go:42-54` (`VerifyLeaf`) = `VerifyLeafFormat` +
  keyset-membership on `leaf.PublicKey`.
- `certs/verify.go:308-317` (`VerifyLeafFormat`) checks only `Type == Leaf`
  and optional Name matching — no issuer, no chain, no signature check.
- A leaf cert with the same `PublicKey` but attacker-chosen `IDChunk`
  (e.g., `attacker.example` instead of the delegate's claimed name)
  passes `VerifyLeaf` against the keyStore populated by the legitimate
  flow.

### 3.3 `TestS6_AgMapIndexIsKeyNotIdentity` — the storage root

The structural root of bearer semantics: `AuthgrantMapSync` keys on
`(TargetUsername, PublicKey)` only
(`authgrants/authgrants.go:41-50,52-64`). Inserting two cosmetically-
different Intents (different `DelegateCert.IDChunk`) under the same
`(user, pub)` coalesces: one drain call returns both grants. The
delegate's claimed identity material is *not* part of the storage key.

### 3.4 `TestS6_F1_DrainAPITakesNoCallerIdentity` — API-shape invariant

AST audit: `(*HopServer).AuthorizeKeyAuthGrant`'s parameter list is
exactly `(user string, publicKey keys.DHPublicKey)`. No caller cert, no
transport handle, no origin. If an upstream fix introduces one, this test
trips.

### 3.5 `TestS6_F2_ProductionAddUsesNoSession` — storage-shape invariant

AST audit: `(*HopServer).AddAuthGrant` (production add path,
`hopserver.go:308-334`) passes the identifier `NoSession` as the
`PrincipalID`. If upstream later threads the issuing principal's session
through here (which would open the door to a session-binding defence),
this test trips.

---

## 4. Cryptographic analysis — what does "Delegate" mean in Hop?

This is the analysis the plan (§7-S6, §9's predicted splits) requires
before classifying the finding.

**The question.** §7.3 says grants are "bound to a specific … Delegate."
What is the cryptographic meaning of "Delegate" at a Hop target's
consumption-time gate?

**The evidence.**

1. **Delegate cert origin.** The `DelegateCert` in an Intent is an
   *ephemeral* cert that the delegate itself generated to express
   intent-time identity. The principal never signs it. There is no CA
   chain. The principal's approval callback sees the Intent (including
   this cert) and either approves or denies — nothing about this
   approval produces a cryptographic *binding artefact* that travels
   with the grant.

2. **Target's identity view.** On the wire, the target sees the delegate
   over transport TLS-equivalent (the Hop handshake). The handshake
   proves possession of the private key matching some public key. That
   public key is then looked up in `keyStore`
   (`authkeys/verify.go:42-54`) — if it's in the set, the client is
   authorized. The target has no notion of "which delegate" beyond
   "holder of a key in `keyStore`."

3. **Grant storage.** The grant in `agMap` is indexed by
   `(TargetUsername, DelegateCert.PublicKey)` and stores
   `PrincipalID = NoSession` for grants issued through the normal path.
   Nothing in the stored row references the delegate beyond the
   pubkey + a `DelegateCert` blob that no later code validates.

4. **Delegate "signing" the intent.** `IntentRequest` carries the
   ephemeral delegate cert for pubkey transport; the intent bytes
   themselves are not signed by the delegate in a way the target
   independently verifies after issuance. The target accepts the
   `IntentCommunication` from the principal and stores the
   principal-forwarded Intent at face value.

**Therefore.** "Delegate" at target consumption time means exactly:
"whoever holds the private key corresponding to `DelegateCert.PublicKey`."
No other binding exists in code. This reduces the "bound to a specific …
Delegate" phrase to bearer-token semantics as deployed.

**Is this a dev bug or a design oversight?**

- If the paper intended "Delegate = whoever the principal approved the
  cert of during the approval dialog" — then the principal must sign a
  binding artefact that the target verifies. The paper names no such
  artefact. **Design oversight.**
- If the paper intended "Delegate = key-pair holder, by construction" —
  then §3's adversary-with-credentials assumption directly collides with
  §7.3's binding claim, because §3 hands the adversary the key. **Still
  a design oversight**: the paper's own threat model invalidates its own
  binding claim. One of the two sentences must be weakened.
- If the paper intended something else (e.g., per-connection re-auth
  with the principal at consumption time) — not implemented and not
  derivable from the text. **Design oversight.**

**What a faithful from-scratch implementation would require.** To
produce a non-bearer grant without changing the Hop spec surface, a new
binding artefact must appear and be verified:

- Principal signs `(DelegateCert.PublicKey, Intent)` with a key the
  target trusts, OR
- Principal issues a short-lived delegate cert in its own CA chain and
  the target checks that chain, OR
- Consumption requires a live challenge-response with the principal
  (which contradicts `authgrant_spec.md`'s explicit "principal may
  disconnect after issuance"), OR
- The grant is issued under a key the *principal* chose (not the
  delegate), with the delegate-chosen key serving only as a pubkey for
  encryption to the delegate.

All four are structural changes to the spec. **This is the clearest
design-level finding in the Phase-3 batch.**

---

## 5. Phase-5 classification (three-question triage, plan §9)

| Q | Answer |
|---|--------|
| 1. What does the paper commit to? | §7.3 "bound to a specific … Delegate"; Req. 5 "Delegated credentials must be bound to a specific user, action, target, and validity period, and must not be reusable beyond their intended scope." |
| 2. Does the paper/spec specify the behavior the code got wrong? | **No.** The paper's binding language is not operationalized. The code is consistent with the only reading of §7.3 the paper actually supports (key-possession = delegate identity). The spec does not name a cryptographic artefact the code is missing. |
| 3. Would a faithful from-scratch implementation following the paper still be vulnerable? | **Yes.** As argued in §4: no mechanism is specified; four non-trivial spec changes could fix it. |

**Verdict:** this is a **design-level oversight**, not a dev bug.
Candidate for a new entry in `design_oversights.md` under a new candidate
heading "grant bearer-token semantics," alongside existing Candidates
1 (capability composition) and 2 (chain-of-authority).

---

## 6. Interactions with S1 and S4

- **S1 + S6.** S1's zombie session is *doubly* exploitable under S6: an
  attacker with the key can drain the grant even after expiry (V3 says
  drain has no expiry filter) and even if the legitimate delegate never
  connected. The attack is not limited by the delegate's online presence.
- **S4 + S6.** S4's V8 compounds: a key-holding attacker can also forward
  an additional Intent through the open principal-session (if the
  principal is still connected) and the discarded-error path adds it to
  the attacker's grant stash. §4's residue means even a fixed #201 does
  not fix the UX-layer habit-approval surface; a key-holding attacker who
  times their follow-up intent to mimic the delegate's can graft grants
  onto the same live approval dialog.
- **S6 + Candidate 2.** The "what does 'Delegate' mean" question is a
  Candidate-2 (chain-of-authority) residue. The chain the paper implies
  is Principal → Delegate → Target; the code's chain is
  Principal → (nothing) → KeyHolder. The step the code elides is the
  cryptographic step that would bind Delegate identity to the grant.

---

## 7. Deliverables (this scenario)

| ID | Path | Purpose |
|----|------|---------|
| S6-T1 | `hop-go/hopserver/grant_scenario_s6_test.go` → `TestS6_BearerConsumptionByAttackerBeforeDelegate` | adversary-with-credentials races and wins |
| S6-T2 | same file → `TestS6_CertChainNotVerifiedOnConsumption` | DelegateCert's identity claim is advisory; pubkey is the gate |
| S6-T3 | same file → `TestS6_AgMapIndexIsKeyNotIdentity` | storage key is (user, pub); identity material is not partitioning |
| S6-T4 | `hop-go/hopserver/grant_scenario_s6_binding_audit_test.go` → `TestS6_F1_DrainAPITakesNoCallerIdentity` | AST invariant on AuthorizeKeyAuthGrant signature |
| S6-T5 | same file → `TestS6_F2_ProductionAddUsesNoSession` | AST invariant that AddAuthGrant stamps NoSession |
| S6-F | this file | adjudication + the cryptographic-binding analysis (§4) |

All five tests pass under `go test ./hopserver/ -run 'TestS6'`.
Full module test (`go test ./...`) passes with zero failures.

---

## 8. Open follow-ons / notes for the next scenarios

- **S7 (shell → PF composition)** compounds with S6 in an important way:
  a bearer-grant for `shell` yields a bearer-reachable `PFControlTube`
  (per S1 §5's zombie capability table). S7's writeup should cite S6 as
  the "who can execute S7" scoping statement — it is not only the
  compromised delegate.
- **S3 (multi-grant drain)** — S6's `TestS6_AgMapIndexIsKeyNotIdentity`
  already exercises the agMap coalescing shape; S3's INV-A/F test will
  reuse the same insertion pattern with duplicate command strings.
- **Upstream engagement** — unlike S1 (dev bugs) and S4 (admitted
  upstream as #201), S6 does not reduce to a filable fix. The upstream
  engagement for S6 is a spec-level question for the authors: which of
  the four §4 structural changes does the paper intend? Draft that
  question — not a patch — for Appendix B.
- **Paper writeup framing** — this is the finding to lead with when
  arguing that Hop's novel security claim (Req. 5 / §7.3's binding
  words) has a code-level gap that is not the authors' typo, not an
  oversight the code team can patch in isolation, but a question the
  spec must answer.
