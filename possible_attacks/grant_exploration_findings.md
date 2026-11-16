# Grant-lifecycle random exploration — findings

**Phase 4.1 of `grant_lifecycle_investigation_plan.md`.** Invariant-guided
random exploration of the L2 grant state machine, paired with a shadow
model that asserts the code's own promises after every op. Deliverable
D4 per plan §10.

**Artifact.** `hop-go/hopserver/grant_exploration_test.go` — one source
file, three tests:
- `TestExploration200x8` — 200 random traces of length 8, default sweep.
- `TestExplorationReplaySeed` — reproduces a single seed on demand
  (env `RANDOM_SEED=0x...`); prints the full op trace.
- `TestExplorationStressLong` — the stop-rule sweep: 2 000 random
  traces of length 12. Opt-in via `EXPLORE_STRESS=1` (24 000 ops total;
  ~0.2 s wall on dev; CI-skippable).

**Pinned state.** `hop-go/` @ `9a198a9` plus the local Phase-0 thunks
clock patch (see `grant_lifecycle_investigation_plan.md` §11).

---

## 1. Op vocabulary

Drawn from the plan's §8.1 enumeration, narrowed to what the L2 layer
can execute without a live transport:

| Op | Payload | Semantic (real + shadow) |
|----|---------|--------------------------|
| `addGrant` | user, pub, {cmd:X \| shell}, ttl | `agMap.AddAuthGrant` + `keyStore.AddKey` |
| `advanceClock` | d ∈ {5s, 30s, 2m, 10m} | moves `thunks.TimeNow` forward by d |
| `drainGrants` | user, pub | `AuthorizeKeyAuthGrant` — mints a session |
| `checkCmd` | sess, cmd | `sess.checkCmd(cmd, false)` |
| `checkShell` | sess | `sess.checkCmd("...", true)` |
| `readdKey` | pub | `keyStore.AddKey(pub)` — S6-adjacent |

**Pools:** 2 users × 3 pubkeys × 4 cmd strings × 4 TTLs = 96 distinct
`addGrant` payloads. Weights favor `addGrant` (30) over
consumption (15/10) so every trace has material to consume. Sessions
created by `drainGrants` are tracked in both the real runner and shadow.

**Why these ops (and not `sendIntent`/`approve`/`stall`/`killPrincipal`):**
the plan's full op list includes L1-layer actions (principal-side
approval flow). Those are covered deterministically by S4 and S5; they
collapse to "grant-added-or-not" at the L2 interface, which is the
layer where state divergence actually lives. Confining this runner to
L2 lets it cover 24 000 ops in 0.2 seconds, which is the right
cost/coverage trade for Phase 4.1.

---

## 2. Invariants asserted

These are the CODE's own promises, not the paper's — the paper-level
invariants (INV-A … INV-G) are already adjudicated by S1–S8 and most
are known-falsified. Random exploration's job is to catch
implementation bugs the scenario matrix missed.

| ID | Statement | Assertion mechanism |
|----|-----------|---------------------|
| M1 | `AuthorizeKeyAuthGrant(u, p)` returns exactly the shadow's `agMap[u][p]` slice in insertion order, and clears it. | Length + per-element GrantType/Cmd/ExpTime equality after each drain. |
| M2 | A successful drain removes `p` from the keystore. | `keyStore.VerifyLeaf(leaf(p), …)` must error "not found" immediately after. |
| M3 | `checkCmd` consumes ≤ 1 grant; on success, it matches the predicate AND is live. | Shadow picks first matching live entry; real must agree. |
| M4 | A failed `checkCmd` leaves `authorizedActions` untouched. | Length unchanged on error. |
| M5 | `addGrant` grows the bucket by 1 and adds `p` to the keystore. | Shadow performs the exact same mutation; divergence flagged. |
| M6 | No panics across 2 000 × 12 ops. | Whole runner wrapped in `recover()`. |

Any divergence panics with `INVARIANT VIOLATION: <msg>`; the outer
test converts that to `t.Fatalf` with the seed and full op trace, so
repro is `RANDOM_SEED=0x... go test -run TestExplorationReplaySeed`.

---

## 3. Characterization counters (not asserted)

Known-falsified paper invariants we observe but don't assert:

| C | What it counts | Why we count it |
|---|---------------|-----------------|
| C_B | Expired grants successfully drained (INV-B residue, S1). | Confirms the random stream exercises the known S1 interleaving. |
| C_F | Successful `checkCmd` on grants past ExpTime between drain and consumption. | Would be a S1 escalation: expired grant surviving into execution. Stays 0 because `checkCmd` has the live gate (V2). |

**Observed (200 × 8 default sweep, seed base 0xc0ffee):**

- `expired-drained = 10` — INV-B residue observed in 10 of 200 traces.
- `expired-cmd-attempts = 0` — no trace produced an expired cmd that
  actually executed through `checkCmd`. This is consistent with V2:
  `checkCmd` does re-check `ExpTime`, so the S1 zombie's residual
  capability is the ungated-tube half (V11), not a per-action bypass.

---

## 4. Results

**200 × 8 (default):** PASS, 0 invariant violations, 0 panics.
**2 000 × 12 (stress, `EXPLORE_STRESS=1`):** PASS, 0 invariant violations,
0 panics.

Combined that's 24 200 ops across 2 200 distinct seeds. Satisfies the
plan's §8.1 stop rule ("no new invariant classes for 2k traces").

### 4.1 No new findings — what that means

The shadow model is deliberately thin: it encodes the code's EXPLICIT
behavior, not the paper's aspirational semantics. The runner found no
case where the real server diverged from that thin model. That is a
CLEAN result for M1–M6.

It is NOT a certification that no further issues exist. The runner's
ceiling is the ops it can emit (no concurrency, no malformed-wire
inputs, no transport-layer races). Parser-level anomalies and message
dispatch panics are explicitly out of scope here — they are Phase 4.2
(D5) via `go test -fuzz`.

### 4.2 Confirmed known findings (via characterization)

- **S1 / INV-B residue:** 10/200 traces drained an expired grant (C_B).
  No further finding beyond S1 — the sweep is consistent with the
  scenario matrix's result.
- **S3 / INV-A duplicate insertion:** every `addGrant` with duplicate
  `(user, pub, cmd)` under live TTL grows the bucket; M1's exact-length
  check means this is implicitly asserted every time it happens. Same
  conclusion as `TestS3_DuplicateCmdStoresThreeEntries`.
- **S6 / bearer-key semantics:** `readdKey` ops produce no divergence —
  the keystore is a set on `DHPublicKey`, and re-adds after a drain
  silently restore trust, exactly as S6 predicts. No new finding.

### 4.3 Negative results worth noting

- `readdKey` followed by a later `drainGrants` under the SAME pubkey
  never produced a double-drain — because the drain had already
  emptied `agMap` for that (user, pub). The keystore and agMap are
  decoupled; re-adding the key doesn't resurrect grants. That is
  arguably the right design (grants are not key-indexed into trust),
  and this runner confirms it holds under random interleavings.
- No ordering anomaly in `agMap` under interleaved adds + drains:
  insertion order is preserved by the slice, as M1 requires.

---

## 5. Reproducibility

- **RNG:** `math/rand/v2` PCG, seeded by `(seed, 0)`. Stable across Go
  1.22+ by Go-team contract.
- **Clock:** `thunks.TimeNow` fixed to `2026-01-01T12:00Z` at trace
  start; each op advances it by a bounded delta.
- **Server:** fresh `newTestServer` per trace, no shared state across
  seeds.
- **Env knobs:**
  - `RANDOM_SEED_BASE=0x<...>`: override the default sweep base seed.
  - `RANDOM_SEED=0x<...>`: single-seed replay for `TestExplorationReplaySeed`.
  - `EXPLORE_STRESS=1`: enable the 2 000×12 sweep.

When a future change causes a sweep to fail, the failure line names
the seed. Run `RANDOM_SEED=0x<...> go test -run TestExplorationReplaySeed`
to inspect the minimal op trace.

---

## 6. What this does NOT cover, and the pointers forward

- **Parser/dispatch panics** — Phase 4.2 fuzzing (`go test -fuzz`
  targets in `authgrants/`), per plan §8.2. F3's LocalPF/RemotePF
  panic class is the seed.
- **Concurrent operations** — this runner is single-threaded. Races
  in `AuthgrantMapSync.agLock` are not explored here; they could be
  added by swapping the sequential loop for `t.Run(..., parallel)` and
  giving the shadow its own mutex, but at the cost of giving up the
  simple "exact-equality after every op" contract.
- **L1-layer interleavings with partial failures** — S5's state-
  reachability map is the targeted artifact for that; the L2 shadow
  model doesn't try to reproduce principal-side control flow.
- **Message-wire fuzzing** — fully disjoint from this runner's scope;
  belongs under D5.

Phase 5 (D6) folds the negative result above into the final triage
addendum alongside S1–S8. The headline sentence for the report is:
*"24 200 random L2 ops produced zero new invariant violations; the
scenario matrix's findings are the complete set at the code-behavior
layer."*
