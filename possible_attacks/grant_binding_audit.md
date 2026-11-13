# Grant Binding Audit

**Target:** `hop-go/` @ `9a198a9` + Phase-0 thunks-clock patch  
**Sources audited:** §7.3, Req. 5, `authgrant_spec.md`, `handshake_spec.md`  
**Method:** For each paper security sentence, map every binding word to where the field is *written/stored* and where it is *read as a check*. Verdict options: **Enforced**, **Partial**, **Absent**, **TODO-marked**, **Bearer**.  
**Rows predicted absent or partial are the candidates for Phase-3 scenario adjudication.**

---

## 1. Field storage map

Which fields from `Intent` survive into the stored `Authgrant`?

| `Intent` field | In `Authgrant` struct | Authgrant map key |
|----------------|-----------------------|-------------------|
| `GrantType` | ✓ | — |
| `StartTime` | ✓ | — |
| `ExpTime` | ✓ | — |
| `TargetSNI` | **✗** | — |
| `TargetUsername` | ✗ (implicit) | outer map key (`agMap[user][key]`) |
| `DelegateCert` | ✓ (full cert) | inner map key (`.PublicKey`) |
| `AssociatedData` | ✓ | — |
| `PrincipalID` | ✓ | — |
| `TargetPort` | **✗** | — |

`TargetSNI` and `TargetPort` are **not stored** in `Authgrant` at all (`newAuthgrant`, `authgrants/authgrants.go:67`). They exist only in transit and are discarded after `checkIntent` returns.

---

## 2. Per-binding-word audit table

Columns: **Paper sentence** | **Binding word** | **Written/stored at** | **Checked at (file:line)** | **Verdict** | **Phase-3 scenario**

---

### 2.1 Expiration / "immediately invalidated after use or timeout"

> §7.3: "immediately invalidated after use **or timeout**"  
> Req. 5: "must not be reusable beyond their … validity period"

| Check point | File:line | Present? |
|-------------|-----------|----------|
| Admission (`checkIntent`) | `hopserver/target.go:42` | ✓ `intent.ExpTime.Before(thunks.TimeNow())` |
| Drain (`AuthorizeKeyAuthGrant`) | `hopserver/target.go:26-36` | **✗ no expiry filter** |
| agMap sweeper | `authgrants/authgrants.go` entire file | **✗ no sweeper exists** |
| Action (`checkCmd`) | `hopserver/target.go:81` | ✓ `thunks.TimeNow().Before(ag.ExpTime)` |
| Transport key removal | `hopserver/hopserver.go:332` / `target.go:31` | Key removed **at drain**, not at expiry |

**Verdict: Partial (INV-B violated in full form)**

- Expiry is enforced at admission and at action, but not at drain.
- An expired grant whose key was added to `keyStore` at creation (`hopserver.go:332`) enables transport auth even after `ExpTime` passes (the key is never removed by a sweeper — only removed on a successful drain call).
- A grant admitted before its TTL passes will drain into a session regardless of whether it has since expired: `AuthorizeKeyAuthGrant` → `RemoveAuthgrants` does no expiry filter (`authgrants/authgrants.go:52-64`).
- The comment "removing expired still TODO" at `target.go:20` is the upstream admission of this gap.
- **Paper claim not met:** "immediately invalidated after **timeout**" requires that after `ExpTime`, no capability derived from the grant is exercisable — but the transport key remains in the pool indefinitely and sessions minted from an expired grant persist (V12).
- **→ S1** (H1, INV-B)

---

### 2.2 Target binding / "bound to a specific … Target"

> §7.3: "bound to a specific … Target"  
> `authgrant_spec.md`: "The Principal verifies that the target server's certificate matches the Target SNI field in the Intent Request"

| Check point | File:line | Present? |
|-------------|-----------|----------|
| `TargetSNI` stored in `Authgrant` | `authgrants/authgrants.go:67` | **✗** (field not copied into `newAuthgrant`) |
| `TargetSNI` checked at admission | `hopserver/target.go:46` | **✗ TODO** ("check target SNI matches … necessary?") |
| `TargetSNI` checked at drain | `hopserver/target.go:26-36` | **✗** |
| `TargetPort` stored in `Authgrant` | `authgrants/authgrants.go:67` | **✗** |
| `TargetPort` checked at any point | (grep: no results) | **✗** |
| Vhost matching | `hopserver/hopserver.go:420-424` | raw glob, no name-type disambiguation (TODO V14) |

**Verdict: Absent (INV-C)**

- `TargetSNI` is transmitted in the `Intent` but never stored in `Authgrant` and never compared against the serving vhost's identity at any stage of the grant lifecycle.
- The spec says "the Principal verifies that the target server's certificate **matches the Target SNI field**" — in `hopclient/principal.go` this check would live in the transport handshake callback, but `authgrants/principal.go:97-104` only passes `checkIntentWithCert` as an `AdditionalVerifyCallback`; whether this callback actually compares SNI depends on the caller's implementation — not enforced in-protocol.
- A grant minted for `target-A` is accepted by `target-B` if the same user/key pair connects.
- **→ S2** (H2, INV-C)

---

### 2.3 Delegate binding / "bound to a specific … Delegate"

> §7.3: "bound to a specific … Delegate"  
> Req. 5: "must not be reusable beyond their intended scope"  
> §3 (Endpoint Adversary): adversary "can obtain previously issued intent-grant credentials"

| Check point | File:line | Present? |
|-------------|-----------|----------|
| `DelegateCert` stored in `Authgrant` | `authgrants/authgrants.go:72` | ✓ |
| Delegate public key added to `keyStore` | `hopserver/hopserver.go:332` | ✓ |
| `keyStore.VerifyLeaf` at transport connect | `hopserver/session.go:67-86` via `transport.Handle` | ✓ public key possession checked |
| Cert *chain* verified | `authkeys/verify.go:42-54` | **✗** only format + key-in-set; no root/CA chain |
| Binding beyond key possession | (grep: no source-address binding, no origin check) | **✗ bearer semantics** |

**Verdict: Bearer (INV-D — open question)**

- "Delegate" = whoever holds the ephemeral keypair that the delegate generated. Possession of `{intent, ephemeral keypair}` is sufficient to consume the grant from any host.
- §3 explicitly places "obtaining previously issued intent-grant credentials" in the adversary model. Under that assumption, nothing prevents consuming the grant from a second host: the target only checks key possession via `keyStore.VerifyLeaf`, not identity of the connecting host.
- Whether this meets §7.3's "bound to a specific Delegate" depends on whether "Delegate" means the cert subject or the cert holder. The cert subject is the ephemeral key; the holder is whoever has the private key. If the principal saw the delegate's cert during the handshake (via `checkIntentWithCert`), "specific Delegate" might mean "the entity that presented that cert during the approval." That entity is undefined after the fact.
- **Classification decision deferred to Phase 5 (S6 adjudication)** — this is the strongest design-level candidate or the strongest negative result.
- **→ S6** (H3, INV-D)

---

### 2.4 "Each one performed at most once" / one-shot consumption

> §7.3: "each one to be performed **at most once**"  
> §7.3: "each intent … authorized **only once**"

| Check point | File:line | Present? |
|-------------|-----------|----------|
| `checkCmd` removes grant after use | `hopserver/target.go:85` `slices.Delete` | ✓ per-grant one-shot for `cmd` |
| Shell grant consumed on use | `hopserver/target.go:90-91` | ✓ per-grant one-shot for `shell` |
| Duplicate cmd grants (two grants, same `cmd` string) | `authgrants/authgrants.go:49` `append` | Allowed — same action can run N times (one per grant) |
| PF via `PFControlTube` | `hopserver/session.go:133` | **✗ no grant check** (V11) |
| PF via `PFTube` | `hopserver/session.go:144` | **✗ no grant check** (V11) |
| `AuthGrantTube` acceptance | `hopserver/session.go:131,175` | **✗ no grant check** (V10 TODO) |

**Verdict: Partial (INV-A per-grant enforced; INV-F per-action violated for duplicates; INV-A/B violated for PF)**

- For `cmd`/`shell` grants: each individual `Authgrant` object enables exactly one action (one-shot `slices.Delete`). **This satisfies INV-A as stated.**
- However: if the principal approved two intents for `cmd:date`, both are stored and both are exercisable, so the same *action* can run twice. INV-F ("each intent authorized only once") is per-grant, so this is a design ambiguity rather than a code bug.
- For PF tubes: `PFControlTube` and `PFTube` are accepted from any authenticated session with zero reference to `authorizedActions` or `checkCmd`. An expired-grant zombie session (S1) retains full PF capability.
- **→ S3** (duplicates), **S7** (PF via zombie session)

---

### 2.5 Explicit approval / "flow stops"

> §7.3: "the authorization grant flow **stops** and the Principal requests **explicit approval** from the user"  
> §7.3: "each intent … is authorized **only once**"

| Check point | File:line | Present? |
|-------------|-----------|----------|
| First intent: `checkIntent` called via `AdditionalVerifyCallback` | `authgrants/principal.go:97-104` | ✓ user approval callback invoked |
| First intent: return error from `checkIntent` aborts target connection | `authgrants/principal.go:105-109` | ✓ |
| Follow-up intent: `checkIntent` called | `authgrants/principal.go:115` | ✓ called |
| Follow-up intent: return error **acted on** | `authgrants/principal.go:115` | **✗ return value discarded** (Issue #201) |
| Follow-up intent: proceeds to `WriteIntentCommunication` even after denied | `authgrants/principal.go:118` | **✗ always sends to target** |

**Verdict: Absent for follow-up intents (INV-E/G)**

- The first intent requires the principal's `setUpTargetConn` callback to call the `AdditionalVerifyCallback`, which wraps `checkIntent`. If denied, `setUpTargetConn` returns an error and the target connection is never established. **First-intent approval is enforced.**
- For every subsequent intent on the same target tube: `p.checkIntent(i, p.targetCert)` is called at line 115 but the return value is not captured. The code proceeds unconditionally to `WriteIntentCommunication`, forwarding the intent to the target **regardless of whether the user approved it.** (Issue #201, confirmed in V8.)
- Target-side: `targetInstance.run()` loops indefinitely on `ReadIntentCommunication`, accepting every forwarded intent. The target's `checkIntent` admission gate still runs (and can reject at the target level), but the **principal-side user approval** is bypassed.
- **→ S4** (H4, INV-E, INV-G)

---

### 2.6 Validity period / `StartTime`

> Req. 5: "bound to a specific … validity period"  
> `authgrant_spec.md`: "Start Time (8 bytes): timestamp of when the authorization grant becomes effective"

| Check point | File:line | Present? |
|-------------|-----------|----------|
| `StartTime` stored in `Authgrant` | `authgrants/authgrants.go:70` | ✓ |
| `StartTime` checked before granting | (grep: no `.StartTime` comparisons in auth path) | **✗ never checked** |

**Verdict: Absent**

`StartTime` is stored but no code path checks that `thunks.TimeNow() >= ag.StartTime` before admitting or executing a grant. A grant with a future `StartTime` is exercisable immediately. This is a minor gap relative to INV-B's expiry issue (grants become exercisable before their window, not after it), but it means the "validity period" lower bound is advisory-only.

---

### 2.7 Nil principal callback / `insecureAcceptAll` default (Issue #202)

> §7.3: "explicit approval from the user"  
> `authgrant_spec.md`: approval UI shown to user

| Check point | File:line | Present? |
|-------------|-----------|----------|
| `nil` `checkIntent` callback | `authgrants/principal.go:45-48` | Defaults to `insecureAcceptAll` — accepts all without user interaction |
| `insecureAcceptAll` logs "insecurely accepting" | `authgrants/principal.go:59` | ✓ logged but not blocked |
| Callers that pass `nil` | `authgrants/authgrants_test.go:142` (`TestPrincipalNilCallback`) | Test explicitly exercises this path |

**Verdict: Absent (design-default fail-open on principal; fail-closed on target)**

- `nil` principal callback → `insecureAcceptAll` (silent approval).
- `nil` target callback → `defaultRejectAll` (explicit rejection).
- Asymmetric defaults: the security-critical side (principal = human approval gate) fails open; the less-critical side (target = policy admission) fails closed. This is Issue #202.

---

### 2.8 `AuthGrantTube` access control (V10 / Issue: in-code TODO)

> `authgrant_spec.md`: "hopd listens on a unix socket for requests from descendant processes"

| Check point | File:line | Present? |
|-------------|-----------|----------|
| Descent check for unix socket clients | `hopserver/agproxy.go:266-310` | ✓ PID-based lineage check (Linux only) |
| Check that session issuing `AuthGrantTube` holds an authgrant | `hopserver/session.go:175` | **✗ TODO** ("add check for authgrant?") |

**Verdict: Absent for transport-layer sessions**

Any authenticated session (including one authenticated via `authorized_keys`, not just via authgrant) can open an `AuthGrantTube` and have the server proxy authgrant protocol messages. The TODO at `session.go:175` acknowledges this.

---

## 3. Summary table

| Binding word | Paper sentence anchor | Verdict | INV | Phase-3 scenario |
|---|---|---|---|---|
| `ExpTime` @ drain | §7.3 "invalidated after timeout" | **Absent** | INV-B | S1 |
| `ExpTime` sweeper | §7.3 "invalidated after timeout" | **Absent** | INV-B | S1 |
| `ExpTime` @ admission | §7.3 "invalidated after timeout" | Enforced | — | — |
| `ExpTime` @ action | §7.3 "invalidated after timeout" | Enforced | — | — |
| `TargetSNI` | §7.3 "bound to … Target" | **Absent/TODO** | INV-C | S2 |
| `TargetPort` | Req. 5 "specific … target" | **Absent** | INV-C | S2 |
| `TargetUsername` | Req. 5 "specific user" | Enforced | — | — |
| `DelegateCert` format | §7.3 "bound to … Delegate" | Enforced | — | — |
| `DelegateCert` chain | §7.3 "bound to … Delegate" | **Absent** | INV-D | S6 |
| `DelegateCert` bearer | §7.3 "bound to … Delegate" | **Bearer** (open) | INV-D | S6 |
| `GrantType` policy | Req. 5 "specific action" | **TODO** | INV-A | S7 |
| `cmd` string one-shot | §7.3 "at most once" | Enforced (per-grant) | INV-A | — |
| `cmd` duplicate grants | §7.3 "each intent only once" | Partial (per-action ambiguous) | INV-F | S3 |
| PF tube grant gate | §7.3 "at most once" | **Absent** | INV-A/B | S7 |
| Follow-up approval | §7.3 "explicit approval" | **Absent** | INV-E/G | S4 |
| First-intent approval | §7.3 "explicit approval" | Enforced | — | — |
| `nil` principal callback | §7.3 "explicit approval" | **Absent (default fail-open)** | INV-E | — |
| `StartTime` check | Req. 5 "validity period" | **Absent** | INV-B | (S1 extension) |
| `AuthGrantTube` access | spec descent check | **Absent (TODO)** | — | (S4 extension) |

**Enforced:** 5 rows  
**Absent/TODO/Bearer/Partial:** 14 rows  

---

## 4. Static-resolved findings (no scenario needed)

**SR-1 — `StartTime` is advisory.** Field stored, never read as a constraint. Any grant is exercisable from the moment it is admitted, regardless of `StartTime`. (Low severity — does not expand attack surface beyond what INV-B already captures.)

**SR-2 — `TargetPort` is advisory.** Not stored in `Authgrant`, not checked at drain or use. A grant requesting port 22 can be consumed against a session that authenticated on port 7777.

**SR-3 — `insecureAcceptAll` is a live production path.** `authgrants/principal.go:47` activates when callers pass `nil`. The only protection is a log line. (Issue #202.)

**SR-4 — `DelegateCert` chain is not verified.** `certs.VerifyLeafFormat` checks structure only; `certs.VerifyOptions{}` is empty. The delegate cert is effectively self-asserted. The security implication is that "delegate identity" reduces to "holder of the keypair," which is the bearer question explored in S6.
