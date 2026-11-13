# Grant TODO/Issue Cross-Reference Roadmap

**Target:** `hop-go/` @ `9a198a9` + Phase-0 thunks-clock patch  
**Source:** `grep -rn 'TODO\|XXX\|FIXME' --include='*.go' authgrants/ hopserver/` — 36 markers  
**Columns:** `TODO (file:line)` | `Paper claim / spec` | `Issue tracker #` | `Already covered / NEW` | `Priority (if NEW)`

Rank criteria for NEW items: *claim criticality × reachability × cost-to-test*  
Priority scale: **P1** = highest / money-shot, **P2** = medium, **P3** = hygiene / deprioritize

---

## 1. `authgrants/` package

| # | TODO (file:line) | Paper / spec claim | Issue # | Coverage | Priority |
|---|---|---|---|---|---|
| A1 | `messages.go:52` — "what interface? inc: Intent, Denial" | None — API design question | — | Hygiene | P3 |
| A2 | `messages.go:80` — "not sure if this is the best way to approach this" (GrantData union) | None — API design | — | Hygiene | P3 |
| A3 | `proxy_messages.go:42` — "make this work for all possible cert.Name.Types" (`ConnectToTarget`) | spec §"Target SNI ≤256 bytes, in format of cert IDBlock" | — | **NEW** | P2 |
| A4 | `principal.go:66` — "add way to close without waiting for delegateconn to close?" | spec: approval gate lifetime | — | Covers Issue #80 partial / **NEW resource-leak angle** | P2 |

### A3 detail — cert.Name.Types disambiguation in `ConnectToTarget`
`proxy_messages.go:42-56`: `ConnectToTarget` currently ignores `m.TargetSNI` entirely and uses `m.TargetURL.Address()` directly. The comment says the intended logic (use `TargetSNI.Label` as hostname) is commented out. `TargetSNI` is a `certs.Name` which has a `Type` field (`TypeRaw`, `TypeDNSName`, `TypeIPv4Address`). Without type disambiguation, any `TypeRaw` label is treated as a raw host string — the same gap as `hopserver/hopserver.go:418` (V14). **Relates to INV-C binding** but is in the proxy path, not the target path: the proxy uses TargetURL (derived from the full URL) to connect; the SNI-based destination check is simply absent. Already noted in grant_binding_audit.md §2.2.

### A4 detail — principal close-without-waiting
`principal.go:66`: The `run()` loop blocks on `ReadIntentRequest` until the delegate closes the connection. No timeout or external signal path. This matters for Issue #80 (approval stalls indefinitely if delegate hangs) and S5 (resource characterization of stall). It is distinct from #80 in that #80 is about the approval callback blocking; A4 is about what happens after the callback returns but the delegate connection is still open.

---

## 2. `hopserver/session.go`

| # | TODO (file:line) | Paper / spec claim | Issue # | Coverage | Priority |
|---|---|---|---|---|---|
| B1 | `session.go:38` — "better solution than pointer to server?" | None — API | — | Hygiene | P3 |
| B2 | `session.go:96` — "change closing behavior for sessions without cmd/shell → integrate port forwarding duration" | §7.1 "headless sessions persist until client manually terminated"; §7.3 "immediately invalidated after … timeout" | #188 (long-lived grants residue) | **NEW — zombie session persistence** | **P1** |
| B3 | `session.go:102` — "Check closing behavior. how to end session completely" | Same as B2 | #188 | **NEW — zombie session** | **P1** |
| B4 | `session.go:120` — "TODO Do Acme Stuff" | Acme grant type: undefined behavior | — | Partial (GrantType policy gap, V7) | P3 |
| B5 | `session.go:160` — "look closely at closing behavior" | §7.1 session lifetime | — | **NEW — zombie session / S1-d** | **P1** |
| B6 | `session.go:175` — "add check for authgrant?" (`handleAgc`) | spec: "hopd listens on unix socket for requests from descendant processes" — implies only authgrant-bearing sessions should issue AGTs | — | **NEW — V10 / unauthorized AGT access** | P2 |
| B7 | `session.go:245` — "These are minimal environment variables. SSH allows for more inheritance from client" | None — env hygiene | — | Hygiene | P3 |
| B8 | `session.go:332` — "find a way of selecting a remote forwarding or a local forwarding" | Req. 5 "specific action" | — | V11 / PF tube dispatch not grant-gated (already in F-series) | P3 |

### B2/B3/B5 detail — zombie session (the S1-d prediction)
Three separate TODO comments in the session lifecycle all acknowledge that session closing for headless (no-exec, no-shell) sessions is undefined. The critical chain is:
1. Grant expires (`ExpTime` passes) — no sweeper removes it from `agMap` (V4)
2. Delegate connects after expiry — drain succeeds (`AuthorizeKeyAuthGrant`, no expiry filter, V3) → session minted
3. Session has `authorizedActions` — `checkCmd` will fail (expiry enforced at action, V2) but `PFControlTube` and `PFTube` are accepted without any authorization check (V11)
4. The session will not close itself because session closing is triggered by `startCodex`'s goroutine signaling done (via `shell` path, `session.go:319`) or by `start()` detecting a muxer error. A headless session just waits.
5. **Predicted outcome:** an expired grant produces a zombie session with ungated PF capability that persists indefinitely.
This is the central finding of S1 and the most direct challenge to INV-B.

### B6 detail — unauthorized AuthGrantTube
`session.go:175`: `handleAgc` runs for any session that opens a `common.AuthGrantTube`, regardless of whether that session authenticated via authgrant or authorized_keys. A regular `authorized_keys` session can therefore trigger the authgrant protocol machinery (open an authgrant tube, have the server act as target-side of the grant protocol) without itself being an authgrant session. Consequence: the attack surface of the authgrant protocol extends to any authenticated session on the server.

---

## 3. `hopserver/agproxy.go`

| # | TODO (file:line) | Paper / spec claim | Issue # | Coverage | Priority |
|---|---|---|---|---|---|
| C1 | `agproxy.go:33` — "TODO others" (creds check on non-linux) | spec descent check | — | Platform compat; not a security gap on Linux | P3 |
| C2 | `agproxy.go:39` — "close down the proxy/associated resources neatly if either side fails" | None stated explicitly | — | Resource lifecycle / S5 characterization | P2 |
| C3 | `agproxy.go:243` — "give principal time to close hop sess with target" | None — race condition in close sequence | — | S5 / resource state | P2 |
| C4 | `agproxy.go:245,259` — "ask george if `WaitForClose` does what I want" | None — semantics question | — | Resource lifecycle | P3 |

### C2/C3 detail — proxy close-down races
When either the delegate→principal proxy or the principal→target proxy closes, the other side is torn down in `agProxy.serveAgpInstance` (`agproxy.go:238-263`). The TODO at :243 acknowledges a possible race: the principal session with the target may not be fully closed before the proxy's connection objects are released. This maps to S5's "approval stall" characterization — if the delegate connection dies mid-approval, what state is left on the target?

---

## 4. `hopserver/hopserver.go`

| # | TODO (file:line) | Paper / spec claim | Issue # | Coverage | Priority |
|---|---|---|---|---|---|
| D1 | `hopserver.go:54` — linting | — | — | Hygiene | P3 |
| D2 | `hopserver.go:57` — "Think about how NewHopServerExt and NewHopServer interact" | — | — | Hygiene | P3 |
| D3 | `hopserver.go:259` — "add logging context to server" | — | — | Hygiene | P3 |
| D4 | `hopserver.go:289,291` — session lock design; sessions remove themselves | — | — | Concurrency | P3 |
| D5 | `hopserver.go:309` — "should authgrants be disabled by default?" | §7.3 principle of least authority | — | **NEW — default-on attack surface** | P2 |
| D6 | `hopserver.go:375` — cert caching across Names blocks | — | — | Performance | P3 |
| D7 | `hopserver.go:418` — "only does raw string matching, needs to disambiguate name types" (`VirtualHosts.Match`) | §7.3 target binding; spec: "Target SNI in format of cert IDBlock" | — | V14 / **NEW — multi-vhost SNI routing for S2-L2** | **P1** |

### D5 detail — authgrants enabled by default?
`hopserver.go:309`: The TODO asks whether authgrants should be enabled by default. Currently they are disabled by default (`config.ServerConfig.EnableAuthgrants = false`). If a deployment enables authgrants without understanding the full implications (V3/V4/V8/V11 gaps), all five hypotheses apply simultaneously. This is a documentation / deployment hygiene issue, not a code vulnerability — but worth noting in the Phase-5 writeup.

### D7 detail — raw-glob vhost matching and SNI binding (S2-L2)
`hopserver.go:420-424` (`VirtualHosts.Match`): Uses `glob.Glob(pattern, name)` where `name` is the raw string from the transport handshake's `ServerName` label. No name-type check (`TypeDNSName` vs `TypeRaw` vs `TypeIPv4Address`). For the S2-L2 test (multi-vhost hopd, deliver intent naming vhost-A to vhost-B), this means a client that presents `TargetSNI = TypeRaw:"*"` could match any vhost if the glob pattern is `"*"`. Relates to INV-C binding but at the routing layer rather than the grant admission layer.

---

## 5. `hopserver/target.go`

| # | TODO (file:line) | Paper / spec claim | Issue # | Coverage | Priority |
|---|---|---|---|---|---|
| E1 | `target.go:20` — "removing expired still TODO" | §7.3 "immediately invalidated after … timeout" | #188 | V4 / **S1 direct** | **P1** |
| E2 | `target.go:46` — "check target SNI matches current hostname? necessary?" | §7.3 "bound to … Target" | — | V7-area / **S2 direct** | **P1** |
| E3 | `target.go:58-59` — "add finer grained policy checks/options", "enable fine grained checks based on config options" | Req. 5 "specific action" | — | V7 / policy vacuum | P2 |
| E4 | `target.go:63` — `Shell:` case body is `// TODO(baumanl)` | Req. 5 "specific action" / grant type semantics | — | V7 / **shell policy absent** | P2 |
| E5 | `target.go:65` — `Command:` case body is `// TODO` | Same | — | V7 | P2 |
| E6 | `target.go:67` — `LocalPF:` case body is `// TODO` | Same | — | V7 | P2 |
| E7 | `target.go:69` — `RemotePF:` case body is `// TODO` | Same | — | V7 | P2 |
| E8 | `target.go:76` — "rewrite this/think about best way to generalize to all grant types" | Req. 5 "specific action" | — | `checkCmd` generalization | P2 |

### E2 detail — the SNI TODO (most exploitable)
`target.go:46`: The comment reads "check target SNI matches the current hostname of this server? necessary?" This is the decisive enforcement point for INV-C: without this check, a grant minted for `web1.example.com` is accepted by `db1.example.com` if the same user/delegate keypair authenticates to both. The question mark in the comment suggests the author was uncertain whether this check was architecturally necessary (chain-of-authority argument: the principal already verified SNI during `setUpTargetConn`). That is the Phase-5 classification question for S2.

### E4-E7 detail — per-type policy vacuum
`checkIntent`'s switch statement has empty bodies for all four non-default grant types. No type-specific policy is enforced at admission: a `shell` grant and a `cmd` grant both pass through `checkIntent` identically (after the base format/expiry/username checks). The only type-aware logic is in `checkCmd` and the tube-dispatch in `session.go:117-140`. This means the admission gate is weaker than it appears — the target accepts any well-formatted grant regardless of type-specific semantics.

---

## 6. NEW-item prioritized list

| Rank | Item | Scenario | Why |
|------|------|----------|-----|
| 1 | E1 — expired grant sweeper absent | S1 | Directly confirmed by code comment; zombie session prediction contingent on this |
| 2 | B2/B3/B5 — zombie session persistence undefined | S1 | Same S1 chain; session will not self-terminate |
| 3 | E2 — SNI check absent (TODO) | S2 | Direct INV-C, cheapest L1 test (15-line test, existing harness) |
| 4 | D7 — raw-glob vhost matching | S2-L2 | Multi-vhost routing extension of S2 |
| 5 | B6 — unauthorized AuthGrantTube | S4 extension | Any session can initiate authgrant protocol machinery |
| 6 | A3 — cert.Name.Types in `ConnectToTarget` | S2 proxy path | Same SNI binding gap in the proxy routing layer |
| 7 | A4 — principal no-close path | S5 | Resource characterization of approval stall |
| 8 | C2/C3 — proxy close-down races | S5 | State reachability under stall |
| 9 | E3-E7 — per-type policy vacuum | S7 | Admission gate weaker than it appears |
| 10 | D5 — authgrants enabled by default? | S8 / writeup | Deployment hygiene |

---

## 7. Items already covered by prior work

The following TODOs map directly to previously filed vulnerabilities or candidates and do not need new Phase-3 scenarios:

| TODO | Prior coverage |
|------|----------------|
| `hopserver/session.go:332` (PF tube dispatch) | Vuln #4b (F-series), `design_oversights.md` Candidate 1 |
| `hopserver/agproxy.go:33` (non-linux creds) | F3-class PoC scope |
| `authgrants/principal.go:45-48` (`insecureAcceptAll`) | Issue #202, `triage_design_vs_devbug_nov_10.md` |
| Follow-up intent return discarded (`principal.go:115`) | Issue #201, V8 — S4 is the new test |
| `hopserver/session.go:120` (Acme TODO) | GrantType policy gap, low priority vs. shell/cmd/PF |
