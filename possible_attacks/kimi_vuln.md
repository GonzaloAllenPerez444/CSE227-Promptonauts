I completed a manual security review of hop-go (no Go toolchain was available in this environment for `gosec`/`go vet`, so this is a targeted code review of the transport, handshake, certificate, and authorization layers). Here are the findings, ordered by severity.

## Critical

### 1. Pre-authentication remote DoS: short transport packet panics the server

`transport/server.go:479` (`handleSessionMessage`) and `transport/client.go:482` (`Client.handleSessionMessage`):

```go
plaintext := make([]byte, PlaintextLen(len(msg)))
```

`PlaintextLen(n) = n - HeaderLen(4) - SessionIDLen(4) - CounterLen(8) - TagLen(32)`, i.e. any transport/control packet under 48 bytes yields a **negative length**, and `make([]byte, negative)` panics. The read path (`readPacketLocked`, transport/transport.go:150) has the same flaw via `enc := b[:ciphertextLen]` with a negative `ciphertextLen`.

Impact: a single UDP packet of 8–47 bytes starting with `MessageTypeTransport`/`MessageTypeControl` and carrying **any valid 4-byte session ID** crashes the whole server process (killing every session, since the server is one process). This happens *before* any AEAD verification, so it's effectively unauthenticated: session IDs are transmitted in plaintext in every packet, and with enough concurrent sessions a 32-bit guess succeeds quickly. The client has the same bug (its `listen()` loop accepts packets from any source address for roaming).

Fix: validate `len(msg) >= HeaderLen+SessionIDLen+CounterLen+TagLen` (and `PlaintextLen >= 0`) before allocating; never slice with computed lengths that haven't been range-checked; consider isolating per-session packet handling so a malformed packet can't take down the process.

## High

### 2. ServerAuth final MAC verified but never enforced (both handshakes)

`transport/handshake.go:406-410` and `transport/handshake_pq.go:466-470`:

```go
hs.duplex.Squeeze(hs.macBuf[:])
if !bytes.Equal(hs.macBuf[:], b[:MacLen]) {
    logrus.Debugf("client: expected sa mac %x, got %x", ...)   // no return!
}
```

In the Noise-XX-style flow, this trailing MAC is the **only proof that the server possesses the private key matching the leaf certificate it presented** (it authenticates the `es` DH output mixed into the key schedule). On mismatch the client only logs and proceeds to derive session keys. A network attacker who replays a victim's certificate (certificates are public) but doesn't know the private key can then complete ServerAuth — the client accepts an unauthenticated peer, whereas the hidden-mode response path (`readPQServerResponseHidden`, handshake_pq.go:1090) *does* enforce the equivalent MAC. This is an inconsistency that strongly suggests a bug rather than a design choice (CWE-347 class).

Fix: return `ErrInvalidMessage` on mismatch, in both `readServerAuth` and `readPQServerAuth`.

## Medium

### 3. Fail-open authorized_keys parsing → authorization bypass

`hopserver/hopserver.go:350-353` (`AuthorizeKey`):

```go
akeys, err := core.ParseAuthorizedKeys(f)
if err != nil {
    return nil        // parse error → treated as AUTHORIZED
}
```

`core.ParseAuthorizedKeys` (core/authorized_keys.go:19) returns an error if **any** non-empty line fails `ParseDHPublicKey`. So a single malformed line in a user's `~/.hop/authorized_keys` makes `AuthorizeKey` return success for **any** presented client key — a complete authorization bypass for that user (OpenSSH fails closed here). The `bufio.Scanner` error is also never checked, which can silently truncate the key list.

Fix: fail closed (return the parse error), and check `s.Err()` after the scan loop.

### 4. Handshake flooding resource exhaustion

Every `ClientHello` triggers an ML-KEM-512 keygen + encapsulation (`handlePQClientHello`), and every `ClientAck` with a valid cookie creates a `SessionState` plus a `time.AfterFunc` timer that lives until `HandshakeTimeout` (default 15s) — with no cap or rate limiting on the `handshakes`/`sessions` maps (`transport/server.go`). UDP source spoofing lets an attacker pin CPU (KEM ops) and grow memory/timers with fresh `(IP, port)` pairs. Also, cookie-key rotation every 2 minutes (server.go:544-556) invalidates in-flight handshakes, a minor availability wart.

Fix: rate-limit ClientHello per source, cache/pool KEM operations where possible, and bound the number of tracked handshakes.

### 5. Duplicate ClientAck breaks handshakes (ignored return value)

`transport/server.go:196` and `:249` ignore the boolean from `setHandshakeState`. On a retransmitted ClientAck (routine on lossy UDP paths), the existing entry is kept, but the server still sends a ServerAuth built from the *new* HandshakeState whose `sessionID` was never populated (all zeros). The client then sends ClientAuth with session ID 0, which mismatches the stored session → handshake failure. A deliberate duplicate can also be injected by any on-path observer holding a valid cookie.

Fix: honor the return value — if state already exists, either re-send the original ServerAuth or drop the packet.

### 6. `Name.String()` panics on unknown IDType (debug-log DoS)

`certs/certificate.go:143` — `panic()` inside `String()`. A client that completes ClientHello+ServerHello (anyone can) can put an out-of-range `IDType` byte in the encrypted SNI of ClientAck; when the server later formats the name (`logrus.Debugf("server: got name %v", name)` in handshake paths), the process panics. Only reachable with debug logging enabled, but `String()` should never panic — format unknown types as hex.

### 7. Unbounded allocation and ignored I/O errors in exec channel

`codex/exec.go:303` (`GetCmd`): `buf := make([]byte, binary.BigEndian.Uint32(l))` — a 32-bit, client-controlled length up to 4 GiB-1, with every `io.ReadFull` error ignored. An authorized-but-unprivileged client can force large allocations (memory pressure) and the server acts on partially-initialized length fields if the tube closes mid-message. Similarly, `userauth.GetInitMsg` ignores `ReadFull` errors. Fix: cap lengths (e.g. 64 KiB) and propagate read errors.

### 8. Port forwarding has no target restrictions

`portforwarding/portforwarding.go` — an authorized session can make the server `net.Dial` **any** TCP/UDP/Unix address (`PfLocal`, line 142 — including `127.0.0.1` services, metadata endpoints, or `/var/run/docker.sock` subject to filesystem perms) and make it **listen** on any address including `0.0.0.0` (`PfRemote`, line 158). There is no `PermitOpen`-style allowlist. This matches OpenSSH's defaults, but for a research protocol aimed at enterprise deployments it deserves explicit policy controls.

## Lower-severity / hardening notes

- **Sensitive material in debug logs**: session keys, DH shared secrets, cookies and MACs are logged at debug level throughout the handshake (e.g. `deriveFinalKeys`, `writeCookie`, all `logrus.Debugf("... %x", secret)` calls). A logging misconfiguration discloses long-term-capable key material. Redact these.
- **SNI silent truncation** (`transport/handshake.go:287-288`): names serializing to > 256 bytes are silently truncated by `copy` into the fixed SNILen buffer instead of erroring.
- **Certificate `Version` never validated** in `Certificate.ReadFrom` (certs/certificate.go:234) — parsed but unchecked, enabling cross-version confusion if a CA ever signs multiple versions.
- **`IDChunk.ReadFrom`** (certs/certificate.go:434) allows individual blocks to extend past the declared chunk length (loop only checks `blockBytesRead < blockLen` before each block) — a parser-differential risk between implementations.
- **Hidden-mode vhost oracle**: the per-certificate trial-decapsulation loop (handshake_pq.go:806-866) creates a timing signal revealing which certificate/vhost matched; acceptable given it's the design, but worth documenting.
- Dead code / sloppy checks that obscure review: duplicated `if err != nil` in `handshake.go:120` and `server.go:840`; the `writeVector` 16-bit "modulo" length issue is known to the authors (duplex.go:100) but unenforced — oversized certs fail closed today, but assert it.

## What looked solid

- X25519 DH uses `curve25519.X25519`, which rejects low-order points; ML-KEM decapsulation uses implicit rejection.
- Cert chain verification (`certs/verify.go`) is fail-closed: type/parent/fingerprint/time checks all enforced, signatures re-verified over raw bytes.
- Transport AEAD binds header+sessionID+counter as associated data with an implicit nonce, and the RFC 6479 sliding window marks sequence numbers only after successful decryption.
- The agproxy unix socket verifies peers via `SO_PEERCRED` and descendant checks rather than socket permissions alone.
- The hidden-mode timestamp anti-replay check is enforced before the final MAC.

The two items worth fixing before any real deployment are **#1** (one UDP packet kills the server) and **#2** (the server's cryptographic proof of possession is never checked); **#3** is a one-line fail-open with serious consequences.