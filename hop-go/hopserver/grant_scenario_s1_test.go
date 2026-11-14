package hopserver

// S1 — Expire-before-connect (Phase 3, scenario S1).
//
// Hypothesis H1 (grant_lifecycle_investigation_plan.md §1):
//   "An expired, unconsumed grant still passes transport auth (key added at
//   grant time), mints a delegate session (AuthorizeKeyAuthGrant has no
//   expiry filter), and — because only ExecTube is grant-gated — yields a
//   zombie headless session with ungated PF capability on the target."
//
// Invariant under test: INV-B — "immediately invalidated after use or
// timeout". Operationalized: after ExpTime, NO capability derived from the
// grant is exercisable.
//
// Static facts exercised (verified §2 of the plan):
//   V2 : checkCmd uses the stubbable clock (target.go:81)
//   V3 : AuthorizeKeyAuthGrant drains without an expiry filter (target.go:26-35)
//   V4 : no TTL sweeper on agMap (authgrants.go — only Add/Remove)
//   V5 : delegate key added to keyStore at grant-add time (hopserver.go:332),
//        removed only on successful drain (target.go:31)
//  V11 : only ExecTube is grant-gated; PFControlTube/PFTube/AuthGrantTube
//        branches in session.go:start() have no action-expiry check
//        (session.go:130-135)
//
// Prediction: INV-B is falsified in the following STRONG form — a grant's
// expiry kills ONLY checkCmd (V2); all other capabilities derived from the
// grant survive the TTL boundary.

import (
	"testing"
	"time"

	"gotest.tools/assert"

	"hop.computer/hop/authgrants"
	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
	"hop.computer/hop/pkg/thunks"
)

// TestS1_ExpireBeforeConnect walks the grant from issuance through
// post-expiry drain and checkCmd, asserting which capabilities survive the
// TTL boundary.
//
// Timeline (fake clock):
//   T0           : grant minted, ExpTime = T0 + 1s
//   T0 + 2s      : clock advanced past expiry
//   T0 + 2s      : (a) keyStore still trusts the delegate key
//   T0 + 2s      : (b) AuthorizeKeyAuthGrant succeeds, returns the expired grant
//   T0 + 2s      : (c) checkCmd denies (V2 enforces per-action expiry)
//   T0 + 2s      : (d) session.authorizedActions is NON-EMPTY after denial —
//                      the expired Authgrant lingers; zombie state reached.
func TestS1_ExpireBeforeConnect(t *testing.T) {
	defer resetClock()
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	setClock(t0)

	srv := newTestServer(t)

	const user = "testuser"
	const cmd = "date"
	pub := l2TestPubKey()
	expTime := t0.Add(time.Second) // TTL = 1s

	intent := addTestGrant(srv, user, pub, cmd, expTime)

	// ---- (a) Pre-expiry: key is in the transport trust pool. ----
	leaf := intent.DelegateCert
	assert.NilError(t, srv.keyStore.VerifyLeaf(&leaf, certs.VerifyOptions{}),
		"V5: delegate key must be in keyStore after AddAuthGrant")

	// Advance fake clock past ExpTime.
	advanceClock(2 * time.Second)
	assert.Check(t, thunks.TimeNow().After(expTime),
		"sanity: fake clock is past grant ExpTime")

	// ---- (a') Post-expiry, pre-drain: key STILL in the transport trust pool. ----
	// V5 is now observable as a bug: expiry does not remove the key.
	assert.NilError(t, srv.keyStore.VerifyLeaf(&leaf, certs.VerifyOptions{}),
		"V5 violation: delegate key still trusted by keyStore AFTER expiry "+
			"(no sweeper, no expiry-driven RemoveKey) — transport auth would succeed")

	// ---- (b) Session mints: AuthorizeKeyAuthGrant has no expiry filter (V3). ----
	grants, err := srv.AuthorizeKeyAuthGrant(user, pub)
	assert.NilError(t, err,
		"V3 violation: AuthorizeKeyAuthGrant drained an EXPIRED grant without filtering")
	assert.Equal(t, 1, len(grants), "expected one grant drained")
	assert.Equal(t, authgrants.Command, grants[0].GrantType)
	assert.Equal(t, cmd, grants[0].AssociatedData.CommandGrantData.Cmd)
	// Ensure what we got back really IS expired — not a clock mistake.
	assert.Check(t, thunks.TimeNow().After(grants[0].ExpTime),
		"drained grant must be past its ExpTime; otherwise this test is vacuous")

	// Post-drain: key IS removed by the drain path (hopserver/target.go:31).
	// The removal is tied to CONSUMPTION, not to expiry. Verify by VerifyLeaf
	// now returning an error.
	assert.ErrorContains(t, srv.keyStore.VerifyLeaf(&leaf, certs.VerifyOptions{}),
		"not found",
		"drain should remove delegate key from keyStore")

	// ---- (c) checkCmd enforces per-action expiry (V2). ----
	sess := &hopSession{
		server:            srv,
		user:              user,
		usingAuthGrant:    true,
		authorizedActions: grants,
	}
	_, err = sess.checkCmd(cmd, false)
	assert.ErrorContains(t, err, "no auth grant",
		"V2: checkCmd must reject an expired cmd grant")

	// ---- (d) ZOMBIE SESSION: authorizedActions remains populated. ----
	//
	// The checkCmd code path (target.go:79-96) only deletes from the slice on
	// SUCCESS. After a denial the expired Authgrant remains in the slice. The
	// session is alive, and its only non-Exec tube handlers
	// (PFControlTube/PFTube/AuthGrantTube/WinSizeTube cases at
	// session.go:130-137) do not inspect authorizedActions at all — so the
	// expired grant's mere existence is not the gate; the gate is absent.
	//
	// We assert the lingering slice as the directly-observable zombie
	// footprint. The PF non-gating itself is a code-structure fact anchored
	// in the plan's V11 (not re-asserted here to avoid instrumenting prod
	// code — see plan §11 "prefer asserting via public behavior").
	assert.Equal(t, 1, len(sess.authorizedActions),
		"ZOMBIE: expired Authgrant lingers in authorizedActions after denial — "+
			"session has not been invalidated by TTL (INV-B violated in strong form); "+
			"session.go:130-135 accepts PF/AuthGrant tubes with no action-check")
}

// TestS1_StaleGrantLeakAgMap confirms V4 (no TTL sweeper) by planting
// multiple expired grants and asserting that none are removed by clock
// advance. agMap grows monotonically; only consumption (or process restart)
// can shrink it.
//
// Operationalization of INV-B's leak dimension: an unconsumed expired grant
// leaves STALE state in agMap indefinitely.
func TestS1_StaleGrantLeakAgMap(t *testing.T) {
	defer resetClock()
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	setClock(t0)

	srv := newTestServer(t)

	const user = "testuser"
	const n = 5
	pubs := make([]keys.DHPublicKey, 0, n)

	// Plant n grants, each under a distinct delegate key, each with TTL=1s.
	for i := 0; i < n; i++ {
		pub := l2TestPubKey()
		pubs = append(pubs, pub)
		addTestGrant(srv, user, pub, "echo stale", t0.Add(time.Second))
	}

	// Advance an hour — well past every ExpTime.
	advanceClock(time.Hour)

	// No sweeper fires. Each grant must still be drainable (its mere
	// drainability demonstrates it is still in agMap).
	for i, pub := range pubs {
		grants, err := srv.AuthorizeKeyAuthGrant(user, pub)
		assert.NilError(t, err,
			"V4 violation (grant %d): expired grant still present in agMap an hour after expiry", i)
		assert.Equal(t, 1, len(grants))
		assert.Check(t, thunks.TimeNow().After(grants[0].ExpTime),
			"grant %d: should be expired", i)
	}
}
