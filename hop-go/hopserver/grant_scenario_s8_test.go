package hopserver

// S8 — Principal death (Phase 3, stretch scenario).
//
// Plan §7-S8:
//   "authgrant_spec.md explicitly allows the principal session to
//    terminate after issuance. Kill the principal harness-side after
//    confirmation; assert grant remains consumable (expected yes, by
//    design). Then characterize the vacuum: no revocation API exists
//    anywhere in authgrants/ — the only invalidation is consumption or
//    TTL, and per S1 even TTL is soft."
//
// This scenario adjudicates the degenerate "chain-of-authority
// termination" case: a chain of length one whose only link (the
// principal) dies. The paper's revocation model is derivable from the
// spec by elimination — nothing in authgrants/* removes a stored grant
// except RemoveAuthgrants (which is the consumption path, not revocation).
//
// Static facts exercised (plan §2):
//   V4 : no TTL sweeper on agMap
//   plus a structural fact proven below: AuthgrantMapSync's exported
//   method set is exactly {AddAuthGrant, RemoveAuthgrants}.
//
// Prediction: INV-B's residue plus structural absence. The grant lives on;
// the principal's corpse is irrelevant to it; no API path can take it back.
// This feeds Candidate 2 (chain-of-authority termination) with a
// one-paragraph walkthrough.

import (
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"gotest.tools/assert"

	"hop.computer/hop/authgrants"
	"hop.computer/hop/certs"
	"hop.computer/hop/core"
	"hop.computer/hop/keys"
	"hop.computer/hop/pkg/thunks"
)

// buildS8Intent constructs a cmd Intent for (user, pub) with a 1h TTL. We
// use an in-package builder (rather than the authgrants IntentBuilder,
// which lives in the authgrants test package and isn't importable here)
// so the test stays self-contained.
func buildS8Intent(user string, pub keys.DHPublicKey, cmd string) authgrants.Intent {
	return authgrants.Intent{
		GrantType:      authgrants.Command,
		TargetPort:     7777,
		StartTime:      thunks.TimeNow(),
		ExpTime:        thunks.TimeNow().Add(time.Hour),
		TargetSNI:      certs.RawStringName("target"),
		TargetUsername: user,
		DelegateCert:   l2TestCert(pub),
		AssociatedData: authgrants.GrantData{
			CommandGrantData: authgrants.CommandGrantData{Cmd: cmd},
		},
	}
}

// TestS8a_GrantSurvivesPrincipalDeath runs the full L1 issuance flow
// (delegate → principal → target), routing the target-side adder into
// the REAL HopServer (so the grant lands in a real agMap + keyStore).
// After GrantAdded fires, we kill every principal-side connection:
//
//   - delegate pipe  : closed (delegate process gone)
//   - principal pipe : closed (principal process gone)
//
// We then assert the grant is STILL in agMap and drainable by any party
// that holds the delegate key. "Principal death" is a no-op on the
// target's state machine — the target is deliberately decoupled.
func TestS8a_GrantSurvivesPrincipalDeath(t *testing.T) {
	defer resetClock()
	setClock(time.Now())

	srv := newTestServer(t)
	const user = "alice"
	const cmd = "echo survives"
	pub := l2TestPubKey()

	intent := buildS8Intent(user, pub, cmd)

	// Wire the L1 flow. prinConn / prinTarget are the target-principal
	// pipe; delConn / delDelegate are the delegate-principal pipe.
	delConn, delDelegate := net.Pipe()
	prinConn, prinTarget := net.Pipe()

	approveAll := func(i authgrants.Intent, cert *certs.Certificate) error { return nil }
	targetAdmitter := func(i authgrants.Intent, cert *certs.Certificate) error { return nil }

	// Route the target-side adder to the REAL production code path:
	// srv.AddAuthGrant → agMap.AddAuthGrant + keyStore.AddKey. This is
	// what makes the grant consumable at L2 afterward.
	adder := srv.AddAuthGrant

	setupTarg := func(u core.URL, vc authgrants.AdditionalVerifyCallback) (net.Conn, error) {
		if vc != nil {
			if err := vc(nil); err != nil {
				return nil, err
			}
		}
		return prinConn, nil
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		authgrants.StartTargetInstance(prinTarget, nil, targetAdmitter, adder)
	}()

	go func() {
		defer wg.Done()
		authgrants.StartPrincipalInstance(delConn, approveAll, setupTarg)
		prinConn.Close()
	}()

	err := authgrants.StartDelegateInstance(delDelegate, []authgrants.Intent{intent})
	assert.NilError(t, err, "delegate flow: at least one intent confirmed")
	delDelegate.Close()
	wg.Wait()

	// ---- Grant is now in agMap. Simulate principal-side DEATH. ----
	//
	// Both pipes are already closed; the principal instance has exited
	// (its run loop broke on the delegateConn EOF). Nothing in hopd
	// tracks a "principal is alive" liveness signal — there is no
	// such signal. The grant lives on in agMap by default.
	//
	// Explicit sanity: the stored Authgrant's PrincipalID is NoSession
	// (hopserver.go:329 — AddAuthGrant hard-codes this sentinel). So
	// even in principle, there is no principal-session ID to use as a
	// revocation key: the target forgets the principal at issuance.

	// Advance the clock by an arbitrary delay: the grant must still be
	// drainable, because the only expiry gate is checkCmd (V2) and the
	// grant is still inside its TTL.
	advanceClock(30 * time.Minute)

	acts, err := srv.AuthorizeKeyAuthGrant(user, pub)
	assert.NilError(t, err,
		"⚠ S8: grant survives principal death — no API path invalidates "+
			"a stored grant on principal-session termination; the target has "+
			"no 'principal alive' signal and ignores it even if it did")
	assert.Equal(t, 1, len(acts))
	assert.Equal(t, cmd, acts[0].AssociatedData.CommandGrantData.Cmd)
	assert.Equal(t, authgrants.PrincipalID(NoSession), acts[0].PrincipalID,
		"grant has no principal-session identity to revoke by — "+
			"hopserver.go:329 stamps NoSession deliberately (S6-related)")

	// Consumption completes end-to-end, long after the principal is gone.
	sess := &hopSession{
		server:            srv,
		user:              user,
		usingAuthGrant:    true,
		authorizedActions: acts,
	}
	_, err = sess.checkCmd(cmd, false)
	assert.NilError(t, err, "cmd executes 30m post-principal-death")
}

// TestS8b_NoRevocationAPI characterizes the "vacuum" leg of S8: enumerate
// AuthgrantMapSync's exported methods and assert the API surface permits
// only Add + consumption-drain. No revoke, no sweep, no
// PrincipalID-based remove, no DelegateCert-based remove.
//
// This test is the reason the finding is a Candidate-2 artifact rather
// than a bug: the absence is not a missed branch, it is a
// system-wide API choice.
func TestS8b_NoRevocationAPI(t *testing.T) {
	mapType := reflect.TypeOf(&authgrants.AuthgrantMapSync{})
	expected := map[string]bool{
		"AddAuthGrant":     true,
		"RemoveAuthgrants": true,
	}

	actual := make(map[string]bool, mapType.NumMethod())
	for i := 0; i < mapType.NumMethod(); i++ {
		m := mapType.Method(i)
		actual[m.Name] = true
	}

	// Exact set equality: any future addition of a revocation-like method
	// will update the expected set here and we will revisit the finding.
	assert.Equal(t, len(expected), len(actual),
		"AuthgrantMapSync method count must be stable — got %v", actual)
	for name := range expected {
		assert.Assert(t, actual[name],
			"expected method %q absent — API surface changed, revisit S8", name)
	}
	for name := range actual {
		assert.Assert(t, expected[name],
			"⚠ S8 vacuum: UNEXPECTED method %q on AuthgrantMapSync — "+
				"the canonical API surface was {Add, RemoveAuthgrants}; this test "+
				"was the sentinel for a new revocation primitive, re-triage S8", name)
	}
}

// TestS8c_RemoveAuthgrantsIsConsumption asserts the semantic claim that
// the ONLY exported removal API is the consumption path: RemoveAuthgrants
// requires the delegate's public key and returns the grants (by draining
// them). It cannot be used as a revocation primitive because:
//   (1) it requires the DelegateCert.PublicKey — a revoking principal
//       might not hold that (delegate chose it); in practice hopd never
//       calls RemoveAuthgrants except during AuthorizeKeyAuthGrant.
//   (2) it is "remove ALL grants for (user, key)" — there is no way to
//       revoke a single grant without draining all sibling grants for
//       that delegate.
//   (3) it has no principal-session parameter; the caller has no way to
//       assert "I was the issuing principal."
//
// We exercise (2) directly.
func TestS8c_RemoveAuthgrantsIsAllOrNothing(t *testing.T) {
	defer resetClock()
	setClock(time.Now())

	srv := newTestServer(t)
	const user = "alice"
	pub := l2TestPubKey()
	expTime := thunks.TimeNow().Add(time.Hour)

	// Plant THREE grants under the same (user, pub). A revocation API
	// would need to let a principal revoke exactly ONE of these without
	// touching the other two. The code offers no such primitive.
	addTestGrant(srv, user, pub, "cmd-A", expTime)
	addTestGrant(srv, user, pub, "cmd-B", expTime)
	addTestGrant(srv, user, pub, "cmd-C", expTime)

	// Calling RemoveAuthgrants (the only removal primitive) drains all
	// three at once. We also lose the keyStore entry — "revoking" cmd-B
	// in this model also revokes cmd-A, cmd-C, AND the transport-level
	// delegate-key trust.
	acts, err := srv.AuthorizeKeyAuthGrant(user, pub)
	assert.NilError(t, err)
	assert.Equal(t, 3, len(acts),
		"⚠ S8: 'revoking' one grant requires draining the entire (user, pub) "+
			"bucket — the API exposes no per-grant removal semantics; it is "+
			"shaped around consumption, not revocation")

	// Post-drain: the delegate's pubkey is also gone from keyStore
	// (hopserver/target.go:31). A principal wishing to revoke only grant
	// B would have to re-add the key afterward and re-plant A + C — a
	// racy, out-of-band workflow with no concurrency guarantees.
	leaf := l2TestCert(pub)
	assert.ErrorContains(t, srv.keyStore.VerifyLeaf(&leaf, certs.VerifyOptions{}),
		"not found",
		"⚠ S8: the consumption-removal primitive ALSO invalidates transport "+
			"trust for the delegate key — a revocation operation implemented via "+
			"RemoveAuthgrants would race against concurrent delegate connects")
}
