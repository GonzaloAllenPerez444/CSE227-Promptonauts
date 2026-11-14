package hopserver

// S6 — Grant theft / bearer semantics (Phase 3).
//
// Hypothesis H3 (grant_lifecycle_investigation_plan.md §1):
//   "The grant's 'Delegate' identity is the ephemeral cert the delegate
//   itself generated; possession of that keypair (plus the intent, which
//   the compromised delegate saw in plaintext) is sufficient to consume
//   the grant from any host. §3 explicitly grants the adversary
//   'previously issued intent-grant credentials' — so the paper's §7.3
//   'bound to a specific … Delegate' is, as deployed,
//   binding-to-a-bearer-key."
//
// Invariant under test: INV-D — §7.3 "bound to a specific … Delegate."
// Operationalized: consuming the grant requires more than possession of a
// copy of the grant material + the delegate ephemeral keypair.
//
// Prediction: INV-D collapses to bearer semantics. The target-side state
// (agMap, keyStore) is indexed solely by (user, publicKey); the drain API
// takes no caller-identity parameter; the stored Authgrant's PrincipalID
// field is the sentinel `NoSession` (hopserver/session.go:29) for grants
// issued through the normal path — so the target has deliberately
// forgotten which principal session issued it. Anyone who holds the key
// can drain.
//
// This is the candidate for the strongest DESIGN-LEVEL finding of the
// Phase-3 batch — see plan §7-S6 and §9's predicted splits. The
// cryptographic analysis of what "Delegate binding" can mean in Hop lives
// in `possible_attacks/grant_scenario_s6_findings.md` §4.

import (
	"testing"
	"time"

	"gotest.tools/assert"

	"hop.computer/hop/authgrants"
	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
	"hop.computer/hop/pkg/thunks"
)

// plantGrantAsProd mirrors hopserver.go:328-332 exactly, using the
// production sentinel `NoSession` for PrincipalID. S6's finding is
// sensitive to that value, so we use it here rather than relying on the
// harness's addTestGrant (which uses PrincipalID(0) for simplicity).
func plantGrantAsProd(srv *HopServer, user string, pub keys.DHPublicKey, cmd string) authgrants.Intent {
	intent := authgrants.Intent{
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
	// Production path: hopserver.go:329 stamps NoSession as the PrincipalID,
	// deliberately dropping the principal-session binding.
	srv.agMap.AddAuthGrant(&intent, authgrants.PrincipalID(NoSession))
	// Production path: hopserver.go:332 adds the delegate-chosen pubkey to
	// the transport trust pool.
	srv.keyStore.AddKey(pub)
	return intent
}

// TestS6_BearerConsumptionByAttackerBeforeDelegate: the §3 adversary — in
// possession of the (intent + ephemeral keypair) pair — can race the
// legitimate delegate and win. From the target's perspective the two
// consumers are indistinguishable.
//
// Timeline:
//   T0 : legitimate flow completes; target has stored grant + added pub to
//        keyStore. Adversary has snapshotted (intent, pub, priv).
//   T1 : adversary consumes first (AuthorizeKeyAuthGrant). SUCCESS.
//        Adversary now holds authorizedActions; checkCmd will fire.
//   T2 : legitimate delegate attempts to consume. FAILS — grant is gone.
//
// No code path at the target can distinguish the two parties: both present
// the same (user, pubkey) tuple; both would pass VerifyLeaf against the
// same keyStore entry; the drained Authgrant records no caller identity.
func TestS6_BearerConsumptionByAttackerBeforeDelegate(t *testing.T) {
	defer resetClock()
	setClock(time.Now())

	srv := newTestServer(t)
	const user = "testuser"
	const cmd = "cat /etc/passwd"
	pub := l2TestPubKey()

	intent := plantGrantAsProd(srv, user, pub, cmd)

	// Sanity: keyStore trusts the delegate key — both parties will pass
	// transport auth. VerifyLeaf is the only identity check at the
	// transport layer.
	leaf := intent.DelegateCert
	assert.NilError(t, srv.keyStore.VerifyLeaf(&leaf, certs.VerifyOptions{}),
		"V5: pubkey must be trusted before drain")

	// ---- T1: ATTACKER drains first. ----
	// Simulated by calling AuthorizeKeyAuthGrant from a code path with no
	// relationship to the issuance flow. The API itself takes no caller
	// identity; whichever caller gets here first wins.
	attackerActions, err := srv.AuthorizeKeyAuthGrant(user, pub)
	assert.NilError(t, err,
		"⚠ INV-D: attacker with only (user, pub) drained the grant — "+
			"AuthorizeKeyAuthGrant has no caller-identity parameter")
	assert.Equal(t, 1, len(attackerActions))
	assert.Equal(t, cmd, attackerActions[0].AssociatedData.CommandGrantData.Cmd)

	// The stored Authgrant's PrincipalID is NoSession — the target has
	// deliberately forgotten which principal session issued the grant. This
	// is the cryptographic root of bearer semantics: there is nothing in
	// the Authgrant struct that references the delegate's identity beyond
	// the DelegateCert, whose keypair the delegate itself chose.
	assert.Equal(t, authgrants.PrincipalID(NoSession), attackerActions[0].PrincipalID,
		"⚠ INV-D: grant stores no principal-session identity "+
			"(hopserver.go:329 uses NoSession as the sentinel)")

	// ---- T2: LEGITIMATE delegate tries to drain. Loses the race. ----
	_, err = srv.AuthorizeKeyAuthGrant(user, pub)
	assert.ErrorContains(t, err, "no authgrant",
		"legitimate delegate is now denied — attacker already consumed the grant; "+
			"the target cannot distinguish a repeat attempt by the attacker from "+
			"the legitimate delegate's first attempt")

	// ---- Attacker exercises checkCmd via a fully-synthetic session. ----
	// This hopSession has no transport state, no provenance, nothing linking
	// it to the original delegate. checkCmd nonetheless admits the action.
	attackerSess := &hopSession{
		server:            srv,
		user:              user,
		usingAuthGrant:    true,
		authorizedActions: attackerActions,
	}
	_, err = attackerSess.checkCmd(cmd, false)
	assert.NilError(t, err,
		"⚠ INV-D: attacker's synthesized session executed the authorized command "+
			"via checkCmd; no target-side check differentiates it from the delegate")
}

// TestS6_CertChainNotVerifiedOnConsumption: the paper's §7.3 names
// DelegateCert as part of the binding, but the target-side code only
// format-checks the leaf (hopserver/target.go:55 →
// certs.VerifyLeafFormat). No CA chain verification, no issuer check, no
// signature validation. If the attacker swaps the DelegateCert's metadata
// (e.g., different ID block / Name) while keeping the public key, the
// grant still drains — because the index is the key, not the cert.
//
// This test documents the scope of the bearer semantics: the "certificate"
// in DelegateCert is not a verifiable identity assertion at the target —
// it is a container for the public key.
func TestS6_CertChainNotVerifiedOnConsumption(t *testing.T) {
	defer resetClock()
	setClock(time.Now())

	srv := newTestServer(t)
	const user = "testuser"
	const cmd = "echo bearer"
	pub := l2TestPubKey()

	_ = plantGrantAsProd(srv, user, pub, cmd)

	// VerifyLeaf is the transport's identity gate; its implementation
	// (authkeys/verify.go:42-54) is: `VerifyLeafFormat(leaf, opts)` then
	// keyset membership. Build a leaf that shares the public key but uses
	// completely different ID blocks. VerifyLeaf should still accept.
	impersonatorLeaf := l2TestCert(pub)
	impersonatorLeaf.IDChunk = certs.IDChunk{
		Blocks: []certs.Name{{
			Type:  certs.TypeDNSName,
			Label: []byte("attacker.example"),
		}},
	}
	assert.NilError(t, srv.keyStore.VerifyLeaf(&impersonatorLeaf, certs.VerifyOptions{}),
		"⚠ INV-D: a leaf cert with ATTACKER-CHOSEN name fields but the same "+
			"pubkey passes VerifyLeaf — the identity gate is the pubkey only; "+
			"the cert's identity claim is advisory")

	// And the grant still drains under that pubkey.
	acts, err := srv.AuthorizeKeyAuthGrant(user, pub)
	assert.NilError(t, err)
	assert.Equal(t, 1, len(acts))
}

// TestS6_AgMapIndexIsKeyNotIdentity documents the structural root of
// bearer semantics: AuthgrantMapSync keys on (TargetUsername, PublicKey).
// We assert this by inserting two grants under the same (user, pub) and
// observing that a single drain returns BOTH — the DelegateCert blocks or
// any other identity material do not partition the entries.
func TestS6_AgMapIndexIsKeyNotIdentity(t *testing.T) {
	defer resetClock()
	setClock(time.Now())

	srv := newTestServer(t)
	const user = "testuser"
	pub := l2TestPubKey()

	// Two grants, same (user, pub), cosmetically-different DelegateCert
	// metadata (different ID blocks).
	g1 := authgrants.Intent{
		GrantType:      authgrants.Command,
		TargetUsername: user,
		StartTime:      thunks.TimeNow(),
		ExpTime:        thunks.TimeNow().Add(time.Hour),
		TargetPort:     7777,
		TargetSNI:      certs.RawStringName("target"),
		DelegateCert:   l2TestCert(pub),
		AssociatedData: authgrants.GrantData{
			CommandGrantData: authgrants.CommandGrantData{Cmd: "cmd-A"},
		},
	}
	g2 := g1
	g2.AssociatedData = authgrants.GrantData{
		CommandGrantData: authgrants.CommandGrantData{Cmd: "cmd-B"},
	}
	g2.DelegateCert = l2TestCert(pub)
	g2.DelegateCert.IDChunk = certs.IDChunk{
		Blocks: []certs.Name{{
			Type:  certs.TypeDNSName,
			Label: []byte("second.delegate"),
		}},
	}

	srv.agMap.AddAuthGrant(&g1, authgrants.PrincipalID(NoSession))
	srv.agMap.AddAuthGrant(&g2, authgrants.PrincipalID(NoSession))
	srv.keyStore.AddKey(pub)

	acts, err := srv.AuthorizeKeyAuthGrant(user, pub)
	assert.NilError(t, err)
	assert.Equal(t, 2, len(acts),
		"⚠ INV-D: one drain returned both grants — agMap keys on "+
			"(user, pub) only; DelegateCert identity material is NOT part of the key "+
			"(authgrants/authgrants.go:41-50)")

	// Both cmds are reachable from the drained session.
	sess := &hopSession{
		server:            srv,
		user:              user,
		usingAuthGrant:    true,
		authorizedActions: acts,
	}
	_, err = sess.checkCmd("cmd-A", false)
	assert.NilError(t, err, "cmd-A reachable")
	_, err = sess.checkCmd("cmd-B", false)
	assert.NilError(t, err, "cmd-B reachable")
}
