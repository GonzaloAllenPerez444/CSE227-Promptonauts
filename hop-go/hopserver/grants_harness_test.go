package hopserver

// L2 (session-level) grant lifecycle harness.
//
// Exercises the HopServer API path: grant storage → AuthorizeKeyAuthGrant
// drain → session with authorizedActions → checkCmd dispatch.
//
// Clock control via thunks.TimeNow lets Phase-3 scenarios advance time
// deterministically (e.g. S1 expire-before-connect).
//
// Phase 0 exit criterion (§4.3): TestGoldenPathL2 verifies that a grant
// added to agMap is drained by AuthorizeKeyAuthGrant, consumed by checkCmd
// exactly once, and rejected on the second attempt.

import (
	"crypto/rand"
	"testing"
	"time"

	"gotest.tools/assert"

	"hop.computer/hop/authgrants"
	"hop.computer/hop/authkeys"
	"hop.computer/hop/certs"
	"hop.computer/hop/config"
	"hop.computer/hop/keys"
	"hop.computer/hop/pkg/thunks"
)

// setClock overrides thunks.TimeNow to always return t.
func setClock(t time.Time) {
	thunks.TimeNow = func() time.Time { return t }
}

// advanceClock moves the fake clock forward by d from its current value.
func advanceClock(d time.Duration) {
	cur := thunks.TimeNow()
	thunks.TimeNow = func() time.Time { return cur.Add(d) }
}

// resetClock restores thunks.TimeNow to real wall-clock time.
func resetClock() {
	thunks.TimeNow = time.Now
}

// newTestServer returns a minimal HopServer with authgrants enabled.
// The transport.Server field is nil; callers must not invoke transport-layer
// methods on the returned server.
func newTestServer(t *testing.T) *HopServer {
	t.Helper()
	ks := authkeys.NewSyncAuthKeySet()
	srv, err := NewHopServerExt(nil, &config.ServerConfig{
		EnableAuthgrants: true,
	}, ks)
	assert.NilError(t, err)
	return srv
}

// l2TestPubKey returns a random keys.DHPublicKey.
func l2TestPubKey() keys.DHPublicKey {
	var pub keys.DHPublicKey
	rand.Read(pub[:])
	return pub
}

// l2TestCert returns a minimal leaf cert with the given public key.
func l2TestCert(pub keys.DHPublicKey) certs.Certificate {
	var sig [certs.SignatureLen]byte
	rand.Read(sig[:])
	return certs.Certificate{
		Version:   1,
		Type:      certs.Leaf,
		IssuedAt:  time.Unix(0x0102030405060708, 0),
		ExpiresAt: time.Unix(0x0FEDCBA098765432, 0),
		IDChunk: certs.IDChunk{
			Blocks: []certs.Name{{
				Type:  certs.TypeDNSName,
				Label: []byte("test.delegate"),
			}},
		},
		PublicKey: pub,
		Parent: certs.SHA3Fingerprint{
			1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
			11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
			21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
		},
		Signature: sig,
	}
}

// addTestGrant plants a cmd grant for user/key directly into srv's agMap and
// keyStore, mirroring what AddGrantFromIntentCommunication does in production.
func addTestGrant(srv *HopServer, user string, pub keys.DHPublicKey, cmd string, expTime time.Time) authgrants.Intent {
	intent := authgrants.Intent{
		GrantType:      authgrants.Command,
		TargetPort:     7777,
		StartTime:      time.Now(),
		ExpTime:        expTime,
		TargetSNI:      certs.RawStringName("target"),
		TargetUsername: user,
		DelegateCert:   l2TestCert(pub),
		AssociatedData: authgrants.GrantData{
			CommandGrantData: authgrants.CommandGrantData{Cmd: cmd},
		},
	}
	srv.agMap.AddAuthGrant(&intent, authgrants.PrincipalID(0))
	srv.keyStore.AddKey(pub)
	return intent
}

// TestGoldenPathL2 is the Phase-0 exit criterion at the session level:
// grant drains, action executes once, second attempt rejected.
func TestGoldenPathL2(t *testing.T) {
	defer resetClock()
	setClock(time.Now()) // deterministic fake clock anchored at test start

	srv := newTestServer(t)

	const user = "testuser"
	const cmd = "echo hello"
	pub := l2TestPubKey()
	expTime := thunks.TimeNow().Add(time.Hour)

	addTestGrant(srv, user, pub, cmd, expTime)

	// Step 1: AuthorizeKeyAuthGrant drains the grant from agMap.
	grants, err := srv.AuthorizeKeyAuthGrant(user, pub)
	assert.NilError(t, err)
	assert.Equal(t, 1, len(grants))
	assert.Equal(t, authgrants.Command, grants[0].GrantType)
	assert.Equal(t, cmd, grants[0].AssociatedData.CommandGrantData.Cmd)

	// Second drain call returns an error (grant already consumed).
	_, err = srv.AuthorizeKeyAuthGrant(user, pub)
	assert.ErrorContains(t, err, "no authgrant")

	// Step 2: checkCmd consumes the grant from authorizedActions exactly once.
	sess := &hopSession{
		server:            srv,
		user:              user,
		authorizedActions: grants,
	}

	_, err = sess.checkCmd(cmd, false)
	assert.NilError(t, err)

	// Grant is consumed; second checkCmd must fail.
	_, err = sess.checkCmd(cmd, false)
	assert.ErrorContains(t, err, "no auth grant")
}
