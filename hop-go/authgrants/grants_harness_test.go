package authgrants

// L1 (role-level) grant lifecycle harness.
//
// Provides event log, intent builder, and recording callbacks for the
// deterministic scenario matrix (Phase 3).
//
// Phase 0 exit criterion (§4.3): TestGoldenPathL1 drives a complete
// Figure-5 issuance — delegate requests cmd:echo hello, principal approves
// (recorded), target stores — and asserts the exact event sequence.

import (
	"crypto/rand"
	"net"
	"sync"
	"testing"
	"time"

	"gotest.tools/assert"
	"gotest.tools/assert/cmp"

	"hop.computer/hop/certs"
	"hop.computer/hop/core"
)

// EventKind labels each observable lifecycle transition.
type EventKind string

const (
	EvApprovalInvoked  EventKind = "ApprovalInvoked"
	EvApprovalReturned EventKind = "ApprovalReturned"
	EvGrantAdded       EventKind = "GrantAdded"
	EvGrantDrained     EventKind = "GrantDrained"
	EvActionRequested  EventKind = "ActionRequested"
	EvActionGranted    EventKind = "ActionGranted"
	EvActionDenied     EventKind = "ActionDenied"
	EvSessionMinted    EventKind = "SessionMinted"
	EvKeyAdded         EventKind = "KeyAdded"
)

// Event is a single lifecycle step appended to the EventLog.
type Event struct {
	Kind    EventKind
	Intent  Intent
	Err     error
	Cmd     string
	Count   int
	ExpTime time.Time
}

// EventLog is a thread-safe ordered log of lifecycle events.
type EventLog struct {
	mu     sync.Mutex
	Events []Event
}

// NewEventLog returns an empty event log.
func NewEventLog() *EventLog { return &EventLog{} }

func (l *EventLog) append(e Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.Events = append(l.Events, e)
}

// Kinds returns the sequence of EventKind values, suitable for cmp.DeepEqual.
func (l *EventLog) Kinds() []EventKind {
	l.mu.Lock()
	defer l.mu.Unlock()
	ks := make([]EventKind, len(l.Events))
	for i, e := range l.Events {
		ks[i] = e.Kind
	}
	return ks
}

// RecordingApprover returns a CheckIntentCallback that appends
// ApprovalInvoked + ApprovalReturned to l and always returns decision.
func (l *EventLog) RecordingApprover(decision error) CheckIntentCallback {
	return func(i Intent, cert *certs.Certificate) error {
		l.append(Event{Kind: EvApprovalInvoked, Intent: i})
		l.append(Event{Kind: EvApprovalReturned, Err: decision})
		return decision
	}
}

// RecordingAdder returns an addAuthGrantFunc that appends a GrantAdded event.
func (l *EventLog) RecordingAdder() addAuthGrantFunc {
	return func(i *Intent) error {
		l.append(Event{Kind: EvGrantAdded, Intent: *i, ExpTime: i.ExpTime})
		return nil
	}
}

// IntentBuilder assembles an Intent for test use.
type IntentBuilder struct {
	intent Intent
}

// NewCmdIntent creates a builder for a Command grant with cmd.
// Default TTL is one hour from now; default username is "user".
func NewCmdIntent(cmd string) *IntentBuilder {
	pub := genTestPubKey()
	return &IntentBuilder{intent: Intent{
		GrantType:      Command,
		TargetPort:     7777,
		StartTime:      time.Now(),
		ExpTime:        time.Now().Add(time.Hour),
		TargetSNI:      certs.RawStringName("target"),
		TargetUsername: "user",
		DelegateCert:   buildTestCert(pub),
		AssociatedData: GrantData{CommandGrantData: CommandGrantData{Cmd: cmd}},
	}}
}

// NewShellIntent creates a builder for a Shell grant.
func NewShellIntent() *IntentBuilder {
	pub := genTestPubKey()
	return &IntentBuilder{intent: Intent{
		GrantType:      Shell,
		TargetPort:     7777,
		StartTime:      time.Now(),
		ExpTime:        time.Now().Add(time.Hour),
		TargetSNI:      certs.RawStringName("target"),
		TargetUsername: "user",
		DelegateCert:   buildTestCert(pub),
		AssociatedData: GrantData{ShellGrantData: ShellGrantData{}},
	}}
}

// WithTTL sets expiration relative to now.
func (b *IntentBuilder) WithTTL(d time.Duration) *IntentBuilder {
	b.intent.StartTime = time.Now()
	b.intent.ExpTime = time.Now().Add(d)
	return b
}

// WithExpired sets expiration one second in the past.
func (b *IntentBuilder) WithExpired() *IntentBuilder {
	return b.WithTTL(-time.Second)
}

// WithUsername sets the target username field.
func (b *IntentBuilder) WithUsername(u string) *IntentBuilder {
	b.intent.TargetUsername = u
	return b
}

// WithTargetSNI sets the TargetSNI field.
func (b *IntentBuilder) WithTargetSNI(sni string) *IntentBuilder {
	b.intent.TargetSNI = certs.RawStringName(sni)
	return b
}

// WithPublicKey replaces the delegate cert's public key.
func (b *IntentBuilder) WithPublicKey(pub [certs.KeyLen]byte) *IntentBuilder {
	b.intent.DelegateCert = buildTestCert(pub)
	return b
}

// Build returns the assembled Intent.
func (b *IntentBuilder) Build() Intent { return b.intent }

// genTestPubKey returns a random public key for delegate certs.
func genTestPubKey() [certs.KeyLen]byte {
	var pub [certs.KeyLen]byte
	rand.Read(pub[:])
	return pub
}

// buildTestCert returns a minimal leaf certificate with pub as the public key.
func buildTestCert(pub [certs.KeyLen]byte) certs.Certificate {
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
		Signature: fakeSignature(),
	}
}

// TestGoldenPathL1 drives the complete Figure-5 authgrant issuance protocol
// at the role-harness level and asserts the exact event sequence:
// ApprovalInvoked → ApprovalReturned → GrantAdded.
func TestGoldenPathL1(t *testing.T) {
	log := NewEventLog()
	intent := NewCmdIntent("echo hello").Build()

	// delegate ↔ principal pipe pair
	delConn, delDelegate := net.Pipe()
	// principal ↔ target pipe pair
	prinConn, prinTarget := net.Pipe()

	principalApprover := log.RecordingApprover(nil)
	adder := log.RecordingAdder()
	targetAdmitter := func(i Intent, cert *certs.Certificate) error { return nil }

	// vc is checkIntentWithCert in principal.go — normally invoked during the
	// transport handshake. We call it here to simulate that approval step.
	setupTarg := func(u core.URL, vc AdditionalVerifyCallback) (net.Conn, error) {
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
		StartTargetInstance(prinTarget, nil, targetAdmitter, adder)
	}()

	go func() {
		defer wg.Done()
		StartPrincipalInstance(delConn, principalApprover, setupTarg)
		prinConn.Close()
	}()

	err := StartDelegateInstance(delDelegate, []Intent{intent})
	assert.NilError(t, err)
	delDelegate.Close()

	wg.Wait()

	assert.Check(t, cmp.DeepEqual(log.Kinds(), []EventKind{
		EvApprovalInvoked,
		EvApprovalReturned,
		EvGrantAdded,
	}))
}
