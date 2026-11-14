package authgrants

// S4 — Follow-up intents mint actions without new approval (Phase 3).
//
// Hypothesis H4 (grant_lifecycle_investigation_plan.md §1):
//   "Exactly one user-approval event covers the first intent per principal
//   instance; follow-up intents on the same tube skip principal-side
//   approval (error discarded, principal.go:111-112) while the target
//   instance loop keeps accepting IntentCommunication on the still-open
//   tube (authgrants/target.go:56-66), adding actions to a live session
//   without any new approval."
//
// Invariants under test:
//   INV-E — "explicit approval from the user". Operationalized: every
//           IntentCommunication accepted by the target corresponds 1:1 to
//           a *successful* principal-side approval (returning nil).
//   INV-G — no capability growth absent a new approval event.
//
// Static facts exercised (plan §2):
//   V8 — principal.go:114-116 (`else { p.checkIntent(i, p.targetCert) }`)
//        discards the callback's error on follow-up intents; the
//        unconditional WriteIntentCommunication at line 118 forwards the
//        intent to the target regardless.
//
// Prediction: a user DENIAL of intent-2 (via checkIntent returning a
// non-nil error) is silently ignored by the principal; the target still
// stores the grant; the delegate sees IntentConfirmation. INV-E and INV-G
// both falsified by a single interleaving.

import (
	"fmt"
	"net"
	"sync"
	"testing"

	"gotest.tools/assert"
	"gotest.tools/assert/cmp"

	"hop.computer/hop/certs"
	"hop.computer/hop/core"
)

// scriptedApprover returns a CheckIntentCallback that, on invocation #k,
// returns decisions[k-1]. Each call appends ApprovalInvoked +
// ApprovalReturned events to log so the sequence can be adjudicated.
//
// If the number of invocations exceeds len(decisions), the test fails via
// t.Fatalf — exceeding our script means the control flow diverged from the
// predicted path and the scenario is invalid.
func scriptedApprover(t *testing.T, log *EventLog, decisions []error) CheckIntentCallback {
	t.Helper()
	var n int
	var mu sync.Mutex
	return func(i Intent, cert *certs.Certificate) error {
		mu.Lock()
		n++
		if n > len(decisions) {
			mu.Unlock()
			t.Fatalf("scriptedApprover: too many invocations (%d), scripted only %d", n, len(decisions))
		}
		decision := decisions[n-1]
		mu.Unlock()
		log.append(Event{Kind: EvApprovalInvoked, Intent: i})
		log.append(Event{Kind: EvApprovalReturned, Err: decision})
		return decision
	}
}

// TestS4_FollowUpIntentApprovalDiscarded drives the Figure-5 flow with two
// intents to the same (SNI, user, port) target. intent-1 is approved by the
// user; intent-2 is DENIED by the user (checkIntent returns an error).
//
// Expected event sequence (predicted by V8):
//
//   [ApprovalInvoked, ApprovalReturned(nil),      GrantAdded,   // intent-1
//    ApprovalInvoked, ApprovalReturned(err=deny), GrantAdded]   // intent-2 ⚠
//
// The final GrantAdded is the smoking gun: the target stored a grant whose
// principal-side approval returned an error. Also assert the delegate sees
// IntentConfirmation for BOTH intents — the user's denial is invisible on
// the wire.
func TestS4_FollowUpIntentApprovalDiscarded(t *testing.T) {
	log := NewEventLog()
	intent1 := NewCmdIntent("echo one").Build()
	intent2 := NewShellIntent().Build()

	// Guard: both intents must name the same TargetURL — otherwise principal.go
	// line 91 ("received intent request for different target") short-circuits and
	// the else branch at line 114-116 is never reached. (Both builders default
	// to the same SNI/user/port, so this is belt-and-braces.)
	assert.Equal(t, intent1.TargetURL(), intent2.TargetURL(),
		"S4 precondition: intent1 and intent2 must share TargetURL")

	delConn, delDelegate := net.Pipe()
	prinConn, prinTarget := net.Pipe()

	userScript := []error{
		nil, // user approves intent-1
		fmt.Errorf("user denies intent-2"), // user denies intent-2
	}
	principalApprover := scriptedApprover(t, log, userScript)
	adder := log.RecordingAdder()
	targetAdmitter := func(i Intent, cert *certs.Certificate) error { return nil }

	// setupTarg: called by principal.go only on the targetConnected=false
	// branch (intent-1). intent-2 takes the else branch and does NOT call
	// setUpTargetConn — which is exactly what V8 is about.
	setupTarg := func(u core.URL, vc AdditionalVerifyCallback) (net.Conn, error) {
		if vc != nil {
			// Ignore vc's return deliberately — the harness simulates the
			// production handshake that already discards on intent-1.
			_ = vc(nil)
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

	// Drive the delegate manually so we can capture per-intent response.
	var delegateResponses []AgMessage
	for idx, intent := range []Intent{intent1, intent2} {
		err := WriteIntentRequest(delDelegate, intent)
		assert.NilError(t, err, "delegate: write intent-%d", idx+1)
		resp, err := ReadConfOrDenial(delDelegate)
		assert.NilError(t, err, "delegate: read response-%d", idx+1)
		delegateResponses = append(delegateResponses, resp)
	}
	delDelegate.Close()
	wg.Wait()

	// ---- (1) Event-log structure. ----
	assert.Check(t, cmp.DeepEqual(log.Kinds(), []EventKind{
		EvApprovalInvoked, EvApprovalReturned, EvGrantAdded, // intent-1
		EvApprovalInvoked, EvApprovalReturned, EvGrantAdded, // intent-2 ⚠
	}))

	// ---- (2) INV-E/G falsification witness: intent-2's approval returned an
	//        error, and yet the immediately-following event is GrantAdded. ----
	//
	// log.Events order:
	//   0 ApprovalInvoked  (intent-1)
	//   1 ApprovalReturned (intent-1, err=nil)
	//   2 GrantAdded       (intent-1)
	//   3 ApprovalInvoked  (intent-2)
	//   4 ApprovalReturned (intent-2, err=deny)   ← user said NO
	//   5 GrantAdded       (intent-2)             ← target stored anyway
	assert.NilError(t, log.Events[1].Err, "intent-1 approval must have succeeded")
	assert.Assert(t, log.Events[4].Err != nil,
		"intent-2 approval must have returned an error (user denial)")
	assert.ErrorContains(t, log.Events[4].Err, "user denies intent-2")
	assert.Equal(t, EvGrantAdded, log.Events[5].Kind,
		"⚠ V8/INV-E: target added a grant immediately after the principal's checkIntent returned an error — "+
			"principal.go:114-116 discarded the decision")

	// ---- (3) Delegate's wire-level view: both intents 'confirmed'. ----
	//
	// From the delegate's perspective, there is no signal that the user
	// denied intent-2. The denial is lost in the else-branch of
	// doIntentRequestChecks and the unconditional WriteIntentCommunication
	// drives the target into storing the grant; the target's Confirmation
	// propagates back through the principal as IntentConfirmation to the
	// delegate.
	assert.Equal(t, IntentConfirmation, delegateResponses[0].MsgType,
		"delegate: intent-1 must be confirmed")
	assert.Equal(t, IntentConfirmation, delegateResponses[1].MsgType,
		"⚠ INV-E/G: delegate saw IntentConfirmation for intent-2 despite user denial")
}

// TestS4_FollowUpIntentCrossTarget is a precondition / scope-guard: a
// follow-up intent naming a DIFFERENT TargetURL than intent-1 is rejected
// at principal.go:91 BEFORE reaching the else-branch; so V8 applies only
// to follow-ups on the SAME target. This test documents that scope by
// showing the different-target path works as the paper would expect: no
// grant is stored.
//
// Without this guard, a reader could ask "why doesn't V8 affect
// different-target follow-ups too?" — this test answers that in-tree.
func TestS4_FollowUpIntentCrossTarget(t *testing.T) {
	log := NewEventLog()
	intent1 := NewCmdIntent("echo one").Build()
	intent2 := NewShellIntent().WithTargetSNI("someotherhost").Build()

	assert.Check(t, intent1.TargetURL() != intent2.TargetURL(),
		"scope: this test requires intent1 and intent2 to differ in TargetURL")

	delConn, delDelegate := net.Pipe()
	prinConn, prinTarget := net.Pipe()

	userScript := []error{nil} // only intent-1 reaches the approver
	principalApprover := scriptedApprover(t, log, userScript)
	adder := log.RecordingAdder()
	targetAdmitter := func(i Intent, cert *certs.Certificate) error { return nil }

	setupTarg := func(u core.URL, vc AdditionalVerifyCallback) (net.Conn, error) {
		if vc != nil {
			_ = vc(nil)
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

	var delegateResponses []AgMessage
	for idx, intent := range []Intent{intent1, intent2} {
		err := WriteIntentRequest(delDelegate, intent)
		assert.NilError(t, err, "delegate: write intent-%d", idx+1)
		resp, err := ReadConfOrDenial(delDelegate)
		assert.NilError(t, err, "delegate: read response-%d", idx+1)
		delegateResponses = append(delegateResponses, resp)
	}
	delDelegate.Close()
	wg.Wait()

	// intent-1: approved → GrantAdded.
	// intent-2: principal.go:91 denies (different target), no approval invoked,
	//           no GrantAdded. Delegate sees IntentDenied.
	assert.Check(t, cmp.DeepEqual(log.Kinds(), []EventKind{
		EvApprovalInvoked, EvApprovalReturned, EvGrantAdded,
	}))

	assert.Equal(t, IntentConfirmation, delegateResponses[0].MsgType,
		"intent-1: confirmed")
	assert.Equal(t, IntentDenied, delegateResponses[1].MsgType,
		"intent-2: denied by cross-target guard (principal.go:91) — scope boundary of V8")
}
