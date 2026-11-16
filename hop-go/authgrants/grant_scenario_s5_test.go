package authgrants

// S5 — Approval-timing races (Phase 3, scenario S5; Issue #80 residue).
//
// The paper (§7.3) says "the authorization grant flow stops and the
// Principal requests explicit approval from the user" but specifies no
// bound on how long "stops" may be, no behavior for a delegate that gives
// up during the stop, and no behavior for a target connection that dies
// mid-approval. Issue #80 (open, upstream) asks exactly these questions.
//
// This scenario is characterization, not violation-hunting: the deliverable
// is a state-reachability map of the stall across the three parties
// (delegate / principal / target) under three interleavings:
//
//   S5a — approval stalls forever: all three parties block cleanly; no
//         side effects accrue (no grant, no wire traffic past the initial
//         IntentRequest).
//   S5b — approval returns AFTER the delegate gave up and disconnected:
//         principal flow proceeds anyway; target adds the grant; agMap
//         gains an entry the delegate never learned was created (⚠ a
//         "silent mint" — the grant exists, bound to the key the now-gone
//         delegate holds).
//   S5c — approval returns AFTER the target tube died: principal's
//         WriteIntentCommunication fails; principal.go:118-121 writes
//         IntentDenied back to the delegate; no grant added, delegate sees
//         a deny message.
//
// Static facts exercised (plan §2):
//   V8-adjacent: principal.go:99-103 — the approver's return value flows
//   out of checkIntentWithCert (first-intent path), which is why S5b's
//   silent mint is slightly non-obvious: if the approver returns nil, the
//   handshake vc also returns nil, so setUpTargetConn returns (conn, nil),
//   so handleIntentRequest proceeds to WriteIntentCommunication regardless
//   of who's still listening.
//
// All three subtests use the L1 harness (grants_harness_test.go) and a
// stall callback that blocks on a release channel the test owns. Each test
// is bounded by a short watchdog so a misdesigned stall can't hang the
// suite.

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gotest.tools/assert"

	"hop.computer/hop/certs"
	"hop.computer/hop/core"
)

// stallApprover returns a CheckIntentCallback that blocks until release is
// closed, then returns decision. invoked is incremented once per entry
// into the callback (observable before the stall).
//
// Pattern: tests build (invoked, release) locally, start the flow, poll
// invoked to confirm the stall point is reached, then either leave release
// closed (S5a) or close it to unblock (S5b/S5c).
func stallApprover(log *EventLog, invoked *int32, release <-chan struct{}, decision error) CheckIntentCallback {
	return func(i Intent, cert *certs.Certificate) error {
		atomic.AddInt32(invoked, 1)
		log.append(Event{Kind: EvApprovalInvoked, Intent: i})
		<-release
		log.append(Event{Kind: EvApprovalReturned, Err: decision})
		return decision
	}
}

// waitForApprovalEntry spins until invoked reaches 1 or deadline elapses.
// Returns true iff the callback was entered (i.e. the stall point is
// observable). Used by all three subtests as the "we are now inside the
// stall" synchronization point.
func waitForApprovalEntry(invoked *int32, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(invoked) >= 1 {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return false
}

// TestS5a_StallForever asserts the clean-stall shape: inside the approval,
// no party makes forward progress. No grant is added; no IntentCommunication
// is sent; the delegate's ReadConfOrDenial has no response.
//
// This is the baseline of the reachability map: "stops" == "all three
// parties block cleanly, no state change." Any deviation from this in
// future code would be a new finding.
func TestS5a_StallForever(t *testing.T) {
	log := NewEventLog()
	intent := NewCmdIntent("echo s5a").Build()

	delConn, delDelegate := net.Pipe()
	prinConn, prinTarget := net.Pipe()

	var invoked int32
	release := make(chan struct{}) // never closed in S5a

	principalApprover := stallApprover(log, &invoked, release, nil)
	adder := log.RecordingAdder()
	targetAdmitter := func(i Intent, cert *certs.Certificate) error { return nil }

	setupTarg := func(u core.URL, vc AdditionalVerifyCallback) (net.Conn, error) {
		if vc != nil {
			_ = vc(nil) // this call blocks inside stallApprover
		}
		return prinConn, nil
	}

	targetDone := make(chan struct{})
	go func() {
		StartTargetInstance(prinTarget, nil, targetAdmitter, adder)
		close(targetDone)
	}()

	principalDone := make(chan struct{})
	go func() {
		StartPrincipalInstance(delConn, principalApprover, setupTarg)
		prinConn.Close() // signal target to exit its read loop
		close(principalDone)
	}()

	// Delegate sends the intent, then tries to read the response — which
	// never arrives because the principal is stalled.
	err := WriteIntentRequest(delDelegate, intent)
	assert.NilError(t, err, "delegate: write intent")

	// Observe the stall point: approver entered but hasn't returned.
	assert.Assert(t, waitForApprovalEntry(&invoked, time.Second),
		"S5a: approver must enter the stall within 1s")

	// ---- Negative evidence: nothing has moved past the stall. ----

	// (1) The delegate's response read would block. Use a short read
	// deadline to prove it: set a tiny deadline on the pipe side, try
	// reading, expect a timeout error.
	_ = delDelegate.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	_, err = ReadConfOrDenial(delDelegate)
	assert.Assert(t, err != nil,
		"S5a: delegate must NOT have a response yet while principal stalls")
	// Clear deadline so cleanup reads don't spuriously fail.
	_ = delDelegate.SetReadDeadline(time.Time{})

	// (2) No GrantAdded event — the target never got an IntentCommunication.
	for _, e := range log.Events {
		assert.Assert(t, e.Kind != EvGrantAdded,
			"S5a: target must not have added a grant during the stall")
	}

	// (3) Approver entered exactly once, never returned.
	assert.Equal(t, int32(1), atomic.LoadInt32(&invoked),
		"S5a: approver entered exactly once")
	for _, e := range log.Events {
		assert.Assert(t, e.Kind != EvApprovalReturned,
			"S5a: approver must NOT have returned during the stall")
	}

	// ---- Cleanup: tear down without hanging the test. ----
	//
	// We release the stall AFTER asserting the negative evidence. This
	// lets the principal finish its loop and the goroutines exit, so the
	// test doesn't leak. We close the delegate side first so the principal
	// won't infinitely wait on it after processing intent-1.
	delDelegate.Close()
	close(release) // let the approver return
	// The principal should now wake up, complete the intent-1 flow (grant
	// WILL be added at this point — see S5b for that assertion), and exit
	// on the next ReadIntentRequest when the delegate pipe is closed.
	<-principalDone
	<-targetDone
}

// TestS5b_ApprovalAfterDelegateGone is the surprising half of the
// reachability map. The sequence:
//
//   1. Delegate sends IntentRequest.
//   2. Principal enters checkIntent and stalls.
//   3. Delegate closes its side (simulating a timeout / user ^C / crash).
//   4. User approves (we close release with nil).
//   5. Principal has NO way to tell the delegate is gone — the stall was
//      inside a synchronous callback. It continues:
//        - vc returns nil
//        - setUpTargetConn returns (prinConn, nil)
//        - WriteIntentCommunication(prinConn, i) succeeds
//        - target adds the grant (GrantAdded event logged)
//        - ReadConfOrDenial on prinConn returns IntentConfirmation
//        - WriteIntentConfirmation(p.delegateConn, ...) — THIS fails
//          because the delegate closed its pipe end.
//   6. Grant IS persisted in agMap; delegate never sees a confirmation.
//
// This is the "silent mint" case. Implication: if the delegate holds the
// ephemeral keypair (which it does — §3 of the paper), it can later
// reconnect with that key and claim the grant. A compromised delegate
// that times out intentionally and reconnects later still gets the grant
// — the user's approval is effectively consumed by a gone party.
func TestS5b_ApprovalAfterDelegateGone(t *testing.T) {
	log := NewEventLog()
	intent := NewCmdIntent("echo s5b").Build()

	delConn, delDelegate := net.Pipe()
	prinConn, prinTarget := net.Pipe()

	var invoked int32
	release := make(chan struct{})

	principalApprover := stallApprover(log, &invoked, release, nil)
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
		prinConn.Close() // mirror the golden-path harness pattern
	}()

	err := WriteIntentRequest(delDelegate, intent)
	assert.NilError(t, err, "delegate: write intent")

	// Wait until the principal is inside the stalled approver.
	assert.Assert(t, waitForApprovalEntry(&invoked, time.Second),
		"S5b: approver must enter stall within 1s")

	// Delegate gives up: close the pipe end from the delegate's side.
	// The principal is blocked in checkIntent, not reading delConn, so
	// this close has no effect yet.
	delDelegate.Close()

	// A tiny wait window to ensure delegate close actually propagates
	// before approval unblocks (not strictly necessary, but makes the
	// ordering clear in the log).
	time.Sleep(10 * time.Millisecond)

	// User approves (nil decision). This drives the rest of the
	// principal's flow to completion against a dead delegate pipe.
	close(release)

	wg.Wait()

	// ---- Assertions: grant added despite delegate being gone. ----

	// Approval was invoked and returned.
	var sawInvoked, sawReturned, sawAdded bool
	for _, e := range log.Events {
		switch e.Kind {
		case EvApprovalInvoked:
			sawInvoked = true
		case EvApprovalReturned:
			sawReturned = true
			assert.NilError(t, e.Err, "approver returned nil (approved)")
		case EvGrantAdded:
			sawAdded = true
		}
	}
	assert.Assert(t, sawInvoked, "approver must have been invoked")
	assert.Assert(t, sawReturned, "approver must have returned")
	assert.Assert(t, sawAdded,
		"⚠ S5b: GrantAdded fired even though delegate closed before approval returned — "+
			"principal has no cancellation path for an in-flight stalled approval; "+
			"the grant is minted into agMap, reachable by anyone holding the "+
			"delegate's ephemeral key (see S6 for the bearer-semantics analysis)")
}

// TestS5c_TargetDiesDuringStall asserts the principal-side error path
// when the target principal-conn drops while approval is stalled.
//
// Sequence:
//   1. Delegate sends IntentRequest.
//   2. Principal enters checkIntent and stalls.
//   3. Target closes its pipe end (simulating a crash/disconnect).
//   4. User approves (we close release with nil).
//   5. Principal's vc returns nil → setUpTargetConn returns (prinConn, nil)
//      → WriteIntentCommunication(prinConn, i) FAILS (pipe closed).
//   6. principal.go:120-122: WriteIntentDenied(p.delegateConn, "...error
//      sending intent comm: ...") — the delegate learns the request was
//      denied (not that the target died).
//   7. No grant is added.
//
// Mapping this reachability case closes out Issue #80's "what if the
// target goes away" leg: the error surfaces as a generic IntentDenied to
// the delegate; no leak into agMap.
func TestS5c_TargetDiesDuringStall(t *testing.T) {
	log := NewEventLog()
	intent := NewCmdIntent("echo s5c").Build()

	delConn, delDelegate := net.Pipe()
	prinConn, prinTarget := net.Pipe()

	var invoked int32
	release := make(chan struct{})

	principalApprover := stallApprover(log, &invoked, release, nil)
	adder := log.RecordingAdder()
	targetAdmitter := func(i Intent, cert *certs.Certificate) error { return nil }

	setupTarg := func(u core.URL, vc AdditionalVerifyCallback) (net.Conn, error) {
		if vc != nil {
			_ = vc(nil)
		}
		return prinConn, nil
	}

	var wg sync.WaitGroup
	wg.Add(1) // we only wait on target; principal's lifecycle bounded by delegate close
	go func() {
		defer wg.Done()
		StartTargetInstance(prinTarget, nil, targetAdmitter, adder)
	}()

	principalDone := make(chan struct{})
	go func() {
		StartPrincipalInstance(delConn, principalApprover, setupTarg)
		close(principalDone)
	}()

	err := WriteIntentRequest(delDelegate, intent)
	assert.NilError(t, err, "delegate: write intent")

	assert.Assert(t, waitForApprovalEntry(&invoked, time.Second),
		"S5c: approver must enter stall within 1s")

	// Kill the target side. The target goroutine's ReadIntentCommunication
	// errors out; the StartTargetInstance defer closes prinTarget.
	//
	// Closing prinTarget cascades: when principal eventually writes to
	// prinConn (the peer), the write returns an error.
	prinTarget.Close()
	// Wait for target loop exit so logs stabilize before unblocking.
	wg.Wait()

	// Unblock approval.
	close(release)

	// Delegate reads the deny message that principal.go:120-122 writes.
	resp, err := ReadConfOrDenial(delDelegate)
	assert.NilError(t, err, "delegate: must read a response (deny) from principal")
	assert.Equal(t, IntentDenied, resp.MsgType,
		"S5c: delegate must see IntentDenied when target died during stall")
	assert.Assert(t, resp.Data.Denial != "",
		"S5c: deny message must carry a reason string")

	// Close the delegate side so the principal's run() loop exits.
	delDelegate.Close()
	<-principalDone

	// ---- Negative evidence: no grant added. ----
	for _, e := range log.Events {
		assert.Assert(t, e.Kind != EvGrantAdded,
			"S5c: target must NOT have added a grant after its conn died")
	}

	// Positive evidence: approval WAS invoked and returned (user approved
	// in a world where the target was already gone — the principal has no
	// way to pre-check target liveness before prompting).
	var sawReturned bool
	for _, e := range log.Events {
		if e.Kind == EvApprovalReturned {
			sawReturned = true
			assert.NilError(t, e.Err,
				"S5c: approver returned nil — user approved into the void")
		}
	}
	assert.Assert(t, sawReturned,
		"S5c: approver did return — user approval is wasted when target dies "+
			"during the prompt; this is an availability characterization, not a "+
			"security bug (no grant leaked), but it informs Issue #80's UX leg")
}

// TestS5d_StallThenApprovalDenial is a minor characterization: if the
// user eventually DENIES after a long stall, no grant is added and the
// delegate sees IntentDenied with the user's reason. This closes the
// "approval delayed but negative" leg of the reachability map.
func TestS5d_StallThenApprovalDenial(t *testing.T) {
	log := NewEventLog()
	intent := NewCmdIntent("echo s5d").Build()

	delConn, delDelegate := net.Pipe()
	prinConn, prinTarget := net.Pipe()

	var invoked int32
	release := make(chan struct{})

	denyReason := fmt.Errorf("user denies after thinking about it")
	principalApprover := stallApprover(log, &invoked, release, denyReason)
	adder := log.RecordingAdder()
	targetAdmitter := func(i Intent, cert *certs.Certificate) error { return nil }

	setupTarg := func(u core.URL, vc AdditionalVerifyCallback) (net.Conn, error) {
		if vc != nil {
			if err := vc(nil); err != nil {
				return nil, err
			}
		}
		return prinConn, nil
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		StartTargetInstance(prinTarget, nil, targetAdmitter, adder)
	}()

	principalDone := make(chan struct{})
	go func() {
		StartPrincipalInstance(delConn, principalApprover, setupTarg)
		prinConn.Close()
		close(principalDone)
	}()

	err := WriteIntentRequest(delDelegate, intent)
	assert.NilError(t, err)
	assert.Assert(t, waitForApprovalEntry(&invoked, time.Second))

	// After an arbitrary "think time" the user denies.
	close(release)

	// The principal writes IntentDenied from its checkIntentWithCert
	// closure (principal.go:101) before returning the error to vc.
	resp, err := ReadConfOrDenial(delDelegate)
	assert.NilError(t, err)
	assert.Equal(t, IntentDenied, resp.MsgType,
		"S5d: user denial after a stall surfaces as IntentDenied")
	assert.Equal(t, denyReason.Error(), resp.Data.Denial,
		"S5d: denial reason string flows through to the delegate verbatim")

	// Note: principal.go also writes a SECOND IntentDenied after
	// setUpTargetConn returns an error (line 108). Read it to drain and
	// keep the pipe clean — this is itself a minor finding (duplicate
	// denies on the wire) worth logging but not a security issue.
	resp2, err := ReadConfOrDenial(delDelegate)
	assert.NilError(t, err,
		"S5d: principal writes a SECOND IntentDenied — target-setup failure path at "+
			"principal.go:108 fires after the user-denial path at principal.go:101; "+
			"delegates see two denies for one intent (low-severity protocol-noise finding)")
	assert.Equal(t, IntentDenied, resp2.MsgType)

	delDelegate.Close()
	<-principalDone
	wg.Wait()

	for _, e := range log.Events {
		assert.Assert(t, e.Kind != EvGrantAdded,
			"S5d: no grant on user denial")
	}
}
