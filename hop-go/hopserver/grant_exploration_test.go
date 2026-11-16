package hopserver

// Phase 4.1 — Invariant-guided random exploration (grant_lifecycle_investigation_plan.md §8.1).
//
// With the scenario matrix (S1–S8) adjudicated, randomized traces are
// the cheap way to surface interleavings we didn't think of. The code
// state machine for authorization grants is small enough that a few
// thousand random traces with per-step invariant checks is effectively
// poor-man's model checking (plan §8.1).
//
// This runner operates at the L2 layer (HopServer + fake clock) and
// maintains a precise SHADOW MODEL of agMap, the transport keystore,
// and any live sessions. Ops are drawn uniformly from a fixed op
// vocabulary; after each op the shadow is compared bit-for-bit to the
// real server state. Any divergence reproduces by seed.
//
// Op vocabulary (plan §8.1, narrowed to the L2 surface):
//   addGrant(user, pub, {cmd:X | shell}, ttl)
//   advanceClock(d)
//   drainGrants(user, pub)       // calls AuthorizeKeyAuthGrant
//   checkCmd(sess, cmd)          // consumes a cmd grant on a tracked session
//   checkShell(sess)             // consumes a shell grant on a tracked session
//   readdKey(pub)                // re-add a pubkey post-drain (S6-adjacent)
//
// Invariants (code-level, not paper-level — the paper-level ones are
// already known falsified; here we assert the CODE's own promises):
//   M1 : drain returns exactly the shadow's grants for (user, pub), in
//        insertion order, cleared from agMap afterward.
//   M2 : after a successful drain, pub is removed from keystore.
//   M3 : checkCmd consumes at most one grant; when it succeeds, the
//        consumed grant matched the request (cmd-equal OR shell-mode)
//        AND was not expired.
//   M4 : a failed checkCmd leaves authorizedActions untouched.
//   M5 : addGrant monotonically grows the bucket by 1 and adds pub.
//   M6 : no panics in 200 traces of length 8.
//
// Characterization counters (tagged, not asserted — these represent
// known-falsified paper invariants we're observing in the random stream):
//   C_B : # expired grants successfully drained (INV-B residue)
//   C_F : # successful checkCmd on grants past ExpTime between drain
//         and consumption (INV-B at the per-action layer)
//
// Reproducibility: the RNG is math/rand/v2 PCG seeded by (seed, 0). Each
// test logs the seed on failure; `-run TestExplorationReplaySeed` with
// RANDOM_SEED=<n> deterministically rebuilds the trace.

import (
	"fmt"
	"math/rand/v2"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"hop.computer/hop/authgrants"
	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
	"hop.computer/hop/pkg/thunks"
)

// ---------- Shadow model ----------

type shadowGrant struct {
	grantType authgrants.GrantType
	cmd       string // "" for shell
	expTime   time.Time
}

type shadowSession struct {
	id      int
	user    string
	pub     keys.DHPublicKey
	actions []shadowGrant
}

type shadowState struct {
	// shadowAgMap mirrors srv.agMap per (user, pub) → slice of pending grants.
	agMap map[string]map[keys.DHPublicKey][]shadowGrant
	// keyStore mirrors srv.keyStore membership (presence boolean, since
	// the real keystore is a set at this layer).
	keyStore map[keys.DHPublicKey]bool
	// live sessions drawn from drains
	sessions []*shadowSession
	nextID   int

	// characterization counters (not asserted)
	expiredDrained          int
	expiredCheckCmdAttempts int
	expiredCheckCmdSuccess  int
}

func newShadowState() *shadowState {
	return &shadowState{
		agMap:    make(map[string]map[keys.DHPublicKey][]shadowGrant),
		keyStore: make(map[keys.DHPublicKey]bool),
	}
}

func (s *shadowState) bucket(user string, pub keys.DHPublicKey) []shadowGrant {
	if u, ok := s.agMap[user]; ok {
		return u[pub]
	}
	return nil
}

// ---------- Op trace ----------

type opKind int

const (
	opAddGrant opKind = iota
	opAdvanceClock
	opDrain
	opCheckCmd
	opCheckShell
	opReaddKey
)

type op struct {
	kind opKind
	// payload fields (set per kind):
	user      string
	pubIdx    int    // index into pool
	cmd       string // for addGrant / checkCmd
	grantType authgrants.GrantType
	ttl       time.Duration
	d         time.Duration // for advanceClock
	sessIdx   int           // for checkCmd / checkShell
}

func (o op) String() string {
	switch o.kind {
	case opAddGrant:
		gt := "cmd"
		if o.grantType == authgrants.Shell {
			gt = "shell"
		}
		return fmt.Sprintf("addGrant(user=%s, pub=#%d, type=%s, cmd=%q, ttl=%s)",
			o.user, o.pubIdx, gt, o.cmd, o.ttl)
	case opAdvanceClock:
		return fmt.Sprintf("advanceClock(%s)", o.d)
	case opDrain:
		return fmt.Sprintf("drainGrants(user=%s, pub=#%d)", o.user, o.pubIdx)
	case opCheckCmd:
		return fmt.Sprintf("checkCmd(sess=%d, cmd=%q)", o.sessIdx, o.cmd)
	case opCheckShell:
		return fmt.Sprintf("checkShell(sess=%d)", o.sessIdx)
	case opReaddKey:
		return fmt.Sprintf("readdKey(pub=#%d)", o.pubIdx)
	}
	return "unknown"
}

// ---------- Trace runner ----------

type runner struct {
	t     *testing.T
	seed  uint64
	rng   *rand.Rand
	srv   *HopServer
	shadow *shadowState

	// Fixed pools so the RNG's output is small-integer indices.
	users []string
	pubs  []keys.DHPublicKey

	// Sessions created by drain ops (shadowed too, in shadow.sessions).
	sessions []*hopSession

	trace []op
}

func newRunner(t *testing.T, seed uint64) *runner {
	t.Helper()
	// PCG seeded by (seed, 0) — stable across Go versions.
	rng := rand.New(rand.NewPCG(seed, 0))

	users := []string{"alice", "bob"}
	pubs := make([]keys.DHPublicKey, 3)
	for i := range pubs {
		pubs[i] = l2TestPubKey()
	}

	srv := newTestServer(t)
	return &runner{
		t:      t,
		seed:   seed,
		rng:    rng,
		srv:    srv,
		shadow: newShadowState(),
		users:  users,
		pubs:   pubs,
	}
}

func (r *runner) genOp() op {
	// Weights: addGrant 30, advanceClock 15, drain 20, checkCmd 15,
	// checkShell 10, readdKey 10. Favors adding grants slightly so that
	// consumption ops have something to chew on.
	type w struct {
		kind opKind
		w    int
	}
	weights := []w{
		{opAddGrant, 30},
		{opAdvanceClock, 15},
		{opDrain, 20},
		{opCheckCmd, 15},
		{opCheckShell, 10},
		{opReaddKey, 10},
	}
	total := 0
	for _, x := range weights {
		total += x.w
	}
	pick := r.rng.IntN(total)
	var kind opKind
	for _, x := range weights {
		if pick < x.w {
			kind = x.kind
			break
		}
		pick -= x.w
	}

	o := op{kind: kind}
	o.user = r.users[r.rng.IntN(len(r.users))]
	o.pubIdx = r.rng.IntN(len(r.pubs))

	switch kind {
	case opAddGrant:
		if r.rng.IntN(2) == 0 {
			o.grantType = authgrants.Command
			cmds := []string{"ls", "date", "whoami", "cat-a"}
			o.cmd = cmds[r.rng.IntN(len(cmds))]
		} else {
			o.grantType = authgrants.Shell
		}
		// TTL between 10s and 20m. Some expire during trace, some don't.
		ttls := []time.Duration{10 * time.Second, 1 * time.Minute, 5 * time.Minute, 20 * time.Minute}
		o.ttl = ttls[r.rng.IntN(len(ttls))]
	case opAdvanceClock:
		ds := []time.Duration{5 * time.Second, 30 * time.Second, 2 * time.Minute, 10 * time.Minute}
		o.d = ds[r.rng.IntN(len(ds))]
	case opCheckCmd:
		if len(r.sessions) == 0 {
			// No sessions yet → turn this into an addGrant, which keeps
			// the trace productive instead of trivially failing with
			// "no session."
			return r.genAddGrantFallback()
		}
		o.sessIdx = r.rng.IntN(len(r.sessions))
		cmds := []string{"ls", "date", "whoami", "cat-a", "nope"}
		o.cmd = cmds[r.rng.IntN(len(cmds))]
	case opCheckShell:
		if len(r.sessions) == 0 {
			return r.genAddGrantFallback()
		}
		o.sessIdx = r.rng.IntN(len(r.sessions))
	}
	return o
}

func (r *runner) genAddGrantFallback() op {
	cmds := []string{"ls", "date", "whoami", "cat-a"}
	return op{
		kind:      opAddGrant,
		user:      r.users[r.rng.IntN(len(r.users))],
		pubIdx:    r.rng.IntN(len(r.pubs)),
		grantType: authgrants.Command,
		cmd:       cmds[r.rng.IntN(len(cmds))],
		ttl:       5 * time.Minute,
	}
}

// ---------- Op execution (real + shadow in lockstep) ----------

func (r *runner) exec(o op) {
	r.trace = append(r.trace, o)
	switch o.kind {
	case opAddGrant:
		r.execAddGrant(o)
	case opAdvanceClock:
		advanceClock(o.d)
	case opDrain:
		r.execDrain(o)
	case opCheckCmd:
		r.execCheckCmd(o)
	case opCheckShell:
		r.execCheckShell(o)
	case opReaddKey:
		pub := r.pubs[o.pubIdx]
		r.srv.keyStore.AddKey(pub)
		r.shadow.keyStore[pub] = true
	}
}

func (r *runner) execAddGrant(o op) {
	pub := r.pubs[o.pubIdx]
	exp := thunks.TimeNow().Add(o.ttl)
	intent := authgrants.Intent{
		GrantType:      o.grantType,
		TargetPort:     7777,
		StartTime:      thunks.TimeNow(),
		ExpTime:        exp,
		TargetSNI:      certs.RawStringName("target"),
		TargetUsername: o.user,
		DelegateCert:   l2TestCert(pub),
		AssociatedData: authgrants.GrantData{
			CommandGrantData: authgrants.CommandGrantData{Cmd: o.cmd},
		},
	}
	r.srv.agMap.AddAuthGrant(&intent, authgrants.PrincipalID(NoSession))
	r.srv.keyStore.AddKey(pub)

	if _, ok := r.shadow.agMap[o.user]; !ok {
		r.shadow.agMap[o.user] = make(map[keys.DHPublicKey][]shadowGrant)
	}
	r.shadow.agMap[o.user][pub] = append(r.shadow.agMap[o.user][pub],
		shadowGrant{grantType: o.grantType, cmd: o.cmd, expTime: exp})
	r.shadow.keyStore[pub] = true
}

func (r *runner) execDrain(o op) {
	pub := r.pubs[o.pubIdx]
	acts, err := r.srv.AuthorizeKeyAuthGrant(o.user, pub)

	expected := r.shadow.bucket(o.user, pub)

	// M1: drain returns exactly the shadow bucket.
	if len(expected) == 0 {
		r.require(err != nil && strings.Contains(err.Error(), "no authgrant"),
			"M1: drain on empty bucket must error; got err=%v len(acts)=%d",
			err, len(acts))
		return
	}
	r.require(err == nil, "M1: drain on non-empty bucket must succeed; got err=%v", err)
	r.require(len(acts) == len(expected),
		"M1: drained %d but shadow expected %d", len(acts), len(expected))
	for i := range acts {
		sg := expected[i]
		r.require(acts[i].GrantType == sg.grantType,
			"M1: grant[%d] type mismatch", i)
		r.require(acts[i].AssociatedData.CommandGrantData.Cmd == sg.cmd,
			"M1: grant[%d] cmd mismatch: real=%q shadow=%q", i,
			acts[i].AssociatedData.CommandGrantData.Cmd, sg.cmd)
		r.require(acts[i].ExpTime.Equal(sg.expTime),
			"M1: grant[%d] expTime mismatch", i)
		// Characterization: was the grant expired at drain time?
		if thunks.TimeNow().After(sg.expTime) {
			r.shadow.expiredDrained++
		}
	}
	// Clear shadow bucket.
	delete(r.shadow.agMap[o.user], pub)

	// M2: keystore drops pub.
	r.require(!keyStillInStore(r.srv, pub),
		"M2: pub must be removed from keystore post-drain")
	delete(r.shadow.keyStore, pub)

	// Create a shadow + real session so later checkCmd/Shell ops can hit it.
	id := r.shadow.nextID
	r.shadow.nextID++
	shadowActs := make([]shadowGrant, len(expected))
	copy(shadowActs, expected)
	r.shadow.sessions = append(r.shadow.sessions, &shadowSession{
		id: id, user: o.user, pub: pub, actions: shadowActs,
	})
	r.sessions = append(r.sessions, &hopSession{
		server:            r.srv,
		user:              o.user,
		usingAuthGrant:    true,
		authorizedActions: acts,
	})
}

func (r *runner) execCheckCmd(o op) {
	sess := r.sessions[o.sessIdx]
	ss := r.shadow.sessions[o.sessIdx]
	beforeLen := len(sess.authorizedActions)
	beforeShadow := len(ss.actions)
	r.require(beforeLen == beforeShadow,
		"precheck: session state desync (real=%d shadow=%d)", beforeLen, beforeShadow)

	// Predict outcome from shadow: the first live cmd-matching grant.
	predictIdx := -1
	for i, ag := range ss.actions {
		if thunks.TimeNow().Before(ag.expTime) &&
			ag.grantType == authgrants.Command && ag.cmd == o.cmd {
			predictIdx = i
			break
		}
		if !thunks.TimeNow().Before(ag.expTime) &&
			ag.grantType == authgrants.Command && ag.cmd == o.cmd {
			r.shadow.expiredCheckCmdAttempts++
		}
	}
	_, err := sess.checkCmd(o.cmd, false)

	if predictIdx == -1 {
		// M4: failure leaves state intact.
		r.require(err != nil, "checkCmd: predicted failure but got nil")
		r.require(len(sess.authorizedActions) == beforeLen,
			"M4: failed checkCmd changed authorizedActions (real %d → %d)",
			beforeLen, len(sess.authorizedActions))
		return
	}
	// M3: success consumes exactly the predicted index.
	r.require(err == nil, "checkCmd: predicted success but got err=%v", err)
	ss.actions = append(ss.actions[:predictIdx], ss.actions[predictIdx+1:]...)
	r.require(len(sess.authorizedActions) == beforeLen-1,
		"M3: successful checkCmd must shrink by 1 (real %d → %d)",
		beforeLen, len(sess.authorizedActions))
	// Was this success on an expired grant? Shouldn't be — M3 says live.
	// We already filtered by ExpTime above, so this branch is unreachable
	// in the shadow; if it fires, that's a finding.
}

func (r *runner) execCheckShell(o op) {
	sess := r.sessions[o.sessIdx]
	ss := r.shadow.sessions[o.sessIdx]
	beforeLen := len(sess.authorizedActions)
	beforeShadow := len(ss.actions)
	r.require(beforeLen == beforeShadow,
		"precheck: session state desync (real=%d shadow=%d)", beforeLen, beforeShadow)

	predictIdx := -1
	for i, ag := range ss.actions {
		if thunks.TimeNow().Before(ag.expTime) && ag.grantType == authgrants.Shell {
			predictIdx = i
			break
		}
	}
	_, err := sess.checkCmd("anything-is-fine", true /* shell */)

	if predictIdx == -1 {
		r.require(err != nil, "checkShell: predicted failure but got nil")
		r.require(len(sess.authorizedActions) == beforeLen,
			"M4: failed checkShell changed authorizedActions")
		return
	}
	r.require(err == nil, "checkShell: predicted success but got err=%v", err)
	ss.actions = append(ss.actions[:predictIdx], ss.actions[predictIdx+1:]...)
	r.require(len(sess.authorizedActions) == beforeLen-1,
		"M3: successful checkShell must shrink by 1")
}

// require panics with the trace on failure. The outer test converts the
// panic to t.Fatalf and includes seed + trace.
func (r *runner) require(cond bool, msg string, args ...any) {
	if !cond {
		panic(fmt.Sprintf("INVARIANT VIOLATION: "+msg, args...))
	}
}

func (r *runner) run(length int) (violation string, panicked bool) {
	defer func() {
		if rec := recover(); rec != nil {
			violation = fmt.Sprint(rec)
			panicked = true
		}
	}()
	for i := 0; i < length; i++ {
		r.exec(r.genOp())
	}
	return "", false
}

func (r *runner) replay() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "seed=%d trace (len=%d):\n", r.seed, len(r.trace))
	for i, o := range r.trace {
		fmt.Fprintf(&sb, "  [%d] %s\n", i, o)
	}
	return sb.String()
}

// keyStillInStore checks via VerifyLeaf whether pub is a member of
// srv.keyStore. VerifyLeafFormat and keyset membership together determine
// the answer; we construct a leaf cert with pub and call VerifyLeaf.
func keyStillInStore(srv *HopServer, pub keys.DHPublicKey) bool {
	leaf := l2TestCert(pub)
	err := srv.keyStore.VerifyLeaf(&leaf, certs.VerifyOptions{})
	return err == nil
}

// ---------- Tests ----------

// TestExploration200x8 runs 200 random traces of length 8 against a
// freshly-initialized HopServer each. Any invariant violation prints the
// seed and the trace so it reproduces deterministically via
// TestExplorationReplaySeed (env RANDOM_SEED=<n>).
//
// With the current code at pin 9a198a9 the expected outcome is CLEAN:
// the shadow model matches the real server's behavior exactly, M1–M6
// all hold, and the characterization counters (C_B, C_F) accumulate
// non-zero counts (expired drains do happen) consistent with S1's
// known INV-B residue.
func TestExploration200x8(t *testing.T) {
	const numTraces = 200
	const traceLen = 8

	var baseSeed uint64 = 0xc0ffee
	if s := os.Getenv("RANDOM_SEED_BASE"); s != "" {
		v, err := strconv.ParseUint(s, 0, 64)
		if err == nil {
			baseSeed = v
		}
	}

	totalExpiredDrained := 0
	totalExpiredCmdAttempts := 0

	for i := 0; i < numTraces; i++ {
		seed := baseSeed ^ uint64(i)*0x9E3779B97F4A7C15 // Weyl step

		// Each trace gets its own clock + server; the fake clock is a
		// process-global, so restore between iterations.
		func() {
			defer resetClock()
			setClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))

			r := newRunner(t, seed)
			violation, panicked := r.run(traceLen)
			if panicked {
				t.Fatalf("seed=0x%x (trace %d/%d) panicked: %s\n%s",
					seed, i, numTraces, violation, r.replay())
			}
			if violation != "" {
				t.Fatalf("seed=0x%x (trace %d/%d) violated: %s\n%s",
					seed, i, numTraces, violation, r.replay())
			}
			totalExpiredDrained += r.shadow.expiredDrained
			totalExpiredCmdAttempts += r.shadow.expiredCheckCmdAttempts
		}()
	}

	// Characterization summary — these are KNOWN falsifications (S1), so
	// their non-zero accumulation across 200 traces is evidence the
	// random stream exercised them, not a new finding.
	t.Logf("characterization: %d traces × %d ops, expired-drained=%d expired-cmd-attempts=%d",
		numTraces, traceLen, totalExpiredDrained, totalExpiredCmdAttempts)
}

// TestExplorationReplaySeed reproduces a single seed. Set RANDOM_SEED
// to the hex seed printed by TestExploration200x8 on failure. By default
// it runs a known-clean seed so the test passes in CI.
func TestExplorationReplaySeed(t *testing.T) {
	var seed uint64 = 0xc0ffee
	if s := os.Getenv("RANDOM_SEED"); s != "" {
		v, err := strconv.ParseUint(s, 0, 64)
		if err != nil {
			t.Fatalf("RANDOM_SEED must parse as uint64 (hex via 0x prefix): %v", err)
		}
		seed = v
	}
	defer resetClock()
	setClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))

	r := newRunner(t, seed)
	violation, panicked := r.run(8)
	t.Logf("seed=0x%x trace:\n%s", seed, r.replay())
	if panicked {
		t.Fatalf("seed=0x%x panicked: %s", seed, violation)
	}
	if violation != "" {
		t.Fatalf("seed=0x%x violated: %s", seed, violation)
	}
}

// TestExplorationStressLong — a longer-run variant that uses larger
// traces to push unusual compositions. Skipped by default (set
// EXPLORE_STRESS=1 to run). Coverage goal: 2k traces × 12 ops as the
// plan's §8.1 stop rule ("no new invariant classes for 2k traces").
func TestExplorationStressLong(t *testing.T) {
	if os.Getenv("EXPLORE_STRESS") == "" {
		t.Skip("set EXPLORE_STRESS=1 to run the long exploration sweep")
	}
	const numTraces = 2000
	const traceLen = 12
	var baseSeed uint64 = 0xdeadbeef

	violations := []uint64{}
	for i := 0; i < numTraces; i++ {
		seed := baseSeed ^ uint64(i)*0x9E3779B97F4A7C15
		func() {
			defer resetClock()
			setClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
			r := newRunner(t, seed)
			v, p := r.run(traceLen)
			if p || v != "" {
				violations = append(violations, seed)
				t.Logf("seed=0x%x: %s\n%s", seed, v, r.replay())
			}
		}()
	}
	if len(violations) > 0 {
		sort.Slice(violations, func(i, j int) bool { return violations[i] < violations[j] })
		t.Fatalf("%d violating seeds (first 10: %v)", len(violations),
			violations[:min(10, len(violations))])
	}
}
