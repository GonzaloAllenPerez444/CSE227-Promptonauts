package hopserver

// S1 companion: AST-level audit of V11.
//
// V11 (verified fact from plan §2):
//   Only ExecTube is grant-gated; PF and AuthGrant tube branches in
//   hopSession.start() have no action-expiry / grant-set check.
//
// This test parses session.go, finds the switch in start(), and asserts that
// the PFControlTube / PFTube / AuthGrantTube / WinSizeTube case bodies do not
// invoke checkCmd. If someone later adds that gate (e.g. upstream fix), this
// test will fail — which is the signal to revisit the S1 zombie finding.
//
// We assert via source structure rather than runtime behavior because the
// alternative (driving a real tubeMuxer over a transport handle) requires
// scaffolding orders of magnitude heavier than the finding — see plan §11
// ("prefer asserting via public behavior over adding instrumentation").

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"gotest.tools/assert"
)

func TestS1_V11_AuditPFDispatchUngated(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "session.go", nil, 0)
	assert.NilError(t, err, "parse session.go")

	start := findMethod(file, "hopSession", "start")
	assert.Assert(t, start != nil, "could not locate (*hopSession).start in session.go")

	// Find the outer-most TypeSwitch/Switch that dispatches on tube.Type().
	// hopSession.start uses a type-assertion on `r, ok := tube.(*tubes.Reliable)`
	// and then a `switch tube.Type()`. Walk the body and find that inner switch.
	cases := extractTubeTypeCases(start)
	assert.Assert(t, len(cases) > 0, "expected non-zero case clauses in start()'s tube-type switch")

	// Collect which case labels we encountered.
	seen := map[string]bool{}
	for _, c := range cases {
		for _, lbl := range c.labels {
			seen[lbl] = true
		}
		// Any branch that is NOT the ExecTube branch must not reference
		// checkCmd — that is the whole point of V11.
		if containsLabel(c.labels, "ExecTube") {
			continue
		}
		assert.Assert(t, !c.calls("checkCmd"),
			"V11 would be broken: case %v calls checkCmd. Re-evaluate S1 zombie finding.", c.labels)
	}

	// Sanity: the specific labels S1 names as ungated must have been present.
	for _, lbl := range []string{"PFControlTube", "PFTube", "AuthGrantTube"} {
		assert.Assert(t, seen[lbl],
			"expected case %q in hopSession.start() dispatch; session.go layout changed — re-verify S1", lbl)
	}
}

// --- helpers ---

type caseClause struct {
	labels []string // selector names like "ExecTube", "PFControlTube"
	body   []ast.Stmt
}

func (c caseClause) calls(name string) bool {
	found := false
	for _, s := range c.body {
		ast.Inspect(s, func(n ast.Node) bool {
			if found {
				return false
			}
			ce, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fn := ce.Fun.(type) {
			case *ast.Ident:
				if fn.Name == name {
					found = true
				}
			case *ast.SelectorExpr:
				if fn.Sel != nil && fn.Sel.Name == name {
					found = true
				}
			}
			return !found
		})
	}
	return found
}

func containsLabel(labels []string, want string) bool {
	for _, l := range labels {
		if l == want {
			return true
		}
	}
	return false
}

// findMethod locates a method FuncDecl whose receiver type name matches recv
// and whose method name matches name.
func findMethod(file *ast.File, recv, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Recv == nil || fd.Name.Name != name {
			continue
		}
		if len(fd.Recv.List) == 0 {
			continue
		}
		rt := fd.Recv.List[0].Type
		if star, ok := rt.(*ast.StarExpr); ok {
			rt = star.X
		}
		if id, ok := rt.(*ast.Ident); ok && id.Name == recv {
			return fd
		}
	}
	return nil
}

// extractTubeTypeCases finds the *inner* switch statement that dispatches on
// `tube.Type()` inside the given function and returns its case clauses with
// the selector-name labels (e.g. common.ExecTube → "ExecTube").
func extractTubeTypeCases(fn *ast.FuncDecl) []caseClause {
	var out []caseClause
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		// Heuristic: the tube-type switch's Tag is a call expression to
		// tube.Type (an ast.CallExpr whose Fun is SelectorExpr with .Sel.Name == "Type").
		if !switchesOnTubeType(sw) {
			return true
		}
		for _, stmt := range sw.Body.List {
			cc, ok := stmt.(*ast.CaseClause)
			if !ok {
				continue
			}
			labels := make([]string, 0, len(cc.List))
			for _, e := range cc.List {
				if sel, ok := e.(*ast.SelectorExpr); ok && sel.Sel != nil {
					labels = append(labels, sel.Sel.Name)
				}
			}
			out = append(out, caseClause{labels: labels, body: cc.Body})
		}
		return false
	})
	return out
}

func switchesOnTubeType(sw *ast.SwitchStmt) bool {
	if sw.Tag == nil {
		return false
	}
	ce, ok := sw.Tag.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := ce.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return sel.Sel != nil && sel.Sel.Name == "Type"
}
