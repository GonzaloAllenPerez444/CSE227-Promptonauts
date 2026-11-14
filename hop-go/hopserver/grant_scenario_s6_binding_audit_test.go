package hopserver

// S6 companion: AST-level audits of the "Delegate binding" surface.
//
// INV-D requires that consuming a grant require MORE than possession of
// (intent + delegate keypair). In this codebase, the entirety of
// "Delegate binding" at consumption time reduces to two facts, both of
// which are structural in the source:
//
//   F1  AuthorizeKeyAuthGrant's parameter list is exactly
//       (user string, publicKey keys.DHPublicKey) — no caller cert, no
//       transport handle, no origin/session identity.
//   F2  The production grant-add call at hopserver.go:329 passes the
//       sentinel NoSession as the PrincipalID — the grant carries no
//       principal-session back-reference.
//
// If upstream ever changes either of these, the S6 bearer story must be
// re-adjudicated. This file converts those two facts into test-suite
// invariants.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"gotest.tools/assert"
)

// TestS6_F1_DrainAPITakesNoCallerIdentity asserts that
// AuthorizeKeyAuthGrant's parameter list is exactly {user, publicKey} and
// its receiver is *HopServer. If anyone adds a third parameter — e.g., a
// client cert or a transport handle — the test trips and S6's "any holder
// of the key, no identity check" claim must be re-evaluated.
func TestS6_F1_DrainAPITakesNoCallerIdentity(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "target.go", nil, 0)
	assert.NilError(t, err, "parse hopserver/target.go")

	fn := findMethod(file, "HopServer", "AuthorizeKeyAuthGrant")
	assert.Assert(t, fn != nil,
		"could not locate (*HopServer).AuthorizeKeyAuthGrant in target.go")

	// Flatten param list: `(a, b string, c T)` → ["string", "string", "T"].
	var paramTypes []string
	for _, field := range fn.Type.Params.List {
		typeStr := exprString(field.Type)
		n := len(field.Names)
		if n == 0 {
			n = 1 // anonymous
		}
		for i := 0; i < n; i++ {
			paramTypes = append(paramTypes, typeStr)
		}
	}

	assert.DeepEqual(t, paramTypes, []string{"string", "keys.DHPublicKey"})
}

// TestS6_F2_ProductionAddUsesNoSession asserts that (*HopServer).AddAuthGrant
// in hopserver.go stamps PrincipalID(NoSession) when inserting into agMap.
// If someone later introduces a real session ID here (for principal
// back-reference), S6's bearer claim weakens — the target gains a
// caller-identity signal that a defence could use.
func TestS6_F2_ProductionAddUsesNoSession(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "hopserver.go", nil, 0)
	assert.NilError(t, err, "parse hopserver/hopserver.go")

	fn := findMethod(file, "HopServer", "AddAuthGrant")
	assert.Assert(t, fn != nil,
		"could not locate (*HopServer).AddAuthGrant in hopserver.go")

	// Find a call like `*.agMap.AddAuthGrant(intent, authgrants.PrincipalID(X))`
	// and assert X is the identifier "NoSession".
	var inner *ast.CallExpr
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if inner != nil {
			return false
		}
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := ce.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel == nil || sel.Sel.Name != "AddAuthGrant" {
			return true
		}
		inner = ce
		return false
	})
	assert.Assert(t, inner != nil,
		"could not find call to agMap.AddAuthGrant inside HopServer.AddAuthGrant")
	assert.Equal(t, 2, len(inner.Args),
		"agMap.AddAuthGrant should take (intent, principalID)")

	// The second argument is authgrants.PrincipalID(X); drill into the
	// conversion and assert X is the identifier "NoSession".
	conv, ok := inner.Args[1].(*ast.CallExpr)
	assert.Assert(t, ok, "expected PrincipalID(...) conversion as second arg")
	assert.Equal(t, 1, len(conv.Args), "PrincipalID takes one arg")
	id, ok := conv.Args[0].(*ast.Ident)
	assert.Assert(t, ok,
		"expected the PrincipalID argument to be a bare identifier (e.g., NoSession); "+
			"if upstream changed this to `sess.ID` or similar, S6's bearer claim weakens — re-evaluate")
	assert.Equal(t, "NoSession", id.Name,
		"⚠ S6: production AddAuthGrant now stamps a non-NoSession PrincipalID (%q) — "+
			"the target has gained a principal-session back-reference. Re-evaluate INV-D.", id.Name)
}

// --- helpers ---

func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	case *ast.StarExpr:
		return "*" + exprString(v.X)
	case *ast.ArrayType:
		return "[]" + exprString(v.Elt)
	default:
		return ""
	}
}
