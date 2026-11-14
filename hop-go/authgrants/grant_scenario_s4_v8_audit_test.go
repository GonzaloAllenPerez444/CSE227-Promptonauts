package authgrants

// S4 companion: AST-level audit of V8.
//
// V8 (verified fact from plan §2):
//   In principal.go's doIntentRequestChecks, the follow-up-intent path
//   (else branch of `if !p.targetConnected`) invokes p.checkIntent as a
//   statement whose return value is discarded.
//
// This test parses principal.go, finds the else branch, and asserts the
// checkIntent call appears there as a bare ExprStmt (return error not
// captured, not inspected, not gating subsequent statements). If someone
// later wraps the call in `if err := ...; err != nil { return ... }` or
// otherwise consumes the error, this test will fail — the signal to
// revisit the S4 finding.
//
// We assert via source structure rather than runtime behavior because the
// alternative (observing the bug by denying intent-2 and watching the
// target store it) is exactly what TestS4_FollowUpIntentApprovalDiscarded
// already does; this audit adds a *stability* claim — the bug persists at
// the AST level — complementing the behavioral assertion.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"gotest.tools/assert"
)

func TestS4_V8_AuditFollowUpIntentCheckIntentReturnDiscarded(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "principal.go", nil, 0)
	assert.NilError(t, err, "parse principal.go")

	fn := findFunc(file, "doIntentRequestChecks")
	assert.Assert(t, fn != nil,
		"could not locate (*principalInstance).doIntentRequestChecks in principal.go")

	// Locate the `if !p.targetConnected { ... } else { ... }` statement.
	ifs := findTopLevelIfWithElse(fn)
	assert.Assert(t, ifs != nil,
		"expected a top-level if/else inside doIntentRequestChecks "+
			"(the targetConnected gate); principal.go layout has changed — re-verify S4")

	elseBlock, ok := ifs.Else.(*ast.BlockStmt)
	assert.Assert(t, ok, "expected else to be a block statement")

	// Scan the else body for any invocation of checkIntent. For V8 to hold,
	// such invocation must be a bare ExprStmt whose value is discarded — not
	// an AssignStmt capturing the error and not inside an IfStmt controlled
	// by the error.
	foundCall := false
	for _, stmt := range elseBlock.List {
		if isBareCheckIntentCall(stmt) {
			foundCall = true
			continue
		}
		// Any OTHER statement that involves checkIntent in the else body is a
		// signal that the discarded-error pattern changed.
		if statementMentionsCheckIntent(stmt) {
			t.Fatalf("V8 may have been fixed: else-branch statement consumes "+
				"checkIntent's return (not a bare ExprStmt): %T. Re-evaluate S4.", stmt)
		}
	}
	assert.Assert(t, foundCall,
		"V8 anchor missing: expected a bare `p.checkIntent(...)` ExprStmt in the else "+
			"branch of doIntentRequestChecks; principal.go layout changed — re-verify S4")
}

// --- helpers ---

func findFunc(file *ast.File, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == name {
			return fd
		}
	}
	return nil
}

// findTopLevelIfWithElse returns the first IfStmt directly in fn.Body with a
// non-nil Else field.
func findTopLevelIfWithElse(fn *ast.FuncDecl) *ast.IfStmt {
	for _, stmt := range fn.Body.List {
		if ifs, ok := stmt.(*ast.IfStmt); ok && ifs.Else != nil {
			return ifs
		}
	}
	return nil
}

// isBareCheckIntentCall reports whether stmt is `*.checkIntent(...)` as an
// ExprStmt — i.e., the call's return value is thrown away.
func isBareCheckIntentCall(stmt ast.Stmt) bool {
	es, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return false
	}
	ce, ok := es.X.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := ce.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return sel.Sel != nil && sel.Sel.Name == "checkIntent"
}

// statementMentionsCheckIntent walks stmt and returns true if any descendant
// is a selector or identifier named "checkIntent". Used to catch patterns
// where the else branch has been refactored to use the return value.
func statementMentionsCheckIntent(stmt ast.Stmt) bool {
	found := false
	ast.Inspect(stmt, func(n ast.Node) bool {
		if found {
			return false
		}
		switch v := n.(type) {
		case *ast.SelectorExpr:
			if v.Sel != nil && v.Sel.Name == "checkIntent" {
				found = true
				return false
			}
		case *ast.Ident:
			if v.Name == "checkIntent" {
				found = true
				return false
			}
		}
		return true
	})
	return found
}
