/*
Determinism enforcement for GSAS primitives.
*/

package core

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strconv"
	"strings"
)

// NonDeterministicPrimitiveError is raised when a primitive is detected as non-deterministic.
type NonDeterministicPrimitiveError struct {
	msg string
}

func (e *NonDeterministicPrimitiveError) Error() string { return e.msg }

// DeterminismEnforcer performs conservative static checks on caller-supplied source.
// It is a validation aid, not a sandbox for already-compiled Go code.
type DeterminismEnforcer struct{}

var bannedImports = [...]string{
	"time", "datetime", "random", "os", "sys", "socket", "urllib", "requests",
	"subprocess", "threading", "multiprocessing", "asyncio", "net", "net/http",
	"math/rand", "crypto/rand", "os/exec", "syscall", "unsafe", "plugin",
}

var bannedFunctions = [...]string{
	"time.Now", "time.Since", "time.Until", "time.Sleep",
	"rand.Int", "rand.Float", "rand.Intn", "rand.Read",
	"os.Getenv", "os.Setenv", "os.Open", "os.Create", "os.ReadFile", "os.WriteFile", "os.Remove",
	"net.Dial", "net.Listen", "http.Get", "http.Post", "exec.Command",
	"fmt.Print", "fmt.Println", "fmt.Printf", "log.Print", "log.Println", "log.Printf",
}

// BannedImports and BannedFunctions are compatibility snapshots. Mutating them does not
// weaken validation; enforcement uses the private immutable tables above.
var BannedImports = append([]string(nil), bannedImports[:]...)
var BannedFunctions = append([]string(nil), bannedFunctions[:]...)

var allowedGoImports = map[string]struct{}{
	"bytes": {}, "crypto/sha256": {}, "encoding/hex": {}, "encoding/json": {},
	"errors": {}, "math": {}, "regexp": {}, "sort": {},
	"strconv": {}, "strings": {}, "unicode": {}, "unicode/utf8": {},
}

var allowedPythonImports = map[string]struct{}{
	"decimal": {}, "fractions": {}, "hashlib": {}, "json": {}, "math": {},
	"re": {}, "typing": {},
}

func isBannedImport(importPath string) bool {
	for _, banned := range bannedImports {
		if importPath == banned || strings.HasPrefix(importPath, banned+"/") {
			return true
		}
	}
	return false
}

// ValidateDeterministic validates source conservatively. Go source is fully parsed;
// malformed source and imports outside the pure allow-list fail closed.
func (de *DeterminismEnforcer) ValidateDeterministic(sourceCode string) error {
	if strings.TrimSpace(sourceCode) == "" {
		return &NonDeterministicPrimitiveError{msg: "empty source code"}
	}

	if regexp.MustCompile(`(?m)^\s*package\s+[A-Za-z_]\w*`).MatchString(sourceCode) {
		return validateDeterministicGo(sourceCode)
	}
	return validateDeterministicScript(sourceCode)
}

func validateDeterministicGo(sourceCode string) error {
	file, err := parser.ParseFile(token.NewFileSet(), "primitive.go", sourceCode, parser.AllErrors)
	if err != nil {
		return &NonDeterministicPrimitiveError{msg: fmt.Sprintf("invalid Go source: %v", err)}
	}

	var violations []string
	aliases := make(map[string]string)
	for _, spec := range file.Imports {
		importPath, unquoteErr := strconv.Unquote(spec.Path.Value)
		if unquoteErr != nil {
			violations = append(violations, "invalid import path")
			continue
		}
		if isBannedImport(importPath) {
			violations = append(violations, fmt.Sprintf("Banned import '%s' found", importPath))
		} else if _, allowed := allowedGoImports[importPath]; !allowed {
			violations = append(violations, fmt.Sprintf("Import '%s' is not on the deterministic allow-list", importPath))
		}
		alias := spec.Name
		if alias == nil {
			parts := strings.Split(importPath, "/")
			aliases[parts[len(parts)-1]] = importPath
		} else if alias.Name == "." || alias.Name == "_" {
			violations = append(violations, fmt.Sprintf("Import '%s' must not use dot or blank aliasing", importPath))
		} else {
			aliases[alias.Name] = importPath
		}
	}

	for _, declaration := range file.Decls {
		switch declaration := declaration.(type) {
		case *ast.GenDecl:
			if declaration.Tok == token.VAR {
				violations = append(violations, "Package-level mutable state is not permitted")
			}
		case *ast.FuncDecl:
			if declaration.Name.Name == "init" {
				violations = append(violations, "init functions are not permitted")
			}
		}
	}

	ast.Inspect(file, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.GoStmt:
			violations = append(violations, "goroutines are not permitted")
		case *ast.CallExpr:
			selector, ok := node.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			identifier, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			qualified := identifier.Name + "." + selector.Sel.Name
			for _, banned := range bannedFunctions {
				if qualified == banned {
					violations = append(violations, fmt.Sprintf("Banned function '%s' found", qualified))
				}
			}
			if importPath, imported := aliases[identifier.Name]; imported && isBannedImport(importPath) {
				violations = append(violations, fmt.Sprintf("Call through banned import '%s' found", importPath))
			}
		}
		return true
	})

	return determinismViolations(violations)
}

func validateDeterministicScript(sourceCode string) error {
	var violations []string
	importPattern := regexp.MustCompile(`(?m)^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import|import\s+([A-Za-z_][\w.]*))`)
	for _, match := range importPattern.FindAllStringSubmatch(sourceCode, -1) {
		importPath := match[1]
		if importPath == "" {
			importPath = match[2]
		}
		root := strings.Split(importPath, ".")[0]
		if isBannedImport(root) {
			violations = append(violations, fmt.Sprintf("Banned import '%s' found", importPath))
		} else if _, allowed := allowedPythonImports[root]; !allowed {
			violations = append(violations, fmt.Sprintf("Import '%s' is not on the deterministic allow-list", importPath))
		}
	}
	if strings.Contains(sourceCode, "__import__") {
		violations = append(violations, "Direct __import__ call detected")
	}
	for _, fn := range bannedFunctions {
		if regexp.MustCompile(regexp.QuoteMeta(fn) + `\s*\(`).MatchString(sourceCode) {
			violations = append(violations, fmt.Sprintf("Banned function '%s' found", fn))
		}
	}
	for _, pattern := range []string{
		`(?m)^\s*global\s+`, `(?m)^\s*nonlocal\s+`, `\bopen\s*\(`,
		`\beval\s*\(`, `\bexec\s*\(`,
	} {
		if regexp.MustCompile(pattern).MatchString(sourceCode) {
			violations = append(violations, "Mutable or dynamic external operation detected")
		}
	}
	return determinismViolations(violations)
}

func determinismViolations(violations []string) error {
	if len(violations) == 0 {
		return nil
	}
	return &NonDeterministicPrimitiveError{msg: strings.Join(violations, "; ")}
}

// ValidatePrimitiveSource validates a primitive implementation's supplied source.
func (de *DeterminismEnforcer) ValidatePrimitiveSource(sourceCode string) error {
	if strings.TrimSpace(sourceCode) == "" {
		return errors.New("source code required for validation - Go reflection cannot retrieve source")
	}
	return de.ValidateDeterministic(sourceCode)
}

// ValidatePrimitiveContract validates the minimum static primitive contract.
func (de *DeterminismEnforcer) ValidatePrimitiveContract(p GovernancePrimitive) error {
	if primitiveIsNil(p) {
		return errors.New("primitive cannot be nil")
	}
	version, err := safePrimitiveVersion(p)
	if err != nil {
		return err
	}
	if strings.TrimSpace(version) == "" {
		return errors.New("primitive must have non-empty version")
	}
	return nil
}
