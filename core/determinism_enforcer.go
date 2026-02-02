/*
Determinism enforcement for GSAS primitives.
*/

package core

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// NonDeterministicPrimitiveError is raised when a primitive is detected as non-deterministic
type NonDeterministicPrimitiveError struct {
	msg string
}

func (e *NonDeterministicPrimitiveError) Error() string {
	return e.msg
}

// DeterminismEnforcer enforces determinism in governance primitives
type DeterminismEnforcer struct{}

// BannedImports lists imports that violate determinism
var BannedImports = []string{
	"time", "datetime", "random", "os", "sys",
	"socket", "urllib", "requests", "subprocess",
	"threading", "multiprocessing", "asyncio",
}

// BannedFunctions lists function calls that violate determinism
var BannedFunctions = []string{
	"time.Now", "time.Since", "time.Until", "time.Sleep",
	"rand.Int", "rand.Float", "rand.Intn", "rand.Read",
	"os.Getenv", "os.Setenv", "os.Open", "os.Create",
	"os.ReadFile", "os.WriteFile", "os.Remove",
	"net.Dial", "net.Listen", "http.Get", "http.Post",
	"exec.Command", "fmt.Print", "fmt.Println",
	"log.Print", "log.Println", "log.Printf",
}

// ValidateDeterministic validates that Go source code is deterministic
// Uses pattern matching for cross-language compatibility
func (de *DeterminismEnforcer) ValidateDeterministic(sourceCode string) error {
	if strings.TrimSpace(sourceCode) == "" {
		return &NonDeterministicPrimitiveError{msg: "empty source code"}
	}

	var violations []string

	// Check for banned imports
	for _, imp := range BannedImports {
		patterns := []string{
			fmt.Sprintf(`import\s+"%s"`, regexp.QuoteMeta(imp)),
			fmt.Sprintf(`import\s+%s\b`, regexp.QuoteMeta(imp)),
			fmt.Sprintf(`from\s+%s\s+import`, regexp.QuoteMeta(imp)),
		}
		for _, pattern := range patterns {
			re := regexp.MustCompile(pattern)
			if re.MatchString(sourceCode) {
				violations = append(violations, fmt.Sprintf("Banned import '%s' found", imp))
			}
		}
	}
	// Check for banned function calls
	for _, fn := range BannedFunctions {
		pattern := regexp.QuoteMeta(fn) + `\s*\(`
		re := regexp.MustCompile(pattern)
		if re.MatchString(sourceCode) {
			violations = append(violations, fmt.Sprintf("Banned function '%s' found", fn))
		}
	}

	// Check for __import__ (Python compatibility)
	if strings.Contains(sourceCode, "__import__") {
		violations = append(violations, "Direct __import__ call detected - use import statements instead")
	}

	// Check for global mutable state patterns
	globalMutablePatterns := []string{
		`var\s+\w+\s*=\s*make\s*\(`,      // var x = make(...)
		`var\s+\w+\s*=\s*\[\]`,            // var x = []...
		`var\s+\w+\s*=\s*map\s*\[`,        // var x = map[...]
	}
	for _, pattern := range globalMutablePatterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(sourceCode) {
			violations = append(violations, "Potential global mutable state detected")
			break
		}
	}

	if len(violations) > 0 {
		return &NonDeterministicPrimitiveError{msg: strings.Join(violations, "; ")}
	}
	return nil
}

// ValidatePrimitiveSource validates that a primitive implementation is deterministic
// Requires source code string since Go reflection cannot retrieve source
func (de *DeterminismEnforcer) ValidatePrimitiveSource(sourceCode string) error {
	if sourceCode == "" {
		return errors.New("source code required for validation - Go reflection cannot retrieve source")
	}
	return de.ValidateDeterministic(sourceCode)
}

// ValidatePrimitiveContract validates a primitive implements required interface
func (de *DeterminismEnforcer) ValidatePrimitiveContract(p GovernancePrimitive) error {
	if p == nil {
		return errors.New("primitive cannot be nil")
	}
	if p.Version() == "" {
		return errors.New("primitive must have non-empty version")
	}
	return nil
}