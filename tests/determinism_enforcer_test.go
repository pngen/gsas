/*
Unit tests for determinism enforcer - Go code validation.
*/

package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gsas/core"
)

func TestValidDeterministicGoCode(t *testing.T) {
	validCode := `
package main

func evaluate(ctx map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"valid": true}
}
`
	enforcer := &core.DeterminismEnforcer{}
	err := enforcer.ValidateDeterministic(validCode)
	assert.NoError(t, err)
}

func TestBannedImportTimeGo(t *testing.T) {
	invalidCode := `
package main

import "time"

func evaluate() {
	_ = time.Now()
}
`
	enforcer := &core.DeterminismEnforcer{}
	err := enforcer.ValidateDeterministic(invalidCode)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "time")
}

func TestBannedImportBlockGo(t *testing.T) {
	invalidCode := `
package main

import (
	"os"
)

func evaluate() map[string]interface{} {
	return map[string]interface{}{"valid": true, "path": os.Args}
}
`
	enforcer := &core.DeterminismEnforcer{}
	err := enforcer.ValidateDeterministic(invalidCode)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "os")
}

func TestBannedImportAliasGo(t *testing.T) {
	invalidCode := `
package main

import r "math/rand"

func evaluate() map[string]interface{} {
	return map[string]interface{}{"valid": true, "value": r.Int()}
}
`
	enforcer := &core.DeterminismEnforcer{}
	err := enforcer.ValidateDeterministic(invalidCode)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "math/rand")
}

func TestBannedFunctionTimeNow(t *testing.T) {
	invalidCode := `
package main

func doSomething() {
	t := time.Now()
	_ = t
}
`
	enforcer := &core.DeterminismEnforcer{}
	err := enforcer.ValidateDeterministic(invalidCode)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "time.Now")
}

func TestBannedFunctionRand(t *testing.T) {
	invalidCode := `
package main

func doSomething() {
	x := rand.Intn(100)
	_ = x
}
`
	enforcer := &core.DeterminismEnforcer{}
	err := enforcer.ValidateDeterministic(invalidCode)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rand.Intn")
}

func TestPythonCompatBannedImport(t *testing.T) {
	invalidCode := `
from time import time

def evaluate():
    return time()
`
	enforcer := &core.DeterminismEnforcer{}
	err := enforcer.ValidateDeterministic(invalidCode)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "time")
}

func TestPythonDirectImport(t *testing.T) {
	invalidCode := `
def evaluate():
    t = __import__('time')
    return t.time()
`
	enforcer := &core.DeterminismEnforcer{}
	err := enforcer.ValidateDeterministic(invalidCode)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "__import__")
}

func TestEmptySourceCode(t *testing.T) {
	enforcer := &core.DeterminismEnforcer{}
	err := enforcer.ValidateDeterministic("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestEmptySourceCodeWhitespace(t *testing.T) {
	enforcer := &core.DeterminismEnforcer{}
	err := enforcer.ValidateDeterministic("   \n\t  ")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestValidatePrimitiveContractNil(t *testing.T) {
	enforcer := &core.DeterminismEnforcer{}
	err := enforcer.ValidatePrimitiveContract(nil)
	assert.Error(t, err)
}

func TestDeterminismRulesCannotBeDisabledByExportedCompatibilitySlices(t *testing.T) {
	original := append([]string(nil), core.BannedImports...)
	core.BannedImports = nil
	t.Cleanup(func() { core.BannedImports = original })

	enforcer := &core.DeterminismEnforcer{}
	assert.Error(t, enforcer.ValidateDeterministic(`package primitive
import "time"
func evaluate() int64 { return time.Now().UnixNano() }
`))
}

func TestDeterminismValidationRejectsMalformedAndUntrustedGoImports(t *testing.T) {
	enforcer := &core.DeterminismEnforcer{}
	assert.Error(t, enforcer.ValidateDeterministic("package primitive\nfunc broken("))
	assert.Error(t, enforcer.ValidateDeterministic(`package primitive
import "example.com/wrapper"
func evaluate() bool { return wrapper.Allow() }
`))
}

func TestDeterminismValidationRejectsPackageStateAndGoroutines(t *testing.T) {
	enforcer := &core.DeterminismEnforcer{}
	assert.Error(t, enforcer.ValidateDeterministic(`package primitive
var counter int
func evaluate() bool { counter++; return counter > 0 }
`))
	assert.Error(t, enforcer.ValidateDeterministic(`package primitive
func evaluate() bool { go func(){}(); return true }
`))
}
