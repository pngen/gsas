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