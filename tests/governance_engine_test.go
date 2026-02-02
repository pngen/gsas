/*
Unit tests for governance evaluation engine.
*/

package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gsas/core"
)

func TestGovernanceEngineAllPass(t *testing.T) {
	engine := core.NewGovernanceEngine()

	p1 := &MockPrimitive{name: "auth", version: "1.0.0", valid: true}
	p2 := &MockPrimitive{name: "rate_limit", version: "1.0.0", valid: true}

	assert.NoError(t, engine.RegisterPrimitive("auth", p1))
	assert.NoError(t, engine.RegisterPrimitive("rate_limit", p2))

	ctx := core.NewDeterministicContext(map[string]interface{}{}, 0)
	decision := engine.Evaluate(ctx)

	assert.True(t, decision.Permitted)
	assert.Len(t, decision.Signals, 2)
	assert.Empty(t, decision.FailureReasons)
	assert.NotNil(t, decision.Proof)
}

func TestGovernanceEngineFailClosed(t *testing.T) {
	engine := core.NewGovernanceEngine()

	p1 := &MockPrimitive{name: "auth", version: "1.0.0", valid: true}
	p2 := &MockPrimitive{name: "denied", version: "1.0.0", valid: false}
	p3 := &MockPrimitive{name: "never_reached", version: "1.0.0", valid: true}

	engine.RegisterPrimitive("auth", p1)
	engine.RegisterPrimitive("denied", p2)
	engine.RegisterPrimitive("never_reached", p3)

	ctx := core.NewDeterministicContext(map[string]interface{}{}, 0)
	decision := engine.Evaluate(ctx)

	assert.False(t, decision.Permitted)
	assert.Len(t, decision.Signals, 2) // Stops at failure
	assert.Len(t, decision.FailureReasons, 1)
	assert.Contains(t, decision.FailureReasons[0], "denied")
}

func TestGovernanceEngineProofGeneration(t *testing.T) {
	engine := core.NewGovernanceEngine()

	p1 := &MockPrimitive{name: "test", version: "2.0.0", valid: true}
	engine.RegisterPrimitive("test", p1)

	ctx := core.NewDeterministicContext(map[string]interface{}{}, 100)
	decision := engine.EvaluateWithLogicalTime(ctx, 12345)

	assert.NotNil(t, decision.Proof)
	assert.True(t, decision.Proof.Decision)
	assert.Equal(t, int64(12345), decision.Proof.GeneratedAt)
	assert.Contains(t, decision.Proof.PrimitiveVersions, "test")
	assert.Equal(t, "2.0.0", decision.Proof.PrimitiveVersions["test"])
}

func TestGovernanceEngineDuplicateRegistration(t *testing.T) {
	engine := core.NewGovernanceEngine()

	p1 := &MockPrimitive{name: "test", version: "1.0.0", valid: true}
	assert.NoError(t, engine.RegisterPrimitive("test", p1))

	p2 := &MockPrimitive{name: "test2", version: "1.0.0", valid: true}
	err := engine.RegisterPrimitive("test", p2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already registered")
}

func TestGovernanceEngineNilPrimitive(t *testing.T) {
	engine := core.NewGovernanceEngine()
	err := engine.RegisterPrimitive("nil", nil)
	assert.Error(t, err)
}

func TestGovernanceEngineEmptyID(t *testing.T) {
	engine := core.NewGovernanceEngine()
	p := &MockPrimitive{name: "test", version: "1.0.0", valid: true}
	err := engine.RegisterPrimitive("", p)
	assert.Error(t, err)
}

func TestGovernanceEngineClear(t *testing.T) {
	engine := core.NewGovernanceEngine()
	p := &MockPrimitive{name: "test", version: "1.0.0", valid: true}
	engine.RegisterPrimitive("test", p)
	assert.Equal(t, 1, engine.PrimitiveCount())

	engine.Clear()
	assert.Equal(t, 0, engine.PrimitiveCount())
}