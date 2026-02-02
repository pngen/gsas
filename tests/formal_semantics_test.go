/*
Unit tests for formal semantics.
*/

package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gsas/core"
)

func TestDeterministicContext(t *testing.T) {
	ctx := &core.DeterministicContextSpec{
		Time: 123,
		Data: map[string]interface{}{"key": "value"},
	}

	assert.Equal(t, 123, ctx.Time)
	assert.Equal(t, "value", ctx.Get("key", nil))
	val, err := ctx.GetItem("key")
	assert.NoError(t, err)
	assert.Equal(t, "value", val)
}

func TestGovernanceSignal(t *testing.T) {
	signal := &core.GovernanceSignalSpec{
		Name:   "test_primitive",
		Valid:  true,
		Metadata: map[string]interface{}{"reason": "test"},
	}

	assert.Equal(t, "test_primitive", signal.Name)
	assert.True(t, signal.Valid)
	assert.Equal(t, "test", signal.Metadata["reason"])
}

func TestCompositeGovernanceDecision(t *testing.T) {
	signal := &core.GovernanceSignalSpec{
		Name:   "test_primitive",
		Valid:  true,
		Metadata: map[string]interface{}{},
	}

	decision := &core.CompositeGovernanceDecisionSpec{
		Permitted:     true,
		Signals:       []core.GovernanceSignalSpec{*signal},
		FailureReasons: []string{},
		Proof:         map[string]interface{}{},
	}

	assert.True(t, decision.Permitted)
	assert.Len(t, decision.Signals, 1)
	assert.Len(t, decision.FailureReasons, 0)
}

func TestDeterministicContextImpl(t *testing.T) {
	data := map[string]interface{}{
		"key1": "value1",
		"key2": map[string]interface{}{"nested": "data"},
	}
	ctx := core.NewDeterministicContext(data, 42)

	assert.Equal(t, 42, ctx.Time())
	assert.Equal(t, "value1", ctx.Get("key1", nil))
	assert.Equal(t, "default", ctx.Get("nonexistent", "default"))
	assert.True(t, ctx.Has("key1"))
	assert.False(t, ctx.Has("nonexistent"))

	// Test immutability - original data mutation shouldn't affect context
	data["key1"] = "mutated"
	assert.Equal(t, "value1", ctx.Get("key1", nil))
}

func TestDeterministicContextImmutability(t *testing.T) {
	ctx := core.NewDeterministicContext(map[string]interface{}{"x": 1}, 0)

	err := ctx.SetItem("y", 2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "immutable")

	err = ctx.DeleteItem("x")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "immutable")
}

func TestDeterministicContextGetItem(t *testing.T) {
	ctx := core.NewDeterministicContext(map[string]interface{}{"x": 1}, 0)

	val, err := ctx.GetItem("x")
	assert.NoError(t, err)
	assert.Equal(t, float64(1), val) // JSON unmarshaling converts to float64
}