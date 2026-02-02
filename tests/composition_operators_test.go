/*
Unit tests for composition operators.
*/

package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gsas/core"
)

func TestSequentialAndAllPass(t *testing.T) {
	composer := &core.PrimitiveComposer{}

	p1 := &MockPrimitive{name: "p1", version: "1.0", valid: true}
	p2 := &MockPrimitive{name: "p2", version: "1.0", valid: true}

	composed := composer.SequentialAnd([]core.GovernancePrimitive{p1, p2})
	result := composed.Evaluate(nil)

	assert.True(t, result["valid"].(bool))
}

func TestSequentialAndFirstFails(t *testing.T) {
	composer := &core.PrimitiveComposer{}

	p1 := &MockPrimitive{name: "fail", version: "1.0", valid: false}
	p2 := &MockPrimitive{name: "pass", version: "1.0", valid: true}

	composed := composer.SequentialAnd([]core.GovernancePrimitive{p1, p2})
	result := composed.Evaluate(nil)

	assert.False(t, result["valid"].(bool))
	meta := result["metadata"].(map[string]interface{})
	assert.Contains(t, meta["reason"], "fail")
}

func TestParallelAndAllPass(t *testing.T) {
	composer := &core.PrimitiveComposer{}

	primitives := []core.GovernancePrimitive{
		&MockPrimitive{name: "a", version: "1.0", valid: true},
		&MockPrimitive{name: "b", version: "1.0", valid: true},
		&MockPrimitive{name: "c", version: "1.0", valid: true},
	}

	composed := composer.ParallelAnd(primitives)
	result := composed.Evaluate(nil)

	assert.True(t, result["valid"].(bool))
}

func TestParallelAndOneFails(t *testing.T) {
	composer := &core.PrimitiveComposer{}

	primitives := []core.GovernancePrimitive{
		&MockPrimitive{name: "pass1", version: "1.0", valid: true},
		&MockPrimitive{name: "fail", version: "1.0", valid: false},
		&MockPrimitive{name: "pass2", version: "1.0", valid: true},
	}

	composed := composer.ParallelAnd(primitives)
	result := composed.Evaluate(nil)

	assert.False(t, result["valid"].(bool))
}

func TestThresholdMet(t *testing.T) {
	composer := &core.PrimitiveComposer{}

	primitives := []core.GovernancePrimitive{
		&MockPrimitive{name: "a", version: "1.0", valid: true},
		&MockPrimitive{name: "b", version: "1.0", valid: false},
		&MockPrimitive{name: "c", version: "1.0", valid: true},
	}

	composed := composer.Threshold(primitives, 2)
	result := composed.Evaluate(nil)

	assert.True(t, result["valid"].(bool))
}

func TestThresholdNotMet(t *testing.T) {
	composer := &core.PrimitiveComposer{}

	primitives := []core.GovernancePrimitive{
		&MockPrimitive{name: "a", version: "1.0", valid: true},
		&MockPrimitive{name: "b", version: "1.0", valid: false},
		&MockPrimitive{name: "c", version: "1.0", valid: false},
	}

	composed := composer.Threshold(primitives, 2)
	result := composed.Evaluate(nil)

	assert.False(t, result["valid"].(bool))
}