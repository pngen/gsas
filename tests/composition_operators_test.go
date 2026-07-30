/*
Unit tests for composition operators.
*/

package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gsas/core"
)

type compositionTestPrimitive struct {
	name                   string
	version                string
	result                 map[string]interface{}
	panicOnName            bool
	panicOnVersion         bool
	panicOnEvaluate        bool
	versionAfterEvaluation string
}

func (p *compositionTestPrimitive) Name() string {
	if p.panicOnName {
		panic("name failure")
	}
	return p.name
}

func (p *compositionTestPrimitive) Version() string {
	if p.panicOnVersion {
		panic("version failure")
	}
	return p.version
}

func (p *compositionTestPrimitive) Evaluate(context interface{}) map[string]interface{} {
	if p.panicOnEvaluate {
		panic("evaluation failure")
	}
	if p.versionAfterEvaluation != "" {
		p.version = p.versionAfterEvaluation
	}
	return p.result
}

type secondCompositionPrimitiveType struct {
	name    string
	version string
}

type alternatingNamePrimitive struct {
	calls int
}

type interfacePayloadPrimitive struct {
	payload interface{}
}

func (interfacePayloadPrimitive) Name() string    { return "interface-payload" }
func (interfacePayloadPrimitive) Version() string { return "1.0" }
func (interfacePayloadPrimitive) Evaluate(context interface{}) map[string]interface{} {
	return validCompositionResult("interface-payload", true)
}

func (p *alternatingNamePrimitive) Name() string {
	p.calls++
	if p.calls%2 == 0 {
		return "authority-b"
	}
	return "authority-a"
}
func (p *alternatingNamePrimitive) Version() string { return "1.0" }
func (p *alternatingNamePrimitive) Evaluate(context interface{}) map[string]interface{} {
	return validCompositionResult("authority", true)
}

func (p *secondCompositionPrimitiveType) Name() string    { return p.name }
func (p *secondCompositionPrimitiveType) Version() string { return p.version }
func (p *secondCompositionPrimitiveType) Evaluate(context interface{}) map[string]interface{} {
	return map[string]interface{}{
		"valid":    true,
		"metadata": map[string]interface{}{"source": "second-type"},
		"evidence": []interface{}{},
	}
}

func validCompositionResult(label string, valid bool) map[string]interface{} {
	return map[string]interface{}{
		"valid":    valid,
		"metadata": map[string]interface{}{"label": label},
		"evidence": []interface{}{"receipt-" + label},
	}
}

func compositionVariants(composer *core.PrimitiveComposer, child core.GovernancePrimitive) map[string]core.GovernancePrimitive {
	return map[string]core.GovernancePrimitive{
		"sequential": composer.SequentialAnd([]core.GovernancePrimitive{child}),
		"parallel":   composer.ParallelAnd([]core.GovernancePrimitive{child}),
		"threshold":  composer.Threshold([]core.GovernancePrimitive{child}, 1),
	}
}

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

func TestSequentialAndCopiesPrimitiveSlice(t *testing.T) {
	composer := &core.PrimitiveComposer{}

	primitives := []core.GovernancePrimitive{
		&MockPrimitive{name: "pass", version: "1.0", valid: true},
	}
	composed := composer.SequentialAnd(primitives)
	primitives[0] = &MockPrimitive{name: "fail_after_compose", version: "1.0", valid: false}

	result := composed.Evaluate(nil)
	assert.True(t, result["valid"].(bool))
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

func TestThresholdInvalidKFailsClosed(t *testing.T) {
	composer := &core.PrimitiveComposer{}

	primitives := []core.GovernancePrimitive{
		&MockPrimitive{name: "a", version: "1.0", valid: false},
	}

	zeroThreshold := composer.Threshold(primitives, 0)
	assert.False(t, zeroThreshold.Evaluate(nil)["valid"].(bool))

	impossibleThreshold := composer.Threshold(primitives, 2)
	assert.False(t, impossibleThreshold.Evaluate(nil)["valid"].(bool))
}

func TestEmptyAndCompositionsFailClosed(t *testing.T) {
	composer := &core.PrimitiveComposer{}

	composites := map[string]core.GovernancePrimitive{
		"sequential": composer.SequentialAnd(nil),
		"parallel":   composer.ParallelAnd(nil),
	}
	for name, composite := range composites {
		t.Run(name, func(t *testing.T) {
			configurable, ok := composite.(core.ConfigurablePrimitive)
			require.True(t, ok)
			assert.Error(t, configurable.ValidateConfiguration())

			result := composite.Evaluate(nil)
			assert.Equal(t, false, result["valid"])
		})
	}
}

func TestCompositionsFailClosedForInvalidChildren(t *testing.T) {
	composer := &core.PrimitiveComposer{}
	var typedNil *compositionTestPrimitive

	children := map[string]core.GovernancePrimitive{
		"typed_nil": typedNil,
		"panic_name": &compositionTestPrimitive{
			name:        "panic-name",
			version:     "1.0",
			panicOnName: true,
			result:      validCompositionResult("panic-name", true),
		},
		"panic_version": &compositionTestPrimitive{
			name:           "panic-version",
			version:        "1.0",
			panicOnVersion: true,
			result:         validCompositionResult("panic-version", true),
		},
		"panic_evaluate": &compositionTestPrimitive{
			name:            "panic-evaluate",
			version:         "1.0",
			panicOnEvaluate: true,
		},
		"malformed_result": &compositionTestPrimitive{
			name:    "malformed",
			version: "1.0",
			result:  map[string]interface{}{"valid": true},
		},
	}

	for childName, child := range children {
		for operator, composite := range compositionVariants(composer, child) {
			t.Run(childName+"/"+operator, func(t *testing.T) {
				assert.NotPanics(t, func() { _ = composite.Version() })
				var result map[string]interface{}
				assert.NotPanics(t, func() { result = composite.Evaluate(nil) })
				require.NotNil(t, result)
				assert.Equal(t, false, result["valid"])
			})
		}
	}
}

func TestCompositionRejectsChildIdentityDriftDuringEvaluation(t *testing.T) {
	composer := &core.PrimitiveComposer{}
	child := &compositionTestPrimitive{
		name:                   "mutable",
		version:                "1.0",
		versionAfterEvaluation: "2.0",
		result:                 validCompositionResult("mutable", true),
	}

	result := composer.SequentialAnd([]core.GovernancePrimitive{child}).Evaluate(nil)
	assert.Equal(t, false, result["valid"])
	assert.Contains(t, result["metadata"].(map[string]interface{})["reason"], "mutable")
}

func TestCompositeVersionsBindOperatorChildIdentityTypeVersionAndBoundaries(t *testing.T) {
	composer := &core.PrimitiveComposer{}
	a := &MockPrimitive{name: "a", version: "1", valid: true}
	b := &MockPrimitive{name: "b", version: "23", valid: true}
	aWithDifferentBoundary := &MockPrimitive{name: "a", version: "12", valid: true}
	bWithDifferentBoundary := &MockPrimitive{name: "b", version: "3", valid: true}

	sequential := composer.SequentialAnd([]core.GovernancePrimitive{a, b})
	assert.NotEqual(t,
		sequential.Version(),
		composer.SequentialAnd([]core.GovernancePrimitive{aWithDifferentBoundary, bWithDifferentBoundary}).Version(),
	)
	assert.NotEqual(t,
		composer.SequentialAnd([]core.GovernancePrimitive{
			&MockPrimitive{name: "auth", version: "1.0", valid: true},
		}).Version(),
		composer.SequentialAnd([]core.GovernancePrimitive{
			&MockPrimitive{name: "billing", version: "1.0", valid: true},
		}).Version(),
	)
	assert.NotEqual(t,
		composer.SequentialAnd([]core.GovernancePrimitive{
			&compositionTestPrimitive{name: "same", version: "1.0", result: validCompositionResult("first", true)},
		}).Version(),
		composer.SequentialAnd([]core.GovernancePrimitive{
			&secondCompositionPrimitiveType{name: "same", version: "1.0"},
		}).Version(),
	)
	assert.NotEqual(t, sequential.Version(), composer.ParallelAnd([]core.GovernancePrimitive{a, b}).Version())
	assert.NotEqual(t,
		composer.Threshold([]core.GovernancePrimitive{a, b}, 1).Version(),
		composer.Threshold([]core.GovernancePrimitive{a, b}, 2).Version(),
	)
}

func TestCompositeVersionOrderingMatchesOperatorSemantics(t *testing.T) {
	composer := &core.PrimitiveComposer{}
	a := &MockPrimitive{name: "a", version: "1", valid: true}
	b := &MockPrimitive{name: "b", version: "2", valid: true}

	assert.NotEqual(t,
		composer.SequentialAnd([]core.GovernancePrimitive{a, b}).Version(),
		composer.SequentialAnd([]core.GovernancePrimitive{b, a}).Version(),
	)
	assert.Equal(t,
		composer.ParallelAnd([]core.GovernancePrimitive{a, b}).Version(),
		composer.ParallelAnd([]core.GovernancePrimitive{b, a}).Version(),
	)
	assert.Equal(t,
		composer.Threshold([]core.GovernancePrimitive{a, b}, 1).Version(),
		composer.Threshold([]core.GovernancePrimitive{b, a}, 1).Version(),
	)
}

func TestOrderIndependentCompositeEvidenceIsCanonical(t *testing.T) {
	composer := &core.PrimitiveComposer{}
	a := &compositionTestPrimitive{name: "a", version: "1", result: validCompositionResult("a", true)}
	b := &compositionTestPrimitive{name: "b", version: "2", result: validCompositionResult("b", true)}

	parallelAB := composer.ParallelAnd([]core.GovernancePrimitive{a, b}).Evaluate(nil)
	parallelBA := composer.ParallelAnd([]core.GovernancePrimitive{b, a}).Evaluate(nil)
	assert.Equal(t, parallelAB, parallelBA)

	thresholdAB := composer.Threshold([]core.GovernancePrimitive{a, b}, 1).Evaluate(nil)
	thresholdBA := composer.Threshold([]core.GovernancePrimitive{b, a}, 1).Evaluate(nil)
	assert.Equal(t, thresholdAB, thresholdBA)
}

func TestThresholdRejectsDuplicatePrimitiveIdentity(t *testing.T) {
	composer := &core.PrimitiveComposer{}
	approval := &MockPrimitive{name: "approval", version: "1.0", valid: true}
	threshold := composer.Threshold([]core.GovernancePrimitive{approval, approval}, 2)

	configurable, ok := threshold.(core.ConfigurablePrimitive)
	require.True(t, ok)
	assert.Error(t, configurable.ValidateConfiguration())
	assert.Equal(t, false, threshold.Evaluate(nil)["valid"])

	alternating := &alternatingNamePrimitive{}
	threshold = composer.Threshold([]core.GovernancePrimitive{alternating, alternating}, 2)
	assert.Error(t, threshold.(core.ConfigurablePrimitive).ValidateConfiguration())
	assert.Equal(t, false, threshold.Evaluate(nil)["valid"])
}

func TestThresholdDoesNotPanicOnDynamicallyUnhashableValuePrimitive(t *testing.T) {
	primitive := interfacePayloadPrimitive{payload: []int{1}}
	threshold := (&core.PrimitiveComposer{}).Threshold([]core.GovernancePrimitive{primitive}, 1)

	assert.NotPanics(t, func() {
		assert.NoError(t, threshold.(core.ConfigurablePrimitive).ValidateConfiguration())
		assert.Equal(t, true, threshold.Evaluate(nil)["valid"])
	})
}

func TestCompositionsPreserveChildResultsAndEvidence(t *testing.T) {
	composer := &core.PrimitiveComposer{}
	child := &compositionTestPrimitive{
		name:    "audited-child",
		version: "1.0",
		result:  validCompositionResult("audited-child", true),
	}

	for operator, composite := range compositionVariants(composer, child) {
		t.Run(operator, func(t *testing.T) {
			result := composite.Evaluate(nil)
			require.Equal(t, true, result["valid"])
			evidence, ok := result["evidence"].([]interface{})
			require.True(t, ok)
			require.Len(t, evidence, 1)
			record, ok := evidence[0].(map[string]interface{})
			require.True(t, ok)
			childResult, ok := record["result"].(map[string]interface{})
			require.True(t, ok)
			assert.Equal(t, true, childResult["valid"])
			assert.Equal(t, "audited-child", childResult["metadata"].(map[string]interface{})["label"])
			assert.Equal(t, []interface{}{"receipt-audited-child"}, childResult["evidence"])
		})
	}
}
