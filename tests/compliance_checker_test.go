/*
Unit tests for compliance checker.
*/

package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gsas/core"
)

type BadVersionPrimitive struct{}

func (b *BadVersionPrimitive) Version() string { return "" }
func (b *BadVersionPrimitive) Evaluate(ctx interface{}) map[string]interface{} {
	return map[string]interface{}{"valid": true}
}

type BadEvaluatePrimitive struct{}

func (b *BadEvaluatePrimitive) Version() string { return "1.0.0" }
func (b *BadEvaluatePrimitive) Evaluate(ctx interface{}) map[string]interface{} {
	return map[string]interface{}{"wrong_key": true}
}

type NonBoolValidPrimitive struct{}

func (b *NonBoolValidPrimitive) Version() string { return "1.0.0" }
func (b *NonBoolValidPrimitive) Evaluate(ctx interface{}) map[string]interface{} {
	return map[string]interface{}{"valid": "true"}
}

type StatefulPrimitive struct {
	state bool
}

type AliasedAlternatingPrimitive struct {
	result map[string]interface{}
	calls  int
}

func (p *AliasedAlternatingPrimitive) Version() string { return "1.0.0" }
func (p *AliasedAlternatingPrimitive) Evaluate(ctx interface{}) map[string]interface{} {
	p.calls++
	p.result["valid"] = p.calls%2 == 0
	return p.result
}

type TypeAlternatingPrimitive struct {
	calls int
}

func (p *TypeAlternatingPrimitive) Version() string { return "1.0.0" }
func (p *TypeAlternatingPrimitive) Evaluate(ctx interface{}) map[string]interface{} {
	p.calls++
	var value interface{} = int64(1)
	if p.calls%2 == 0 {
		value = float64(1)
	}
	return map[string]interface{}{
		"valid": true, "metadata": map[string]interface{}{"value": value}, "evidence": []interface{}{},
	}
}

func (p *StatefulPrimitive) Version() string { return "1.0.0" }
func (p *StatefulPrimitive) Evaluate(ctx interface{}) map[string]interface{} {
	p.state = !p.state
	return map[string]interface{}{
		"valid":    p.state,
		"metadata": map[string]interface{}{},
		"evidence": []interface{}{},
	}
}

func TestComplianceCheckerValidPrimitive(t *testing.T) {
	checker := core.NewComplianceChecker()
	p := &MockPrimitive{name: "valid", version: "1.0.0", valid: true}

	report, err := checker.CheckPrimitive(p)

	assert.NoError(t, err)
	assert.True(t, report.Compliant)
	assert.Empty(t, report.Violations)
}

func TestComplianceCheckerEmptyVersion(t *testing.T) {
	checker := core.NewComplianceChecker()
	p := &BadVersionPrimitive{}

	report, err := checker.CheckPrimitive(p)

	assert.NoError(t, err)
	assert.False(t, report.Compliant)
	assert.Len(t, report.Violations, 1)
	assert.Contains(t, report.Violations[0].Details, "non-empty")
}

func TestComplianceCheckerNilPrimitive(t *testing.T) {
	checker := core.NewComplianceChecker()
	_, err := checker.CheckPrimitive(nil)
	assert.Error(t, err)
}

func TestComplianceCheckerRejectsNonBoolValid(t *testing.T) {
	checker := core.NewComplianceChecker()
	p := &NonBoolValidPrimitive{}

	report, err := checker.CheckPrimitive(p)

	assert.NoError(t, err)
	assert.False(t, report.Compliant)
	assert.Contains(t, report.Violations[0].Details, "boolean")
}

func TestComplianceCheckerRejectsEmptyAndNondeterministicDeployment(t *testing.T) {
	checker := core.NewComplianceChecker()

	empty, err := checker.CheckAll(nil)
	assert.NoError(t, err)
	assert.False(t, empty.Compliant)
	assert.Contains(t, empty.Violations[0].Requirement, "non_empty")

	report, err := checker.CheckPrimitive(&StatefulPrimitive{})
	assert.NoError(t, err)
	assert.False(t, report.Compliant)
	assert.Contains(t, report.Violations[0].Requirement, "repeatability")
}

func TestComplianceSnapshotsFirstResultAndPreservesValueTypes(t *testing.T) {
	checker := core.NewComplianceChecker()
	aliased := &AliasedAlternatingPrimitive{result: map[string]interface{}{
		"valid": false, "metadata": map[string]interface{}{}, "evidence": []interface{}{},
	}}

	for _, primitive := range []core.GovernancePrimitive{aliased, &TypeAlternatingPrimitive{}} {
		report, err := checker.CheckPrimitive(primitive)
		assert.NoError(t, err)
		assert.False(t, report.Compliant)
		assert.Contains(t, report.Violations[0].Requirement, "repeatability")
	}
}
