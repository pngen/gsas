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