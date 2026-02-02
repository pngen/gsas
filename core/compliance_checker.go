/*
Compliance checker for GSAS governance primitives.

Validates that primitives and deployments satisfy governance contracts.
*/

package core

import (
	"errors"
	"fmt"
)

// ComplianceViolation represents a single compliance violation
type ComplianceViolation struct {
	Primitive   string `json:"primitive"`
	Requirement string `json:"requirement"`
	Details     string `json:"details"`
}

func (cv *ComplianceViolation) Error() string {
	return fmt.Sprintf("[%s] %s: %s", cv.Primitive, cv.Requirement, cv.Details)
}

// ComplianceReport contains results of compliance checking
type ComplianceReport struct {
	Compliant  bool                  `json:"compliant"`
	Violations []ComplianceViolation `json:"violations"`
	Checked    []string              `json:"checked"`
}

// ComplianceChecker validates governance primitives against contracts
type ComplianceChecker struct {
	enforcer *DeterminismEnforcer
}

// NewComplianceChecker creates a new compliance checker
func NewComplianceChecker() *ComplianceChecker {
	return &ComplianceChecker{
		enforcer: &DeterminismEnforcer{},
	}
}

// CheckPrimitive validates a single primitive
func (cc *ComplianceChecker) CheckPrimitive(p GovernancePrimitive) (*ComplianceReport, error) {
	if p == nil {
		return nil, errors.New("primitive cannot be nil")
	}

	report := &ComplianceReport{
		Compliant:  true,
		Violations: []ComplianceViolation{},
		Checked:    []string{"version", "evaluate_contract"},
	}

	name := "unknown"
	if np, ok := p.(NamedPrimitive); ok {
		name = np.Name()
	}

	// Check version
	version := p.Version()
	if version == "" {
		report.Compliant = false
		report.Violations = append(report.Violations, ComplianceViolation{
			Primitive:   name,
			Requirement: "version",
			Details:     "Version() must return non-empty string",
		})
	}

	// Check evaluate returns valid structure
	testCtx := NewDeterministicContext(map[string]interface{}{}, 0)
	result := p.Evaluate(testCtx)

	if _, ok := result["valid"]; !ok {
		report.Compliant = false
		report.Violations = append(report.Violations, ComplianceViolation{
			Primitive:   name,
			Requirement: "evaluate_contract",
			Details:     "Evaluate() must return map with 'valid' key",
		})
	}

	return report, nil
}

// CheckAll validates multiple primitives
func (cc *ComplianceChecker) CheckAll(primitives []GovernancePrimitive) (*ComplianceReport, error) {
	combined := &ComplianceReport{Compliant: true, Violations: []ComplianceViolation{}, Checked: []string{}}

	for _, p := range primitives {
		report, err := cc.CheckPrimitive(p)
		if err != nil {
			return nil, err
		}
		if !report.Compliant {
			combined.Compliant = false
			combined.Violations = append(combined.Violations, report.Violations...)
		}
		combined.Checked = append(combined.Checked, report.Checked...)
	}

	return combined, nil
}