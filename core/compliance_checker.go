/*
Compliance checker for GSAS governance primitives.
*/

package core

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

// ComplianceViolation represents a single compliance violation.
type ComplianceViolation struct {
	Primitive   string `json:"primitive"`
	Requirement string `json:"requirement"`
	Details     string `json:"details"`
}

func (cv *ComplianceViolation) Error() string {
	return fmt.Sprintf("[%s] %s: %s", cv.Primitive, cv.Requirement, cv.Details)
}

// ComplianceReport contains results of compliance checking.
type ComplianceReport struct {
	Compliant  bool                  `json:"compliant"`
	Violations []ComplianceViolation `json:"violations"`
	Checked    []string              `json:"checked"`
}

// ComplianceChecker validates governance primitives against contracts.
type ComplianceChecker struct {
	enforcer *DeterminismEnforcer
}

func NewComplianceChecker() *ComplianceChecker {
	return &ComplianceChecker{enforcer: &DeterminismEnforcer{}}
}

// CheckPrimitive validates static identity, the complete result schema, and
// repeatability on an identical immutable probe context. Source-aware primitives
// also receive conservative static source validation.
func (cc *ComplianceChecker) CheckPrimitive(p GovernancePrimitive) (*ComplianceReport, error) {
	if primitiveIsNil(p) {
		return nil, errors.New("primitive cannot be nil")
	}

	name := "unknown"
	if candidate, nameErr := safePrimitiveName(p); nameErr != nil {
		return &ComplianceReport{
			Compliant: false,
			Violations: []ComplianceViolation{{
				Primitive: "unknown", Requirement: "identity", Details: nameErr.Error(),
			}},
			Checked: []string{"identity"},
		}, nil
	} else if strings.TrimSpace(candidate) != "" {
		name = strings.TrimSpace(candidate)
	}
	report := &ComplianceReport{
		Compliant:  true,
		Violations: []ComplianceViolation{},
		Checked:    []string{"version", "evaluate_contract", "repeatability"},
	}
	addViolation := func(requirement, details string) {
		report.Compliant = false
		report.Violations = append(report.Violations, ComplianceViolation{
			Primitive: name, Requirement: requirement, Details: details,
		})
	}

	version, err := safePrimitiveVersion(p)
	if err != nil {
		addViolation("version", err.Error())
		return report, nil
	}
	if strings.TrimSpace(version) == "" {
		addViolation("version", "Version() must return non-empty string")
		return report, nil
	}
	if configurable, ok := p.(ConfigurablePrimitive); ok {
		report.Checked = append(report.Checked, "configuration")
		if err := safePrimitiveConfiguration(configurable); err != nil {
			addViolation("configuration", err.Error())
			return report, nil
		}
		fingerprinted, ok := p.(FingerprintedConfigurablePrimitive)
		if !ok {
			addViolation("configuration", "configurable primitives must expose a configuration fingerprint")
			return report, nil
		}
		firstFingerprint, err := safeConfigurationFingerprint(fingerprinted)
		if err != nil {
			addViolation("configuration", err.Error())
			return report, nil
		}
		secondFingerprint, err := safeConfigurationFingerprint(fingerprinted)
		if err != nil || secondFingerprint != firstFingerprint {
			if err != nil {
				addViolation("configuration", err.Error())
			} else {
				addViolation("configuration", "configuration fingerprint is not stable")
			}
			return report, nil
		}
	}

	if sourcePrimitive, ok := p.(SourceGovernancePrimitive); ok {
		report.Checked = append(report.Checked, "deterministic_source")
		source, err := safePrimitiveSource(sourcePrimitive)
		if err == nil {
			err = cc.enforcer.ValidatePrimitiveSource(source)
		}
		if err != nil {
			addViolation("deterministic_source", err.Error())
		}
	}

	testContext := NewDeterministicContext(map[string]interface{}{}, 0)
	first, firstErr := safePrimitiveEvaluation(p, testContext)
	if firstErr != nil {
		addViolation("evaluate_contract", firstErr.Error())
		return report, nil
	}
	firstNormalized, firstErr := normalizeEvaluationResult(first)
	if firstErr != nil {
		addViolation("evaluate_contract", firstErr.Error())
		return report, nil
	}
	firstCanonical, firstErr := canonicalPrimitiveJSON(firstNormalized)
	if firstErr != nil {
		addViolation("evaluate_contract", firstErr.Error())
		return report, nil
	}

	second, secondErr := safePrimitiveEvaluation(p, testContext)
	if secondErr != nil {
		addViolation("evaluate_contract", secondErr.Error())
		return report, nil
	}
	secondNormalized, secondErr := normalizeEvaluationResult(second)
	if secondErr != nil {
		addViolation("evaluate_contract", secondErr.Error())
		return report, nil
	}
	secondCanonical, secondErr := canonicalPrimitiveJSON(secondNormalized)
	if secondErr != nil {
		addViolation("evaluate_contract", secondErr.Error())
		return report, nil
	}
	if !bytes.Equal(firstCanonical, secondCanonical) {
		addViolation("repeatability", "Evaluate returned different results for identical context")
	}

	return report, nil
}

// CheckAll validates a non-empty deployment. Absence of governance is itself a
// compliance violation rather than a vacuous success.
func (cc *ComplianceChecker) CheckAll(primitives []GovernancePrimitive) (*ComplianceReport, error) {
	combined := &ComplianceReport{Compliant: true, Violations: []ComplianceViolation{}, Checked: []string{}}
	if len(primitives) == 0 {
		combined.Compliant = false
		combined.Checked = append(combined.Checked, "non_empty_deployment")
		combined.Violations = append(combined.Violations, ComplianceViolation{
			Primitive: "deployment", Requirement: "non_empty_deployment", Details: "at least one governance primitive is required",
		})
		return combined, nil
	}

	for _, primitive := range primitives {
		report, err := cc.CheckPrimitive(primitive)
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
