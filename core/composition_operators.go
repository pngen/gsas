/*
Primitive composition operators for GSAS.
*/

package core

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

type compositeChildDescriptor struct {
	Identity                 string `json:"identity"`
	Name                     string `json:"name"`
	Type                     string `json:"type"`
	Version                  string `json:"version"`
	SourceFingerprint        string `json:"source_fingerprint,omitempty"`
	ConfigurationFingerprint string `json:"configuration_fingerprint,omitempty"`
	Invalid                  string `json:"invalid,omitempty"`
}

type compositeVersionDescriptor struct {
	Operator  string                     `json:"operator"`
	Threshold int                        `json:"threshold,omitempty"`
	Children  []compositeChildDescriptor `json:"children"`
}

type compositeChildOutcome struct {
	descriptor compositeChildDescriptor
	evidence   map[string]interface{}
	valid      bool
}

type compositeReferenceKey struct {
	typeName string
	pointer  uintptr
}

func clonePrimitives(primitives []GovernancePrimitive) []GovernancePrimitive {
	return append([]GovernancePrimitive(nil), primitives...)
}

func compositePrimitiveType(p GovernancePrimitive) string {
	primitiveType := reflect.TypeOf(p)
	if primitiveType == nil {
		return "<nil>"
	}

	packageType := primitiveType
	for packageType.Kind() == reflect.Ptr {
		packageType = packageType.Elem()
	}
	return fmt.Sprintf("%s@%s", primitiveType.String(), packageType.PkgPath())
}

func describeCompositeChild(p GovernancePrimitive) (compositeChildDescriptor, error) {
	descriptor := compositeChildDescriptor{Type: compositePrimitiveType(p)}
	if primitiveIsNil(p) {
		descriptor.Identity = "invalid:" + descriptor.Type
		descriptor.Invalid = "nil_primitive"
		return descriptor, fmt.Errorf("primitive cannot be nil")
	}

	name, err := safePrimitiveName(p)
	if err != nil {
		descriptor.Identity = "invalid:" + descriptor.Type
		descriptor.Invalid = "name_unavailable"
		return descriptor, err
	}
	if _, named := p.(NamedPrimitive); named && strings.TrimSpace(name) == "" {
		descriptor.Identity = "invalid:" + descriptor.Type
		descriptor.Invalid = "empty_name"
		return descriptor, fmt.Errorf("named primitive must have a non-empty name")
	}

	version, err := safePrimitiveVersion(p)
	if err != nil {
		descriptor.Name = name
		descriptor.Identity = "invalid:" + descriptor.Type
		descriptor.Invalid = "version_unavailable"
		return descriptor, err
	}
	if strings.TrimSpace(version) == "" {
		descriptor.Name = name
		descriptor.Identity = "invalid:" + descriptor.Type
		descriptor.Invalid = "empty_version"
		return descriptor, fmt.Errorf("primitive version cannot be empty")
	}

	descriptor.Name = name
	descriptor.Version = version
	descriptor.SourceFingerprint, err = currentSourceFingerprint(p)
	if err != nil {
		descriptor.Identity = "invalid:" + descriptor.Type
		descriptor.Invalid = "source_unavailable"
		return descriptor, err
	}
	descriptor.ConfigurationFingerprint, err = currentConfigurationFingerprint(p)
	if err != nil {
		descriptor.Identity = "invalid:" + descriptor.Type
		descriptor.Invalid = "configuration_invalid"
		return descriptor, err
	}
	if name != "" {
		descriptor.Identity = "name:" + name
	} else {
		descriptor.Identity = "type:" + descriptor.Type
	}
	return descriptor, nil
}

func descriptorLess(left, right compositeChildDescriptor) bool {
	if left.Identity != right.Identity {
		return left.Identity < right.Identity
	}
	if left.Name != right.Name {
		return left.Name < right.Name
	}
	if left.Type != right.Type {
		return left.Type < right.Type
	}
	if left.Version != right.Version {
		return left.Version < right.Version
	}
	if left.SourceFingerprint != right.SourceFingerprint {
		return left.SourceFingerprint < right.SourceFingerprint
	}
	if left.ConfigurationFingerprint != right.ConfigurationFingerprint {
		return left.ConfigurationFingerprint < right.ConfigurationFingerprint
	}
	return left.Invalid < right.Invalid
}

func describeCompositeChildren(primitives []GovernancePrimitive) ([]compositeChildDescriptor, error) {
	descriptors := make([]compositeChildDescriptor, len(primitives))
	for index, primitive := range primitives {
		descriptor, err := describeCompositeChild(primitive)
		descriptors[index] = descriptor
		if err != nil {
			return descriptors, fmt.Errorf("child %d: %w", index, err)
		}
	}
	return descriptors, nil
}

func validateCompositeConfiguration(
	operator string,
	primitives []GovernancePrimitive,
	threshold int,
	requireUniqueIdentities bool,
) ([]compositeChildDescriptor, error) {
	if len(primitives) == 0 {
		return nil, fmt.Errorf("%s requires at least one primitive", operator)
	}
	if operator == "threshold" && (threshold <= 0 || threshold > len(primitives)) {
		return nil, fmt.Errorf("invalid threshold %d for %d primitives", threshold, len(primitives))
	}
	if requireUniqueIdentities {
		seenReferences := make(map[compositeReferenceKey]struct{}, len(primitives))
		for index, primitive := range primitives {
			if primitiveIsNil(primitive) {
				return nil, fmt.Errorf("child %d: primitive cannot be nil", index)
			}
			value := reflect.ValueOf(primitive)
			switch value.Kind() {
			case reflect.Chan, reflect.Func, reflect.Map, reflect.Ptr, reflect.Slice:
				key := compositeReferenceKey{typeName: value.Type().String(), pointer: value.Pointer()}
				if _, duplicate := seenReferences[key]; duplicate {
					return nil, fmt.Errorf("child %d repeats the same concrete primitive", index)
				}
				seenReferences[key] = struct{}{}
			}
		}
	}

	descriptors, err := describeCompositeChildren(primitives)
	if err != nil {
		return descriptors, err
	}
	if requireUniqueIdentities {
		seen := make(map[string]struct{}, len(descriptors))
		for index, descriptor := range descriptors {
			if _, exists := seen[descriptor.Identity]; exists {
				return descriptors, fmt.Errorf("child %d duplicates primitive identity %q", index, descriptor.Identity)
			}
			seen[descriptor.Identity] = struct{}{}
		}
	}
	return descriptors, nil
}

func compositeVersion(
	operator string,
	threshold int,
	primitives []GovernancePrimitive,
	orderIndependent bool,
) string {
	descriptors := make([]compositeChildDescriptor, len(primitives))
	for index, primitive := range primitives {
		descriptor, _ := describeCompositeChild(primitive)
		descriptors[index] = descriptor
	}
	if orderIndependent {
		sort.Slice(descriptors, func(i, j int) bool {
			return descriptorLess(descriptors[i], descriptors[j])
		})
	}

	payload, err := json.Marshal(compositeVersionDescriptor{
		Operator:  operator,
		Threshold: threshold,
		Children:  descriptors,
	})
	if err != nil {
		// All descriptor fields are strings and integers, so this protects the
		// Version contract without creating an authorization fallback.
		payload = []byte(operator + ":invalid_descriptor")
	}
	digest := sha256.Sum256(payload)
	return fmt.Sprintf("%s-sha256-%x", operator, digest)
}

func invalidCompositeResult(reason string) map[string]interface{} {
	return map[string]interface{}{
		"valid": false,
		"metadata": map[string]interface{}{
			"reason": reason,
		},
		"evidence": []interface{}{},
	}
}

func compositeChildLabel(descriptor compositeChildDescriptor, index int) string {
	if descriptor.Name != "" {
		return descriptor.Name
	}
	if descriptor.Identity != "" {
		return descriptor.Identity
	}
	return fmt.Sprintf("primitive_%d", index)
}

func evaluateCompositeChild(
	primitive GovernancePrimitive,
	descriptor compositeChildDescriptor,
	index int,
	context interface{},
) compositeChildOutcome {
	record := map[string]interface{}{
		"index":    index,
		"identity": descriptor.Identity,
		"name":     descriptor.Name,
		"type":     descriptor.Type,
		"version":  descriptor.Version,
	}

	result, err := safePrimitiveEvaluation(primitive, context)
	if err == nil {
		result, err = normalizeEvaluationResult(result)
	}
	if err == nil {
		var after compositeChildDescriptor
		after, err = describeCompositeChild(primitive)
		if err == nil && after != descriptor {
			err = fmt.Errorf("primitive identity or version changed during evaluation")
		}
	}
	if err != nil {
		record["error"] = err.Error()
		record["result"] = map[string]interface{}{
			"valid":    false,
			"metadata": map[string]interface{}{"reason": err.Error()},
			"evidence": []interface{}{},
		}
		return compositeChildOutcome{descriptor: descriptor, evidence: record, valid: false}
	}

	record["result"] = result
	valid := result["valid"].(bool)
	return compositeChildOutcome{descriptor: descriptor, evidence: record, valid: valid}
}

func outcomesAsEvidence(outcomes []compositeChildOutcome, orderIndependent bool) []interface{} {
	ordered := append([]compositeChildOutcome(nil), outcomes...)
	if orderIndependent {
		sort.SliceStable(ordered, func(i, j int) bool {
			if descriptorLess(ordered[i].descriptor, ordered[j].descriptor) {
				return true
			}
			if descriptorLess(ordered[j].descriptor, ordered[i].descriptor) {
				return false
			}
			left, _ := canonicalPrimitiveJSON(ordered[i].evidence["result"])
			right, _ := canonicalPrimitiveJSON(ordered[j].evidence["result"])
			return string(left) < string(right)
		})
	}
	evidence := make([]interface{}, len(ordered))
	for index := range ordered {
		record := make(map[string]interface{}, len(ordered[index].evidence))
		for key, value := range ordered[index].evidence {
			record[key] = value
		}
		if orderIndependent {
			record["index"] = index
		}
		evidence[index] = record
	}
	return evidence
}

// PrimitiveComposer composes primitives with explicit semantics.
type PrimitiveComposer struct{}

// SequentialAnd returns a primitive that requires all input primitives to pass in order.
func (pc *PrimitiveComposer) SequentialAnd(primitives []GovernancePrimitive) GovernancePrimitive {
	return &sequentialAndPrimitive{primitives: clonePrimitives(primitives)}
}

type sequentialAndPrimitive struct {
	primitives []GovernancePrimitive
}

func (p *sequentialAndPrimitive) Version() string {
	return compositeVersion("sequential-and", 0, p.primitives, false)
}

func (p *sequentialAndPrimitive) ValidateConfiguration() error {
	_, err := validateCompositeConfiguration("sequential-and", p.primitives, 0, false)
	return err
}

func (p *sequentialAndPrimitive) ConfigurationFingerprint() string { return p.Version() }

func (p *sequentialAndPrimitive) Evaluate(context interface{}) map[string]interface{} {
	descriptors, err := validateCompositeConfiguration("sequential-and", p.primitives, 0, false)
	if err != nil {
		return invalidCompositeResult(fmt.Sprintf("Invalid sequential composition: %v", err))
	}

	outcomes := make([]compositeChildOutcome, 0, len(p.primitives))
	for index, primitive := range p.primitives {
		outcome := evaluateCompositeChild(primitive, descriptors[index], index, context)
		outcomes = append(outcomes, outcome)
		if !outcome.valid {
			return map[string]interface{}{
				"valid": false,
				"metadata": map[string]interface{}{
					"reason":       fmt.Sprintf("Primitive %s failed", compositeChildLabel(outcome.descriptor, index)),
					"failed_index": index,
				},
				"evidence": outcomesAsEvidence(outcomes, false),
			}
		}
	}

	return map[string]interface{}{
		"valid": true,
		"metadata": map[string]interface{}{
			"message": "All primitives passed sequentially",
		},
		"evidence": outcomesAsEvidence(outcomes, false),
	}
}

// ParallelAnd returns a primitive that requires all input primitives to pass, order independent.
func (pc *PrimitiveComposer) ParallelAnd(primitives []GovernancePrimitive) GovernancePrimitive {
	return &parallelAndPrimitive{primitives: clonePrimitives(primitives)}
}

type parallelAndPrimitive struct {
	primitives []GovernancePrimitive
}

func (p *parallelAndPrimitive) Version() string {
	return compositeVersion("parallel-and", 0, p.primitives, true)
}

func (p *parallelAndPrimitive) ValidateConfiguration() error {
	_, err := validateCompositeConfiguration("parallel-and", p.primitives, 0, false)
	return err
}

func (p *parallelAndPrimitive) ConfigurationFingerprint() string { return p.Version() }

func (p *parallelAndPrimitive) Evaluate(context interface{}) map[string]interface{} {
	descriptors, err := validateCompositeConfiguration("parallel-and", p.primitives, 0, false)
	if err != nil {
		return invalidCompositeResult(fmt.Sprintf("Invalid parallel composition: %v", err))
	}

	outcomes := make([]compositeChildOutcome, len(p.primitives))
	failed := make([]string, 0)
	for index, primitive := range p.primitives {
		outcomes[index] = evaluateCompositeChild(primitive, descriptors[index], index, context)
		if !outcomes[index].valid {
			failed = append(failed, compositeChildLabel(outcomes[index].descriptor, index))
		}
	}
	sort.Strings(failed)

	if len(failed) != 0 {
		return map[string]interface{}{
			"valid": false,
			"metadata": map[string]interface{}{
				"reason": fmt.Sprintf("Failed primitives: %v", failed),
			},
			"evidence": outcomesAsEvidence(outcomes, true),
		}
	}
	return map[string]interface{}{
		"valid": true,
		"metadata": map[string]interface{}{
			"message": "All primitives passed in parallel",
		},
		"evidence": outcomesAsEvidence(outcomes, true),
	}
}

// Threshold returns a primitive that requires at least k unique input primitives to pass.
func (pc *PrimitiveComposer) Threshold(primitives []GovernancePrimitive, k int) GovernancePrimitive {
	return &thresholdPrimitive{primitives: clonePrimitives(primitives), k: k}
}

type thresholdPrimitive struct {
	primitives []GovernancePrimitive
	k          int
}

func (p *thresholdPrimitive) Version() string {
	return compositeVersion("threshold", p.k, p.primitives, true)
}

func (p *thresholdPrimitive) ValidateConfiguration() error {
	_, err := validateCompositeConfiguration("threshold", p.primitives, p.k, true)
	return err
}

func (p *thresholdPrimitive) ConfigurationFingerprint() string { return p.Version() }

func (p *thresholdPrimitive) Evaluate(context interface{}) map[string]interface{} {
	descriptors, err := validateCompositeConfiguration("threshold", p.primitives, p.k, true)
	if err != nil {
		return invalidCompositeResult(fmt.Sprintf("Invalid threshold composition: %v", err))
	}

	outcomes := make([]compositeChildOutcome, len(p.primitives))
	passedCount := 0
	for index, primitive := range p.primitives {
		outcomes[index] = evaluateCompositeChild(primitive, descriptors[index], index, context)
		if outcomes[index].valid {
			passedCount++
		}
	}

	if passedCount < p.k {
		return map[string]interface{}{
			"valid": false,
			"metadata": map[string]interface{}{
				"reason": fmt.Sprintf("Only %d of %d primitives passed, need at least %d", passedCount, len(p.primitives), p.k),
			},
			"evidence": outcomesAsEvidence(outcomes, true),
		}
	}
	return map[string]interface{}{
		"valid": true,
		"metadata": map[string]interface{}{
			"message": fmt.Sprintf("%d of %d primitives passed", passedCount, len(p.primitives)),
		},
		"evidence": outcomesAsEvidence(outcomes, true),
	}
}
