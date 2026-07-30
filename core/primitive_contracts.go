/*
Type-safe contracts and fail-closed helpers for GSAS governance primitives.
*/

package core

import (
	"bytes"
	"fmt"
	"math"
	"reflect"
)

// EvaluationResult represents the result returned by governance primitive evaluation.
type EvaluationResult map[string]interface{}

// GovernancePrimitive defines the interface for all governance primitives.
type GovernancePrimitive interface {
	Version() string
	Evaluate(context interface{}) map[string]interface{}
}

// NamedPrimitive extends GovernancePrimitive with a stable name.
type NamedPrimitive interface {
	GovernancePrimitive
	Name() string
}

// SourceGovernancePrimitive can expose the exact source that was validated at
// registration. In-process primitives that do not implement this interface are
// treated as trusted compiled code and are still checked for reproducible output.
type SourceGovernancePrimitive interface {
	GovernancePrimitive
	DeterministicSource() string
}

// ConfigurablePrimitive exposes static composition/configuration validation.
type ConfigurablePrimitive interface {
	GovernancePrimitive
	ValidateConfiguration() error
}

// FingerprintedConfigurablePrimitive binds mutable configuration to a stable
// identifier. Configurable primitives must implement this contract to register.
type FingerprintedConfigurablePrimitive interface {
	ConfigurablePrimitive
	ConfigurationFingerprint() string
}

func primitiveIsNil(p GovernancePrimitive) bool {
	if p == nil {
		return true
	}
	value := reflect.ValueOf(p)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func safePrimitiveVersion(p GovernancePrimitive) (version string, err error) {
	if primitiveIsNil(p) {
		return "", fmt.Errorf("primitive cannot be nil")
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			version = ""
			err = fmt.Errorf("primitive Version panicked: %v", recovered)
		}
	}()
	return p.Version(), nil
}

func safePrimitiveName(p GovernancePrimitive) (name string, err error) {
	if primitiveIsNil(p) {
		return "", fmt.Errorf("primitive cannot be nil")
	}
	named, ok := p.(NamedPrimitive)
	if !ok {
		return "", nil
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			name = ""
			err = fmt.Errorf("primitive Name panicked: %v", recovered)
		}
	}()
	return named.Name(), nil
}

func safePrimitiveSource(p SourceGovernancePrimitive) (source string, err error) {
	if primitiveIsNil(p) {
		return "", fmt.Errorf("primitive cannot be nil")
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			source = ""
			err = fmt.Errorf("primitive DeterministicSource panicked: %v", recovered)
		}
	}()
	return p.DeterministicSource(), nil
}

func safePrimitiveConfiguration(p ConfigurablePrimitive) (err error) {
	if primitiveIsNil(p) {
		return fmt.Errorf("primitive cannot be nil")
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("primitive configuration validation panicked: %v", recovered)
		}
	}()
	return p.ValidateConfiguration()
}

func safeConfigurationFingerprint(p FingerprintedConfigurablePrimitive) (fingerprint string, err error) {
	if primitiveIsNil(p) {
		return "", fmt.Errorf("primitive cannot be nil")
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			fingerprint = ""
			err = fmt.Errorf("primitive ConfigurationFingerprint panicked: %v", recovered)
		}
	}()
	fingerprint = p.ConfigurationFingerprint()
	if fingerprint == "" {
		return "", fmt.Errorf("configuration fingerprint cannot be empty")
	}
	return fingerprint, nil
}

func safePrimitiveEvaluation(p GovernancePrimitive, context interface{}) (result map[string]interface{}, err error) {
	if primitiveIsNil(p) {
		return nil, fmt.Errorf("primitive cannot be nil")
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			result = nil
			err = fmt.Errorf("primitive Evaluate panicked: %v", recovered)
		}
	}()
	return p.Evaluate(context), nil
}

// normalizeEvaluationResult validates the complete signal schema and takes a
// lossless plain-data snapshot so primitive-owned state cannot mutate an audit.
func normalizeEvaluationResult(result map[string]interface{}) (normalized map[string]interface{}, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			normalized = nil
			err = fmt.Errorf("primitive result could not be snapshotted: %v", recovered)
		}
	}()
	if result == nil {
		return nil, fmt.Errorf("Evaluate must return a non-nil result")
	}
	valid, ok := result["valid"].(bool)
	if !ok {
		return nil, fmt.Errorf("Evaluate result must contain boolean 'valid'")
	}
	metadata, exists := result["metadata"]
	if !exists {
		return nil, fmt.Errorf("Evaluate result must contain 'metadata'")
	}
	evidence, exists := result["evidence"]
	if !exists {
		return nil, fmt.Errorf("Evaluate result must contain 'evidence'")
	}

	metadataCopy, err := clonePrimitiveValue(reflect.ValueOf(metadata), 0)
	if err != nil {
		return nil, fmt.Errorf("invalid metadata: %w", err)
	}
	if _, ok := metadataCopy.(map[string]interface{}); !ok {
		return nil, fmt.Errorf("metadata must be an object")
	}
	evidenceCopy, err := clonePrimitiveValue(reflect.ValueOf(evidence), 0)
	if err != nil {
		return nil, fmt.Errorf("invalid evidence: %w", err)
	}
	if _, ok := evidenceCopy.([]interface{}); !ok {
		return nil, fmt.Errorf("evidence must be an array")
	}

	normalized = map[string]interface{}{
		"valid":    valid,
		"metadata": metadataCopy,
		"evidence": evidenceCopy,
	}
	if _, err := canonicalPrimitiveJSON(normalized); err != nil {
		return nil, err
	}
	return normalized, nil
}

func clonePrimitiveValue(value reflect.Value, depth int) (interface{}, error) {
	if depth > 64 {
		return nil, fmt.Errorf("value is cyclic or nested too deeply")
	}
	if !value.IsValid() {
		return nil, nil
	}
	if value.Kind() == reflect.Interface {
		if value.IsNil() {
			return nil, nil
		}
		return clonePrimitiveValue(value.Elem(), depth+1)
	}

	switch value.Kind() {
	case reflect.Bool:
		return value.Interface(), nil
	case reflect.String:
		if value.Type() == jsonNumberType && !validJSONNumber(value.String()) {
			return nil, fmt.Errorf("invalid JSON number %q", value.String())
		}
		return value.Interface(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return value.Interface(), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return value.Interface(), nil
	case reflect.Float32, reflect.Float64:
		floating := value.Float()
		if math.IsNaN(floating) || math.IsInf(floating, 0) {
			return nil, fmt.Errorf("non-finite numbers are not deterministic data")
		}
		return value.Interface(), nil
	case reflect.Map:
		if value.IsNil() {
			return map[string]interface{}{}, nil
		}
		if value.Type().Key().Kind() != reflect.String {
			return nil, fmt.Errorf("object keys must be strings")
		}
		copyMap := make(map[string]interface{}, value.Len())
		iterator := value.MapRange()
		for iterator.Next() {
			key := iterator.Key().String()
			cloned, err := clonePrimitiveValue(iterator.Value(), depth+1)
			if err != nil {
				return nil, fmt.Errorf("field %q: %w", key, err)
			}
			copyMap[key] = cloned
		}
		return copyMap, nil
	case reflect.Slice, reflect.Array:
		if value.Kind() == reflect.Slice && value.IsNil() {
			return []interface{}{}, nil
		}
		copySlice := make([]interface{}, value.Len())
		for index := 0; index < value.Len(); index++ {
			cloned, err := clonePrimitiveValue(value.Index(index), depth+1)
			if err != nil {
				return nil, fmt.Errorf("item %d: %w", index, err)
			}
			copySlice[index] = cloned
		}
		return copySlice, nil
	case reflect.Invalid:
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported value type %s", value.Type())
	}
}

func canonicalPrimitiveJSON(value interface{}) (data []byte, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			data = nil
			err = fmt.Errorf("value canonicalization panicked: %v", recovered)
		}
	}()
	var canonical bytes.Buffer
	writeFrame(&canonical, "GSAS-PRIMITIVE-VALUE-v1")
	if err := writeCanonicalValue(&canonical, reflect.ValueOf(value)); err != nil {
		return nil, fmt.Errorf("value is not canonically serializable: %w", err)
	}
	return canonical.Bytes(), nil
}
