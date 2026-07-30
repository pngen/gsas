/*
Proof theory for GSAS governance decisions.
*/

package core

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
)

const (
	// GovernanceProofSchemaVersion identifies the canonical proof envelope schema.
	GovernanceProofSchemaVersion = "gsas-governance-proof/v1"
	deterministicDefaultTime     = int64(0)
)

// GovernanceProof is a self-contained, tamper-evident record of a governance
// decision. It binds the evaluated primitive identities and versions, their
// canonical signals, the decision, failure reasons, logical time, and an
// optional context snapshot under one SHA-256 envelope commitment.
type GovernanceProof struct {
	SchemaVersion string `json:"schema_version"`

	PrimitiveVersions map[string]string `json:"primitive_versions"`
	EvaluationOrder   []string          `json:"evaluation_order"`

	Decision          bool                     `json:"decision"`
	Signals           []map[string]interface{} `json:"signals"`
	SignalCommitments []string                 `json:"signal_commitments"`
	FailureReasons    []string                 `json:"failure_reasons"`

	ContextSnapshot   map[string]interface{} `json:"context_snapshot,omitempty"`
	ContextCommitment string                 `json:"context_commitment,omitempty"`
	GeneratedAt       int64                  `json:"generated_at"`

	EnvelopeCommitment string `json:"envelope_commitment"`
}

type governanceProofEnvelope struct {
	SchemaVersion     string                   `json:"schema_version"`
	PrimitiveVersions map[string]string        `json:"primitive_versions"`
	EvaluationOrder   []string                 `json:"evaluation_order"`
	Decision          bool                     `json:"decision"`
	Signals           []map[string]interface{} `json:"signals"`
	SignalCommitments []string                 `json:"signal_commitments"`
	FailureReasons    []string                 `json:"failure_reasons"`
	ContextIncluded   bool                     `json:"context_included"`
	ContextCommitment string                   `json:"context_commitment"`
	GeneratedAt       int64                    `json:"generated_at"`
}

// Verify checks the complete proof envelope without re-executing primitives.
// The supplied map establishes the expected primitive identities and versions.
func (gp *GovernanceProof) Verify(primitives map[string]GovernancePrimitive) (bool, error) {
	if gp == nil {
		return false, errors.New("proof cannot be nil")
	}
	if gp.SchemaVersion != GovernanceProofSchemaVersion {
		return false, fmt.Errorf("unsupported proof schema %q", gp.SchemaVersion)
	}
	if len(gp.EvaluationOrder) != len(gp.Signals) ||
		len(gp.Signals) != len(gp.SignalCommitments) {
		return false, errors.New("evaluation order, signals, and commitments must have equal lengths")
	}
	if len(gp.PrimitiveVersions) != len(gp.EvaluationOrder) {
		return false, errors.New("primitive versions must contain exactly the evaluated primitives")
	}

	seen := make(map[string]struct{}, len(gp.EvaluationOrder))
	allValid := len(gp.Signals) > 0
	for i, id := range gp.EvaluationOrder {
		if strings.TrimSpace(id) == "" {
			return false, fmt.Errorf("evaluation order contains a blank primitive ID at index %d", i)
		}
		if _, duplicate := seen[id]; duplicate {
			return false, fmt.Errorf("primitive %q appears more than once", id)
		}
		seen[id] = struct{}{}

		version, exists := gp.PrimitiveVersions[id]
		if !exists || strings.TrimSpace(version) == "" {
			return false, fmt.Errorf("proof has no version for evaluated primitive %q", id)
		}

		canonicalSignal, canonicalData, err := cloneStoredSignal(gp.Signals[i])
		if err != nil {
			return false, fmt.Errorf("signal %d is not canonical JSON: %w", i, err)
		}
		valid, err := validateSignal(canonicalSignal, id, version)
		if err != nil {
			return false, fmt.Errorf("signal %d is invalid: %w", i, err)
		}
		if !valid {
			allValid = false
		}

		expectedSignalCommitment := hashBytes(canonicalData)
		if !validSHA256(gp.SignalCommitments[i]) ||
			!equalCommitments(gp.SignalCommitments[i], expectedSignalCommitment) {
			return false, fmt.Errorf("signal %d commitment mismatch", i)
		}

		primitive, exists := primitives[id]
		if !exists {
			return false, fmt.Errorf("primitive %q was not supplied for verification", id)
		}
		actualVersion, err := safePrimitiveVersion(primitive)
		if err != nil {
			return false, fmt.Errorf("cannot validate primitive %q: %w", id, err)
		}
		if actualVersion != version {
			return false, fmt.Errorf(
				"primitive %q version mismatch: proof=%q supplied=%q",
				id,
				version,
				actualVersion,
			)
		}
	}

	if gp.Decision != allValid {
		return false, fmt.Errorf("decision does not match the conjunction of evaluated signals")
	}
	if err := validateFailureReasons(gp.Decision, gp.FailureReasons); err != nil {
		return false, err
	}

	if gp.ContextSnapshot == nil {
		if gp.Decision {
			return false, errors.New("permitted proofs require a bound context")
		}
		if gp.ContextCommitment != "" {
			return false, errors.New("context commitment is present without a context snapshot")
		}
	} else {
		_, contextData, err := cloneStoredContext(gp.ContextSnapshot)
		if err != nil {
			return false, fmt.Errorf("context snapshot is not canonical JSON: %w", err)
		}
		expectedContextCommitment := hashBytes(contextData)
		if !validSHA256(gp.ContextCommitment) ||
			!equalCommitments(gp.ContextCommitment, expectedContextCommitment) {
			return false, errors.New("context commitment mismatch")
		}
	}

	if !validSHA256(gp.EnvelopeCommitment) {
		return false, errors.New("invalid envelope commitment")
	}
	expectedEnvelopeCommitment, err := gp.computeEnvelopeCommitment()
	if err != nil {
		return false, fmt.Errorf("cannot recompute proof envelope: %w", err)
	}
	if !equalCommitments(gp.EnvelopeCommitment, expectedEnvelopeCommitment) {
		return false, errors.New("proof envelope commitment mismatch")
	}

	return true, nil
}

// ReconstructContext returns a defensive copy of the bound context snapshot.
// The index argument is retained for source compatibility and is intentionally
// ignored: proofs no longer fabricate per-index context data.
func (gp *GovernanceProof) ReconstructContext(index int) map[string]interface{} {
	_ = index
	if gp == nil || gp.ContextSnapshot == nil || !validSHA256(gp.ContextCommitment) {
		return map[string]interface{}{}
	}
	contextCopy, contextData, err := cloneStoredContext(gp.ContextSnapshot)
	if err != nil || !equalCommitments(gp.ContextCommitment, hashBytes(contextData)) {
		return map[string]interface{}{}
	}
	expectedEnvelopeCommitment, err := gp.computeEnvelopeCommitment()
	if err != nil || !equalCommitments(gp.EnvelopeCommitment, expectedEnvelopeCommitment) {
		return map[string]interface{}{}
	}
	return contextCopy
}

// CommitSignal creates a commitment for compatibility with the original API.
// Invalid signals return an empty string; security-sensitive callers must use
// CommitSignalStrict so serialization errors cannot be mistaken for a digest.
func (gp *GovernanceProof) CommitSignal(result map[string]interface{}) string {
	commitment, _ := commitSignalStrict(result)
	return commitment
}

// ProofGenerator generates cryptographic proofs for governance decisions.
type ProofGenerator struct{}

// GenerateProof is the compatibility entry point. Its default logical time is
// deliberately constant so identical evaluations produce identical proofs.
func (pg *ProofGenerator) GenerateProof(
	decision bool,
	evaluatedPrimitives []string,
	signals []map[string]interface{},
	primitiveVersions map[string]string,
) *GovernanceProof {
	return pg.generateLegacyProof(
		decision,
		evaluatedPrimitives,
		signals,
		primitiveVersions,
		deterministicDefaultTime,
	)
}

// GenerateProofWithTime is the compatibility entry point with explicit logical
// time. New engine code should use GenerateProofForContext so failures surface.
func (pg *ProofGenerator) GenerateProofWithTime(
	decision bool,
	evaluatedPrimitives []string,
	signals []map[string]interface{},
	primitiveVersions map[string]string,
	logicalTime int64,
) *GovernanceProof {
	return pg.generateLegacyProof(
		decision,
		evaluatedPrimitives,
		signals,
		primitiveVersions,
		logicalTime,
	)
}

// GenerateProofForContext is the strict proof API for the governance engine.
// It returns every canonicalization or schema failure to the caller, filters
// versions to evaluated primitives, and binds an optional context snapshot.
func (pg *ProofGenerator) GenerateProofForContext(
	decision bool,
	evaluatedPrimitives []string,
	signals []map[string]interface{},
	primitiveVersions map[string]string,
	failureReasons []string,
	contextSnapshot map[string]interface{},
	logicalTime int64,
) (*GovernanceProof, error) {
	if len(evaluatedPrimitives) != len(signals) {
		return nil, errors.New("evaluation order and signals must have equal lengths")
	}
	if err := validateFailureReasons(decision, failureReasons); err != nil {
		return nil, err
	}
	if decision && contextSnapshot == nil {
		return nil, errors.New("permitted proofs require a bound context")
	}

	evaluationOrder := append([]string(nil), evaluatedPrimitives...)
	evaluatedVersions := make(map[string]string, len(evaluationOrder))
	canonicalSignals := make([]map[string]interface{}, len(signals))
	signalCommitments := make([]string, len(signals))
	seen := make(map[string]struct{}, len(evaluationOrder))
	allValid := len(signals) > 0

	for i, id := range evaluationOrder {
		if strings.TrimSpace(id) == "" {
			return nil, fmt.Errorf("evaluation order contains a blank primitive ID at index %d", i)
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, fmt.Errorf("primitive %q appears more than once", id)
		}
		seen[id] = struct{}{}

		version, exists := primitiveVersions[id]
		if !exists || strings.TrimSpace(version) == "" {
			return nil, fmt.Errorf("missing version for evaluated primitive %q", id)
		}
		evaluatedVersions[id] = version

		canonicalSignal, canonicalData, err := canonicalizeSignalInput(signals[i])
		if err != nil {
			return nil, fmt.Errorf("signal %d cannot be committed: %w", i, err)
		}
		valid, err := validateSignal(canonicalSignal, id, version)
		if err != nil {
			return nil, fmt.Errorf("signal %d is invalid: %w", i, err)
		}
		if !valid {
			allValid = false
		}
		canonicalSignals[i] = canonicalSignal
		signalCommitments[i] = hashBytes(canonicalData)
	}

	if decision != allValid {
		return nil, errors.New("decision does not match the conjunction of evaluated signals")
	}

	var canonicalContext map[string]interface{}
	contextCommitment := ""
	if contextSnapshot != nil {
		var contextData []byte
		var err error
		canonicalContext, contextData, err = canonicalizeContextInput(contextSnapshot)
		if err != nil {
			return nil, fmt.Errorf("context cannot be committed: %w", err)
		}
		contextCommitment = hashBytes(contextData)
	}

	proof := &GovernanceProof{
		SchemaVersion:     GovernanceProofSchemaVersion,
		PrimitiveVersions: evaluatedVersions,
		EvaluationOrder:   evaluationOrder,
		Decision:          decision,
		Signals:           canonicalSignals,
		SignalCommitments: signalCommitments,
		FailureReasons:    append([]string(nil), failureReasons...),
		ContextSnapshot:   canonicalContext,
		ContextCommitment: contextCommitment,
		GeneratedAt:       logicalTime,
	}

	envelopeCommitment, err := proof.computeEnvelopeCommitment()
	if err != nil {
		return nil, fmt.Errorf("cannot commit proof envelope: %w", err)
	}
	proof.EnvelopeCommitment = envelopeCommitment
	return proof, nil
}

func (pg *ProofGenerator) generateLegacyProof(
	decision bool,
	evaluatedPrimitives []string,
	signals []map[string]interface{},
	primitiveVersions map[string]string,
	logicalTime int64,
) *GovernanceProof {
	failureReasons := []string{}
	if !decision {
		failureReasons = []string{"governance evaluation denied"}
	}

	proof, err := pg.GenerateProofForContext(
		decision,
		evaluatedPrimitives,
		signals,
		primitiveVersions,
		failureReasons,
		nil,
		logicalTime,
	)
	if err == nil {
		return proof
	}

	// The legacy API cannot return an error. Return a valid denial proof rather
	// than an authorization or an error-shaped pseudo-commitment.
	proof, fallbackErr := pg.GenerateProofForContext(
		false,
		nil,
		nil,
		map[string]string{},
		[]string{fmt.Sprintf("proof generation failed: %v", err)},
		nil,
		logicalTime,
	)
	if fallbackErr != nil {
		return nil
	}
	return proof
}

// CommitSignalStrict commits a canonical signal and surfaces serialization
// errors to the caller.
func (pg *ProofGenerator) CommitSignalStrict(result map[string]interface{}) (string, error) {
	return commitSignalStrict(result)
}

// CommitSignal preserves the original convenience API. Invalid input never
// produces an error-shaped value that could be confused with a valid digest.
func (pg *ProofGenerator) CommitSignal(result map[string]interface{}) string {
	commitment, _ := commitSignalStrict(result)
	return commitment
}

func commitSignalStrict(result map[string]interface{}) (string, error) {
	if result == nil {
		return "", errors.New("signal cannot be nil")
	}
	_, canonicalData, err := canonicalizeSignalInput(result)
	if err != nil {
		return "", err
	}
	return hashBytes(canonicalData), nil
}

func validateSignal(signal map[string]interface{}, expectedID, expectedVersion string) (bool, error) {
	primitiveID, ok := signal["primitive_id"].(string)
	if !ok || primitiveID == "" {
		return false, errors.New("primitive_id must be a non-empty string")
	}
	if primitiveID != expectedID {
		return false, fmt.Errorf("primitive_id %q does not match evaluation order %q", primitiveID, expectedID)
	}

	version, ok := signal["version"].(string)
	if !ok || version == "" {
		return false, errors.New("version must be a non-empty string")
	}
	if version != expectedVersion {
		return false, fmt.Errorf("version %q does not match registered version %q", version, expectedVersion)
	}

	valid, ok := signal["valid"].(bool)
	if !ok {
		return false, errors.New("valid must be a boolean")
	}
	if metadata, ok := signal["metadata"]; !ok {
		return false, errors.New("metadata is required")
	} else if _, ok := metadata.(map[string]interface{}); !ok {
		return false, errors.New("metadata must be an object")
	}
	if evidence, ok := signal["evidence"]; !ok {
		return false, errors.New("evidence is required")
	} else if _, ok := evidence.([]interface{}); !ok {
		return false, errors.New("evidence must be an array")
	}
	return valid, nil
}

func validateFailureReasons(decision bool, failureReasons []string) error {
	for i, reason := range failureReasons {
		if strings.TrimSpace(reason) == "" {
			return fmt.Errorf("failure reason %d is blank", i)
		}
	}
	if decision && len(failureReasons) != 0 {
		return errors.New("permitted proofs cannot contain failure reasons")
	}
	if !decision && len(failureReasons) == 0 {
		return errors.New("denied proofs require at least one failure reason")
	}
	return nil
}

func (gp *GovernanceProof) computeEnvelopeCommitment() (commitment string, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			commitment = ""
			err = fmt.Errorf("proof envelope canonicalization panicked: %v", recovered)
		}
	}()

	signals := make([]map[string]interface{}, len(gp.Signals))
	for index, signal := range gp.Signals {
		cloned, _, cloneErr := cloneStoredSignal(signal)
		if cloneErr != nil {
			return "", fmt.Errorf("signal %d is not a safe canonical snapshot: %w", index, cloneErr)
		}
		signals[index] = cloned
	}
	var context map[string]interface{}
	if gp.ContextSnapshot != nil {
		context, _, err = cloneStoredContext(gp.ContextSnapshot)
		if err != nil {
			return "", fmt.Errorf("context is not a safe canonical snapshot: %w", err)
		}
	}
	versions := make(map[string]string, len(gp.PrimitiveVersions))
	for id, version := range gp.PrimitiveVersions {
		versions[id] = version
	}
	envelope := governanceProofEnvelope{
		SchemaVersion:     gp.SchemaVersion,
		PrimitiveVersions: versions,
		EvaluationOrder:   append([]string(nil), gp.EvaluationOrder...),
		Decision:          gp.Decision,
		Signals:           signals,
		SignalCommitments: append([]string(nil), gp.SignalCommitments...),
		FailureReasons:    append([]string(nil), gp.FailureReasons...),
		ContextIncluded:   context != nil,
		ContextCommitment: gp.ContextCommitment,
		GeneratedAt:       gp.GeneratedAt,
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		return "", err
	}
	return hashBytes(data), nil
}

const proofValueDepthLimit = 64

var (
	builtinBoolType   = reflect.TypeOf(false)
	builtinStringType = reflect.TypeOf("")
	builtinMapType    = reflect.TypeOf(map[string]interface{}{})
	builtinSliceType  = reflect.TypeOf([]interface{}{})
)

func canonicalizeSignalInput(input map[string]interface{}) (canonical map[string]interface{}, data []byte, err error) {
	defer proofCanonicalizationRecovery(&canonical, &data, &err)
	if input == nil {
		return nil, nil, errors.New("signal cannot be nil")
	}
	if len(input) != 5 {
		return nil, nil, errors.New("signal must contain exactly primitive_id, version, valid, metadata, and evidence")
	}
	primitiveID, ok := input["primitive_id"].(string)
	if !ok {
		return nil, nil, errors.New("primitive_id must be a string")
	}
	version, ok := input["version"].(string)
	if !ok {
		return nil, nil, errors.New("version must be a string")
	}
	valid, ok := input["valid"].(bool)
	if !ok {
		return nil, nil, errors.New("valid must be a boolean")
	}
	metadata, err := encodeProofRootObject(input["metadata"])
	if err != nil {
		return nil, nil, fmt.Errorf("metadata: %w", err)
	}
	evidence, err := encodeProofRootArray(input["evidence"])
	if err != nil {
		return nil, nil, fmt.Errorf("evidence: %w", err)
	}
	canonical = map[string]interface{}{
		"primitive_id": primitiveID,
		"version":      version,
		"valid":        valid,
		"metadata":     metadata,
		"evidence":     evidence,
	}
	data, err = json.Marshal(canonical)
	return canonical, data, err
}

func canonicalizeContextInput(input map[string]interface{}) (canonical map[string]interface{}, data []byte, err error) {
	defer proofCanonicalizationRecovery(&canonical, &data, &err)
	if input == nil {
		return nil, nil, errors.New("context cannot be nil")
	}
	canonical, err = encodeProofRootObject(input)
	if err != nil {
		return nil, nil, err
	}
	data, err = json.Marshal(canonical)
	return canonical, data, err
}

func encodeProofRootObject(input interface{}) (map[string]interface{}, error) {
	value := reflect.ValueOf(input)
	if !value.IsValid() || value.Kind() != reflect.Map || value.Type().Key().Kind() != reflect.String {
		return nil, errors.New("value must be an object with string keys")
	}
	if value.IsNil() {
		return map[string]interface{}{}, nil
	}
	encoded := make(map[string]interface{}, value.Len())
	iterator := value.MapRange()
	for iterator.Next() {
		child, err := encodeProofValue(iterator.Value(), 0)
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", iterator.Key().String(), err)
		}
		encoded[iterator.Key().String()] = child
	}
	return encoded, nil
}

func encodeProofRootArray(input interface{}) ([]interface{}, error) {
	value := reflect.ValueOf(input)
	if !value.IsValid() || (value.Kind() != reflect.Slice && value.Kind() != reflect.Array) {
		return nil, errors.New("value must be an array")
	}
	if value.Kind() == reflect.Slice && value.IsNil() {
		return []interface{}{}, nil
	}
	encoded := make([]interface{}, value.Len())
	for index := 0; index < value.Len(); index++ {
		child, err := encodeProofValue(value.Index(index), 0)
		if err != nil {
			return nil, fmt.Errorf("item %d: %w", index, err)
		}
		encoded[index] = child
	}
	return encoded, nil
}

func encodeProofValue(value reflect.Value, depth int) (interface{}, error) {
	if depth > proofValueDepthLimit {
		return nil, errors.New("value is cyclic or nested too deeply")
	}
	if !value.IsValid() {
		return nil, nil
	}
	if value.Kind() == reflect.Interface {
		if value.IsNil() {
			return nil, nil
		}
		return encodeProofValue(value.Elem(), depth+1)
	}
	typeID := canonicalTypeID(value.Type())
	switch value.Kind() {
	case reflect.Bool:
		if value.Type() == builtinBoolType {
			return value.Bool(), nil
		}
		return proofTaggedValue("bool", typeID, value.Bool()), nil
	case reflect.String:
		if value.Type() == jsonNumberType && !validJSONNumber(value.String()) {
			return nil, fmt.Errorf("invalid JSON number %q", value.String())
		}
		if value.Type() == builtinStringType {
			return value.String(), nil
		}
		return proofTaggedValue("string", typeID, value.String()), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return proofTaggedValue("int", typeID, strconv.FormatInt(value.Int(), 10)), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return proofTaggedValue("uint", typeID, strconv.FormatUint(value.Uint(), 10)), nil
	case reflect.Float32, reflect.Float64:
		floating := value.Float()
		if math.IsNaN(floating) || math.IsInf(floating, 0) {
			return nil, errors.New("non-finite numbers are not permitted")
		}
		return proofTaggedValue(
			"float", typeID, strconv.FormatFloat(floating, 'g', -1, value.Type().Bits()),
		), nil
	case reflect.Map:
		if value.Type().Key().Kind() != reflect.String {
			return nil, errors.New("object keys must be strings")
		}
		if value.IsNil() {
			return proofTaggedValue("map", typeID, nil), nil
		}
		entries := make(map[string]interface{}, value.Len())
		iterator := value.MapRange()
		for iterator.Next() {
			child, err := encodeProofValue(iterator.Value(), depth+1)
			if err != nil {
				return nil, fmt.Errorf("field %q: %w", iterator.Key().String(), err)
			}
			entries[iterator.Key().String()] = child
		}
		return proofTaggedValue("map", typeID, entries), nil
	case reflect.Slice, reflect.Array:
		if value.Kind() == reflect.Slice && value.IsNil() {
			return proofTaggedValue("slice", typeID, nil), nil
		}
		items := make([]interface{}, value.Len())
		for index := 0; index < value.Len(); index++ {
			child, err := encodeProofValue(value.Index(index), depth+1)
			if err != nil {
				return nil, fmt.Errorf("item %d: %w", index, err)
			}
			items[index] = child
		}
		kind := "slice"
		if value.Kind() == reflect.Array {
			kind = "array"
		}
		return proofTaggedValue(kind, typeID, items), nil
	default:
		return nil, fmt.Errorf("unsupported value type %s", value.Type())
	}
}

func proofTaggedValue(kind, typeID string, value interface{}) map[string]interface{} {
	return map[string]interface{}{
		"$gsas_kind":  kind,
		"$gsas_type":  typeID,
		"$gsas_value": value,
	}
}

func cloneStoredSignal(input map[string]interface{}) (canonical map[string]interface{}, data []byte, err error) {
	defer proofCanonicalizationRecovery(&canonical, &data, &err)
	if input == nil || len(input) != 5 {
		return nil, nil, errors.New("stored signal has an invalid shape")
	}
	primitiveID, ok := input["primitive_id"].(string)
	if !ok {
		return nil, nil, errors.New("stored primitive_id must be a string")
	}
	version, ok := input["version"].(string)
	if !ok {
		return nil, nil, errors.New("stored version must be a string")
	}
	valid, ok := input["valid"].(bool)
	if !ok {
		return nil, nil, errors.New("stored valid must be a boolean")
	}
	metadata, err := cloneStoredRootObject(input["metadata"])
	if err != nil {
		return nil, nil, fmt.Errorf("stored metadata: %w", err)
	}
	evidence, err := cloneStoredRootArray(input["evidence"])
	if err != nil {
		return nil, nil, fmt.Errorf("stored evidence: %w", err)
	}
	canonical = map[string]interface{}{
		"primitive_id": primitiveID,
		"version":      version,
		"valid":        valid,
		"metadata":     metadata,
		"evidence":     evidence,
	}
	data, err = json.Marshal(canonical)
	return canonical, data, err
}

func cloneStoredContext(input map[string]interface{}) (canonical map[string]interface{}, data []byte, err error) {
	defer proofCanonicalizationRecovery(&canonical, &data, &err)
	if input == nil {
		return nil, nil, errors.New("stored context cannot be nil")
	}
	canonical, err = cloneStoredRootObject(input)
	if err != nil {
		return nil, nil, err
	}
	data, err = json.Marshal(canonical)
	return canonical, data, err
}

func cloneStoredRootObject(input interface{}) (map[string]interface{}, error) {
	value := reflect.ValueOf(input)
	if !value.IsValid() || value.Type() != builtinMapType {
		return nil, errors.New("value must be a canonical object")
	}
	if value.IsNil() {
		return map[string]interface{}{}, nil
	}
	cloned := make(map[string]interface{}, value.Len())
	iterator := value.MapRange()
	for iterator.Next() {
		child, err := cloneStoredValue(iterator.Value(), 0)
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", iterator.Key().String(), err)
		}
		cloned[iterator.Key().String()] = child
	}
	return cloned, nil
}

func cloneStoredRootArray(input interface{}) ([]interface{}, error) {
	value := reflect.ValueOf(input)
	if !value.IsValid() || value.Type() != builtinSliceType {
		return nil, errors.New("value must be a canonical array")
	}
	if value.IsNil() {
		return []interface{}{}, nil
	}
	cloned := make([]interface{}, value.Len())
	for index := 0; index < value.Len(); index++ {
		child, err := cloneStoredValue(value.Index(index), 0)
		if err != nil {
			return nil, fmt.Errorf("item %d: %w", index, err)
		}
		cloned[index] = child
	}
	return cloned, nil
}

func cloneStoredValue(value reflect.Value, depth int) (interface{}, error) {
	if depth > proofValueDepthLimit {
		return nil, errors.New("stored value is nested too deeply")
	}
	if !value.IsValid() {
		return nil, nil
	}
	if value.Kind() == reflect.Interface {
		if value.IsNil() {
			return nil, nil
		}
		return cloneStoredValue(value.Elem(), depth+1)
	}
	if value.Type() == builtinBoolType {
		return value.Bool(), nil
	}
	if value.Type() == builtinStringType {
		return value.String(), nil
	}
	if value.Type() == builtinMapType {
		return cloneStoredRootObject(value.Interface())
	}
	if value.Type() == builtinSliceType {
		return cloneStoredRootArray(value.Interface())
	}
	return nil, fmt.Errorf("unsafe or non-canonical stored value type %s", value.Type())
}

func proofCanonicalizationRecovery(canonical *map[string]interface{}, data *[]byte, err *error) {
	if recovered := recover(); recovered != nil {
		*canonical = nil
		*data = nil
		*err = fmt.Errorf("proof canonicalization panicked: %v", recovered)
	}
}

func hashBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func equalCommitments(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
