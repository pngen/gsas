/*
Governance Evaluation Engine for GSAS.
*/

package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

// GovernanceDecision represents the result of governance evaluation.
type GovernanceDecision struct {
	Permitted      bool                     `json:"permitted"`
	Signals        []map[string]interface{} `json:"signals"`
	FailureReasons []string                 `json:"failure_reasons"`
	Proof          *GovernanceProof         `json:"proof"`
}

type registeredPrimitive struct {
	id                       string
	primitive                GovernancePrimitive
	version                  string
	sourceFingerprint        string
	configurationFingerprint string
}

type evaluationState struct {
	recursive bool
}

// GovernanceEngine evaluates a validated registration snapshot in sequence.
type GovernanceEngine struct {
	registrations                 []registeredPrimitive
	configurationEpoch            uint64
	registrationActive            bool
	registrationMutationAttempted bool
	callbackEvaluations           map[uint64]*evaluationState
	mu                            sync.RWMutex
	proofGen                      *ProofGenerator
}

func NewGovernanceEngine() *GovernanceEngine {
	return &GovernanceEngine{
		registrations:       []registeredPrimitive{},
		callbackEvaluations: make(map[uint64]*evaluationState),
		proofGen:            &ProofGenerator{},
	}
}

// RegisterPrimitive validates a primitive before publishing it atomically.
// User callbacks are never invoked while the engine lock is held.
func (ge *GovernanceEngine) RegisterPrimitive(id string, primitive GovernancePrimitive) error {
	if id == "" || strings.TrimSpace(id) != id {
		return errors.New("primitive ID cannot be empty or contain surrounding whitespace")
	}
	if primitiveIsNil(primitive) {
		return errors.New("primitive cannot be nil")
	}

	ge.mu.Lock()
	if ge.registrationActive {
		ge.registrationMutationAttempted = true
		ge.mu.Unlock()
		return errors.New("primitive registration cannot be called recursively")
	}
	if ge.hasPrimitiveIDLocked(id) {
		ge.mu.Unlock()
		return fmt.Errorf("primitive with ID '%s' already registered", id)
	}
	ge.registrationActive = true
	ge.registrationMutationAttempted = false
	ge.mu.Unlock()
	defer func() {
		ge.mu.Lock()
		ge.registrationActive = false
		ge.registrationMutationAttempted = false
		ge.mu.Unlock()
	}()

	report, err := NewComplianceChecker().CheckPrimitive(primitive)
	if err != nil {
		return err
	}
	if !report.Compliant {
		return fmt.Errorf("primitive %q is not compliant: %s", id, complianceSummary(report))
	}
	version, err := safePrimitiveVersion(primitive)
	if err != nil {
		return err
	}
	if strings.TrimSpace(version) != version || version == "" {
		return errors.New("primitive version cannot be empty or contain surrounding whitespace")
	}
	sourceFingerprint, err := currentSourceFingerprint(primitive)
	if err != nil {
		return err
	}
	configurationFingerprint, err := currentConfigurationFingerprint(primitive)
	if err != nil {
		return err
	}

	registration := registeredPrimitive{
		id:                       id,
		primitive:                primitive,
		version:                  version,
		sourceFingerprint:        sourceFingerprint,
		configurationFingerprint: configurationFingerprint,
	}
	ge.mu.Lock()
	defer ge.mu.Unlock()
	if ge.registrationMutationAttempted {
		return errors.New("primitive attempted to mutate engine configuration during registration")
	}
	if ge.hasPrimitiveIDLocked(id) {
		return fmt.Errorf("primitive with ID '%s' already registered", id)
	}
	ge.registrations = append(ge.registrations, registration)
	ge.configurationEpoch++
	return nil
}

func (ge *GovernanceEngine) hasPrimitiveIDLocked(id string) bool {
	for _, registration := range ge.registrations {
		if registration.id == id {
			return true
		}
	}
	return false
}

func complianceSummary(report *ComplianceReport) string {
	parts := make([]string, len(report.Violations))
	for index, violation := range report.Violations {
		parts[index] = violation.Error()
	}
	return strings.Join(parts, "; ")
}

func currentSourceFingerprint(primitive GovernancePrimitive) (string, error) {
	sourcePrimitive, ok := primitive.(SourceGovernancePrimitive)
	if !ok {
		return "", nil
	}
	source, err := safePrimitiveSource(sourcePrimitive)
	if err != nil {
		return "", err
	}
	if err := (&DeterminismEnforcer{}).ValidatePrimitiveSource(source); err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(source))
	return hex.EncodeToString(digest[:]), nil
}

func currentConfigurationFingerprint(primitive GovernancePrimitive) (string, error) {
	configurable, ok := primitive.(ConfigurablePrimitive)
	if !ok {
		return "", nil
	}
	if err := safePrimitiveConfiguration(configurable); err != nil {
		return "", err
	}
	fingerprinted, ok := primitive.(FingerprintedConfigurablePrimitive)
	if !ok {
		return "", errors.New("configurable primitives must expose a configuration fingerprint")
	}
	return safeConfigurationFingerprint(fingerprinted)
}

// Evaluate derives proof time from the immutable context rather than wall time.
func (ge *GovernanceEngine) Evaluate(ctx *DeterministicContext) *GovernanceDecision {
	logicalTime := int64(0)
	if ctx != nil {
		logicalTime = int64(ctx.Time())
	}
	return ge.evaluate(ctx, logicalTime)
}

// EvaluateWithLogicalTime rejects a timestamp that is not the context's bound
// logical time; callers cannot relabel an evaluation after the fact.
func (ge *GovernanceEngine) EvaluateWithLogicalTime(ctx *DeterministicContext, logicalTime int64) *GovernanceDecision {
	if ctx != nil && int64(ctx.Time()) != logicalTime {
		return ge.preconditionDenial(
			ctx,
			int64(ctx.Time()),
			fmt.Sprintf("logical time %d does not match context time %d", logicalTime, ctx.Time()),
		)
	}
	return ge.evaluate(ctx, logicalTime)
}

func (ge *GovernanceEngine) evaluate(ctx *DeterministicContext, logicalTime int64) *GovernanceDecision {
	if ctx == nil {
		return ge.preconditionDenial(nil, logicalTime, "governance context is required")
	}
	if err := ctx.ValidationError(); err != nil {
		return ge.preconditionDenial(nil, logicalTime, err.Error())
	}

	goroutineID, err := currentGoroutineID()
	if err != nil {
		return ge.preconditionDenial(ctx, logicalTime, err.Error())
	}
	ge.mu.Lock()
	if ge.callbackEvaluations == nil {
		ge.callbackEvaluations = make(map[uint64]*evaluationState)
	}
	if parent, recursive := ge.callbackEvaluations[goroutineID]; recursive {
		parent.recursive = true
		ge.mu.Unlock()
		return ge.preconditionDenial(ctx, logicalTime, "recursive governance evaluation is not permitted")
	}
	registrations := append([]registeredPrimitive(nil), ge.registrations...)
	configurationEpoch := ge.configurationEpoch
	ge.mu.Unlock()

	if len(registrations) == 0 {
		return ge.preconditionDenial(ctx, logicalTime, "at least one governance primitive is required")
	}

	decision := &GovernanceDecision{
		Permitted:      true,
		Signals:        make([]map[string]interface{}, 0, len(registrations)),
		FailureReasons: []string{},
	}
	evaluatedIDs := make([]string, 0, len(registrations))
	evaluatedVersions := make(map[string]string, len(registrations))
	evaluation := &evaluationState{}

	for _, registration := range registrations {
		signal, failureReason := ge.evaluateRegistration(evaluation, registration, ctx)
		decision.Signals = append(decision.Signals, signal)
		evaluatedIDs = append(evaluatedIDs, registration.id)
		evaluatedVersions[registration.id] = registration.version
		if failureReason != "" {
			decision.Permitted = false
			decision.FailureReasons = append(decision.FailureReasons, failureReason)
			break
		}
	}

	ge.mu.RLock()
	configurationChanged := ge.configurationEpoch != configurationEpoch
	recursiveEvaluation := evaluation.recursive
	ge.mu.RUnlock()
	if recursiveEvaluation {
		return ge.preconditionDenial(ctx, logicalTime, "recursive governance evaluation was attempted")
	}
	if configurationChanged {
		return ge.preconditionDenial(ctx, logicalTime, "governance configuration changed during evaluation")
	}

	contextSnapshot := ctx.Data()
	proof, err := ge.proofGenerator().GenerateProofForContext(
		decision.Permitted,
		evaluatedIDs,
		decision.Signals,
		evaluatedVersions,
		decision.FailureReasons,
		contextSnapshot,
		logicalTime,
	)
	if err != nil {
		decision.Permitted = false
		decision.FailureReasons = append(decision.FailureReasons, "proof generation failed: "+err.Error())
		decision.Proof = nil
		decision.Signals = []map[string]interface{}{}
		return decision
	}
	decision.Proof = proof
	decision.Signals = make([]map[string]interface{}, len(proof.Signals))
	for index, signal := range proof.Signals {
		cloned, _, cloneErr := cloneStoredSignal(signal)
		if cloneErr != nil {
			decision.Permitted = false
			decision.FailureReasons = append(decision.FailureReasons, "proof signal snapshot failed: "+cloneErr.Error())
			decision.Proof = nil
			decision.Signals = []map[string]interface{}{}
			return decision
		}
		decision.Signals[index] = cloned
	}
	return decision
}

func (ge *GovernanceEngine) proofGenerator() *ProofGenerator {
	ge.mu.RLock()
	generator := ge.proofGen
	ge.mu.RUnlock()
	if generator == nil {
		return &ProofGenerator{}
	}
	return generator
}

func (ge *GovernanceEngine) evaluateRegistration(
	evaluation *evaluationState,
	registration registeredPrimitive,
	ctx *DeterministicContext,
) (map[string]interface{}, string) {
	failureSignal := func(reason string) (map[string]interface{}, string) {
		return map[string]interface{}{
			"primitive_id": registration.id,
			"version":      registration.version,
			"valid":        false,
			"metadata":     map[string]interface{}{"reason": reason},
			"evidence":     []interface{}{},
		}, fmt.Sprintf("Primitive '%s' failed: %s", registration.id, reason)
	}

	version, err := safePrimitiveVersion(registration.primitive)
	if err != nil {
		return failureSignal(err.Error())
	}
	if version != registration.version {
		return failureSignal(fmt.Sprintf(
			"version drift detected (registered %q, current %q)", registration.version, version,
		))
	}
	fingerprint, err := currentSourceFingerprint(registration.primitive)
	if err != nil {
		return failureSignal(err.Error())
	}
	if fingerprint != registration.sourceFingerprint {
		return failureSignal("validated primitive source changed after registration")
	}
	configurationFingerprint, err := currentConfigurationFingerprint(registration.primitive)
	if err != nil {
		return failureSignal(err.Error())
	}
	if configurationFingerprint != registration.configurationFingerprint {
		return failureSignal("configuration drift detected after registration")
	}

	firstRaw, firstErr := ge.invokePrimitiveEvaluation(evaluation, registration.primitive, ctx)
	if firstErr != nil {
		return failureSignal(firstErr.Error())
	}
	first, firstErr := normalizeEvaluationResult(firstRaw)
	if firstErr != nil {
		return failureSignal(firstErr.Error())
	}
	firstCanonical, firstErr := canonicalPrimitiveJSON(first)
	if firstErr != nil {
		return failureSignal(firstErr.Error())
	}

	secondRaw, secondErr := ge.invokePrimitiveEvaluation(evaluation, registration.primitive, ctx)
	if secondErr != nil {
		return failureSignal(secondErr.Error())
	}
	second, secondErr := normalizeEvaluationResult(secondRaw)
	if secondErr != nil {
		return failureSignal(secondErr.Error())
	}
	secondCanonical, secondErr := canonicalPrimitiveJSON(second)
	if secondErr != nil {
		return failureSignal(secondErr.Error())
	}
	if !bytes.Equal(firstCanonical, secondCanonical) {
		return failureSignal("non-deterministic result for identical context")
	}

	version, err = safePrimitiveVersion(registration.primitive)
	if err != nil || version != registration.version {
		if err != nil {
			return failureSignal(err.Error())
		}
		return failureSignal("version changed during evaluation")
	}
	fingerprint, err = currentSourceFingerprint(registration.primitive)
	if err != nil || fingerprint != registration.sourceFingerprint {
		if err != nil {
			return failureSignal(err.Error())
		}
		return failureSignal("validated source changed during evaluation")
	}
	configurationFingerprint, err = currentConfigurationFingerprint(registration.primitive)
	if err != nil || configurationFingerprint != registration.configurationFingerprint {
		if err != nil {
			return failureSignal(err.Error())
		}
		return failureSignal("configuration changed during evaluation")
	}

	signal := map[string]interface{}{
		"primitive_id": registration.id,
		"version":      registration.version,
		"valid":        first["valid"],
		"metadata":     first["metadata"],
		"evidence":     first["evidence"],
	}
	if first["valid"].(bool) {
		return signal, ""
	}
	reason := "governance signal was denied"
	if metadata := first["metadata"].(map[string]interface{}); metadata != nil {
		if candidate, ok := metadata["reason"].(string); ok && strings.TrimSpace(candidate) != "" {
			reason = candidate
		}
	}
	return signal, fmt.Sprintf("Primitive '%s' failed: %s", registration.id, reason)
}

func (ge *GovernanceEngine) invokePrimitiveEvaluation(
	evaluation *evaluationState,
	primitive GovernancePrimitive,
	ctx *DeterministicContext,
) (map[string]interface{}, error) {
	goroutineID, err := currentGoroutineID()
	if err != nil {
		return nil, err
	}
	ge.mu.Lock()
	if ge.callbackEvaluations == nil {
		ge.callbackEvaluations = make(map[uint64]*evaluationState)
	}
	if parent, active := ge.callbackEvaluations[goroutineID]; active {
		parent.recursive = true
		ge.mu.Unlock()
		return nil, errors.New("recursive primitive callback is not permitted")
	}
	ge.callbackEvaluations[goroutineID] = evaluation
	ge.mu.Unlock()
	defer func() {
		ge.mu.Lock()
		if ge.callbackEvaluations[goroutineID] == evaluation {
			delete(ge.callbackEvaluations, goroutineID)
		}
		ge.mu.Unlock()
	}()
	return safePrimitiveEvaluation(primitive, ctx)
}

func currentGoroutineID() (uint64, error) {
	var stackHeader [64]byte
	length := runtime.Stack(stackHeader[:], false)
	fields := bytes.Fields(stackHeader[:length])
	if len(fields) < 2 || string(fields[0]) != "goroutine" {
		return 0, errors.New("cannot identify governance evaluation call chain")
	}
	id, err := strconv.ParseUint(string(fields[1]), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("cannot identify governance evaluation call chain: %w", err)
	}
	return id, nil
}

func (ge *GovernanceEngine) preconditionDenial(ctx *DeterministicContext, logicalTime int64, reason string) *GovernanceDecision {
	decision := &GovernanceDecision{
		Permitted:      false,
		Signals:        []map[string]interface{}{},
		FailureReasons: []string{reason},
	}
	var contextSnapshot map[string]interface{}
	if ctx != nil && ctx.ValidationError() == nil {
		contextSnapshot = ctx.Data()
	}
	proof, err := ge.proofGenerator().GenerateProofForContext(
		false, nil, nil, map[string]string{}, decision.FailureReasons, contextSnapshot, logicalTime,
	)
	if err == nil {
		decision.Proof = proof
	} else {
		decision.FailureReasons = append(decision.FailureReasons, "proof generation failed: "+err.Error())
	}
	return decision
}

func (ge *GovernanceEngine) PrimitiveCount() int {
	ge.mu.RLock()
	defer ge.mu.RUnlock()
	return len(ge.registrations)
}

func (ge *GovernanceEngine) Clear() error {
	ge.mu.Lock()
	defer ge.mu.Unlock()
	if ge.registrationActive {
		ge.registrationMutationAttempted = true
		return errors.New("cannot clear governance configuration while primitive registration is active")
	}
	ge.registrations = []registeredPrimitive{}
	ge.configurationEpoch++
	return nil
}
