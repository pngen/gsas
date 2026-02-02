/*
Governance Evaluation Engine for GSAS.

Core evaluation engine that enforces all governance primitives in strict sequence,
fails closed on violations, and emits structured proofs.
*/

package core

import (
	"errors"
	"fmt"
	"sync"
)

// GovernanceDecision represents the result of governance evaluation
type GovernanceDecision struct {
	Permitted      bool                     `json:"permitted"`
	Signals        []map[string]interface{} `json:"signals"`
	FailureReasons []string                 `json:"failure_reasons"`
	Proof          *GovernanceProof         `json:"proof"`
}

// GovernanceEngine evaluates governance primitives in sequence
type GovernanceEngine struct {
	primitives   []GovernancePrimitive
	primitiveIDs []string
	versions     map[string]string
	mu           sync.RWMutex
	proofGen     *ProofGenerator
}

// NewGovernanceEngine creates a new governance engine
func NewGovernanceEngine() *GovernanceEngine {
	return &GovernanceEngine{
		primitives:   []GovernancePrimitive{},
		primitiveIDs: []string{},
		versions:     make(map[string]string),
		proofGen:     &ProofGenerator{},
	}
}

// RegisterPrimitive registers a governance primitive with an ID
func (ge *GovernanceEngine) RegisterPrimitive(id string, p GovernancePrimitive) error {
	if p == nil {
		return errors.New("primitive cannot be nil")
	}
	if id == "" {
		return errors.New("primitive ID cannot be empty")
	}

	ge.mu.Lock()
	defer ge.mu.Unlock()

	// Check for duplicate ID
	for _, existingID := range ge.primitiveIDs {
		if existingID == id {
			return fmt.Errorf("primitive with ID '%s' already registered", id)
		}
	}

	ge.primitives = append(ge.primitives, p)
	ge.primitiveIDs = append(ge.primitiveIDs, id)
	ge.versions[id] = p.Version()

	return nil
}

// Evaluate evaluates all registered primitives against context
// Fails closed: any failure results in denial
func (ge *GovernanceEngine) Evaluate(ctx *DeterministicContext) *GovernanceDecision {
	ge.mu.RLock()
	defer ge.mu.RUnlock()

	decision := &GovernanceDecision{
		Permitted:      true,
		Signals:        make([]map[string]interface{}, 0, len(ge.primitives)),
		FailureReasons: []string{},
	}

	// Evaluate each primitive in strict sequence
	for i, primitive := range ge.primitives {
		id := ge.primitiveIDs[i]
		result := primitive.Evaluate(ctx)

		signal := map[string]interface{}{
			"primitive_id": id,
			"version":      ge.versions[id],
			"valid":        result["valid"],
			"metadata":     result["metadata"],
			"evidence":     result["evidence"],
		}
		decision.Signals = append(decision.Signals, signal)

		valid, ok := result["valid"].(bool)
		if !ok || !valid {
			decision.Permitted = false
			reason := fmt.Sprintf("Primitive '%s' failed", id)
			if meta, ok := result["metadata"].(map[string]interface{}); ok {
				if r, ok := meta["reason"].(string); ok {
					reason = fmt.Sprintf("Primitive '%s' failed: %s", id, r)
				}
			}
			decision.FailureReasons = append(decision.FailureReasons, reason)
			// Fail closed: stop on first failure
			break
		}
	}

	// Generate proof
	evaluatedIDs := make([]string, len(decision.Signals))
	for i, sig := range decision.Signals {
		evaluatedIDs[i] = sig["primitive_id"].(string)
	}

	decision.Proof = ge.proofGen.GenerateProof(
		decision.Permitted,
		evaluatedIDs,
		decision.Signals,
		ge.versions,
	)

	return decision
}

// EvaluateWithLogicalTime evaluates with explicit logical time (for deterministic testing)
func (ge *GovernanceEngine) EvaluateWithLogicalTime(ctx *DeterministicContext, logicalTime int64) *GovernanceDecision {
	ge.mu.RLock()
	defer ge.mu.RUnlock()

	decision := &GovernanceDecision{
		Permitted:      true,
		Signals:        make([]map[string]interface{}, 0, len(ge.primitives)),
		FailureReasons: []string{},
	}

	for i, primitive := range ge.primitives {
		id := ge.primitiveIDs[i]
		result := primitive.Evaluate(ctx)

		signal := map[string]interface{}{
			"primitive_id": id,
			"version":      ge.versions[id],
			"valid":        result["valid"],
			"metadata":     result["metadata"],
			"evidence":     result["evidence"],
		}
		decision.Signals = append(decision.Signals, signal)

		valid, ok := result["valid"].(bool)
		if !ok || !valid {
			decision.Permitted = false
			reason := fmt.Sprintf("Primitive '%s' failed", id)
			if meta, ok := result["metadata"].(map[string]interface{}); ok {
				if r, ok := meta["reason"].(string); ok {
					reason = fmt.Sprintf("Primitive '%s' failed: %s", id, r)
				}
			}
			decision.FailureReasons = append(decision.FailureReasons, reason)
			break
		}
	}

	evaluatedIDs := make([]string, len(decision.Signals))
	for i, sig := range decision.Signals {
		evaluatedIDs[i] = sig["primitive_id"].(string)
	}

	decision.Proof = ge.proofGen.GenerateProofWithTime(
		decision.Permitted,
		evaluatedIDs,
		decision.Signals,
		ge.versions,
		logicalTime,
	)

	return decision
}

// PrimitiveCount returns number of registered primitives
func (ge *GovernanceEngine) PrimitiveCount() int {
	ge.mu.RLock()
	defer ge.mu.RUnlock()
	return len(ge.primitives)
}

// Clear removes all registered primitives
func (ge *GovernanceEngine) Clear() {
	ge.mu.Lock()
	defer ge.mu.Unlock()
	ge.primitives = []GovernancePrimitive{}
	ge.primitiveIDs = []string{}
	ge.versions = make(map[string]string)
}