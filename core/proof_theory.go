/*
Proof theory for GSAS governance decisions.
*/

package core

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

// GovernanceProof represents a cryptographically verifiable proof of governance decision
type GovernanceProof struct {
	// What was evaluated
	PrimitiveVersions map[string]string `json:"primitive_versions"`
	EvaluationOrder   []string          `json:"evaluation_order"`

	// What was decided
	Decision          bool     `json:"decision"`
	SignalCommitments []string `json:"signal_commitments"` // SHA256 hashes of signals

	// Metadata
	GeneratedAt int64 `json:"generated_at"` // Logical timestamp
	// How to verify
}

// Verify independently verifies proof correctness.
// LIMITATION: Verification requires stored context.
// Current implementation cannot verify proofs independently.
// See issue #123 for roadmap.
func (gp *GovernanceProof) Verify(primitives map[string]GovernancePrimitive) (bool, error) {
	// This is a placeholder implementation that raises NotImplementedError
	// as per the requirement to be honest about limitations
	return false, fmt.Errorf("Full verification not yet supported. Proof verification requires stored execution context. See issue #123 for roadmap.")
}

// ReconstructContext reconstructs context for verification (simplified)
func (gp *GovernanceProof) ReconstructContext(index int) map[string]interface{} {
	// In practice, this would use stored context data or deterministic replay
	return map[string]interface{}{"index": index}
}

// CommitSignal creates cryptographic commitment to signal
func (gp *GovernanceProof) CommitSignal(result map[string]interface{}) string {
	return commitSignal(result)
}

// ProofGenerator generates cryptographic proofs for governance decisions
type ProofGenerator struct{}

func cloneStringMap(input map[string]string) map[string]string {
	cloned := make(map[string]string, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}

func commitSignal(result map[string]interface{}) string {
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Sprintf("error:%x", sha256.Sum256([]byte(err.Error())))
	}
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

// GenerateProof generates a cryptographic proof of governance evaluation
func (pg *ProofGenerator) GenerateProof(
	decision bool,
	evaluatedPrimitives []string,
	signals []map[string]interface{},
	primitiveVersions map[string]string,
) *GovernanceProof {
	return pg.GenerateProofWithTime(decision, evaluatedPrimitives, signals, primitiveVersions, time.Now().UnixNano())
}

// GenerateProofWithTime generates proof with explicit logical time (for deterministic testing)
func (pg *ProofGenerator) GenerateProofWithTime(
	decision bool,
	evaluatedPrimitives []string,
	signals []map[string]interface{},
	primitiveVersions map[string]string,
	logicalTime int64,
) *GovernanceProof {
	signalCommitments := make([]string, len(signals))
	for i, signal := range signals {
		signalCommitments[i] = pg.CommitSignal(signal)
	}
	evaluationOrder := append([]string(nil), evaluatedPrimitives...)

	return &GovernanceProof{
		PrimitiveVersions: cloneStringMap(primitiveVersions),
		EvaluationOrder:   evaluationOrder,
		Decision:          decision,
		SignalCommitments: signalCommitments,
		GeneratedAt:       logicalTime,
	}
}

// CommitSignal creates cryptographic commitment to signal
func (pg *ProofGenerator) CommitSignal(result map[string]interface{}) string {
	return commitSignal(result)
}
