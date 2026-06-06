/*
Unit tests for GSAS proof commitments.
*/

package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gsas/core"
)

func TestProofCommitmentBindsFullSignal(t *testing.T) {
	generator := &core.ProofGenerator{}
	base := map[string]interface{}{
		"primitive_id": "auth",
		"version":      "1.0.0",
		"valid":        true,
		"metadata":     map[string]interface{}{"reason": "ok"},
		"evidence":     []interface{}{"allow-list"},
	}

	changedEvidence := map[string]interface{}{
		"primitive_id": "auth",
		"version":      "1.0.0",
		"valid":        true,
		"metadata":     map[string]interface{}{"reason": "ok"},
		"evidence":     []interface{}{"deny-list"},
	}
	changedPrimitive := map[string]interface{}{
		"primitive_id": "billing",
		"version":      "1.0.0",
		"valid":        true,
		"metadata":     map[string]interface{}{"reason": "ok"},
		"evidence":     []interface{}{"allow-list"},
	}

	assert.NotEqual(t, generator.CommitSignal(base), generator.CommitSignal(changedEvidence))
	assert.NotEqual(t, generator.CommitSignal(base), generator.CommitSignal(changedPrimitive))
}

func TestProofGeneratorCopiesMutableInputs(t *testing.T) {
	generator := &core.ProofGenerator{}
	evaluated := []string{"auth"}
	versions := map[string]string{"auth": "1.0.0"}

	proof := generator.GenerateProofWithTime(true, evaluated, []map[string]interface{}{}, versions, 10)
	evaluated[0] = "changed"
	versions["auth"] = "2.0.0"
	versions["new"] = "1.0.0"

	assert.Equal(t, []string{"auth"}, proof.EvaluationOrder)
	assert.Equal(t, "1.0.0", proof.PrimitiveVersions["auth"])
	assert.NotContains(t, proof.PrimitiveVersions, "new")
}
