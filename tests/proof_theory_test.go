/*
Unit tests for GSAS proof commitments.
*/

package tests

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gsas/core"
)

type verificationPrimitive struct {
	version     string
	evaluations int
}

type panickingJSONNumber int64

func (panickingJSONNumber) MarshalJSON() ([]byte, error) {
	panic("custom marshaler must not be invoked")
}

func (p *verificationPrimitive) Version() string { return p.version }
func (p *verificationPrimitive) Evaluate(context interface{}) map[string]interface{} {
	p.evaluations++
	return map[string]interface{}{"valid": false}
}

func passingProofInputs() (
	[]string,
	[]map[string]interface{},
	map[string]string,
	map[string]interface{},
) {
	return []string{"auth"},
		[]map[string]interface{}{{
			"primitive_id": "auth",
			"version":      "1.0.0",
			"valid":        true,
			"metadata":     map[string]interface{}{"reason": "ok"},
			"evidence":     []interface{}{"allow-list"},
		}},
		map[string]string{"auth": "1.0.0", "not_evaluated": "9.9.9"},
		map[string]interface{}{
			"tenant": "example",
			"limits": map[string]interface{}{"requests": 10},
		}
}

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

func TestStrictSignalCommitmentSurfacesSerializationErrors(t *testing.T) {
	generator := &core.ProofGenerator{}
	unserializable := map[string]interface{}{"value": math.NaN()}

	commitment, err := generator.CommitSignalStrict(unserializable)
	require.Error(t, err)
	assert.Empty(t, commitment)
	assert.Empty(t, generator.CommitSignal(unserializable))
}

func TestProofGeneratorCopiesAndFiltersMutableInputs(t *testing.T) {
	generator := &core.ProofGenerator{}
	evaluated, signals, versions, context := passingProofInputs()

	proof, err := generator.GenerateProofForContext(
		true,
		evaluated,
		signals,
		versions,
		nil,
		context,
		10,
	)
	require.NoError(t, err)

	evaluated[0] = "changed"
	versions["auth"] = "2.0.0"
	versions["new"] = "1.0.0"
	signals[0]["metadata"].(map[string]interface{})["reason"] = "mutated"
	context["tenant"] = "mutated"

	assert.Equal(t, []string{"auth"}, proof.EvaluationOrder)
	assert.Equal(t, "1.0.0", proof.PrimitiveVersions["auth"])
	assert.NotContains(t, proof.PrimitiveVersions, "not_evaluated")
	assert.NotContains(t, proof.PrimitiveVersions, "new")
	assert.Equal(t, "ok", proof.Signals[0]["metadata"].(map[string]interface{})["reason"])
	assert.Equal(t, "example", proof.ContextSnapshot["tenant"])
}

func TestProofVerifyChecksEnvelopeWithoutExecutingPrimitives(t *testing.T) {
	generator := &core.ProofGenerator{}
	evaluated, signals, versions, context := passingProofInputs()
	proof, err := generator.GenerateProofForContext(
		true,
		evaluated,
		signals,
		versions,
		nil,
		context,
		42,
	)
	require.NoError(t, err)

	primitive := &verificationPrimitive{version: "1.0.0"}
	valid, err := proof.Verify(map[string]core.GovernancePrimitive{"auth": primitive})
	require.NoError(t, err)
	assert.True(t, valid)
	assert.Zero(t, primitive.evaluations)

	encoded, err := json.Marshal(proof)
	require.NoError(t, err)
	var restored core.GovernanceProof
	require.NoError(t, json.Unmarshal(encoded, &restored))
	valid, err = restored.Verify(map[string]core.GovernancePrimitive{"auth": primitive})
	require.NoError(t, err)
	assert.True(t, valid)
	assert.Zero(t, primitive.evaluations)
}

func TestProofVerifyRejectsTamperingAndVersionSubstitution(t *testing.T) {
	newProof := func(t *testing.T) *core.GovernanceProof {
		t.Helper()
		evaluated, signals, versions, context := passingProofInputs()
		proof, err := (&core.ProofGenerator{}).GenerateProofForContext(
			true,
			evaluated,
			signals,
			versions,
			nil,
			context,
			42,
		)
		require.NoError(t, err)
		return proof
	}

	t.Run("decision", func(t *testing.T) {
		proof := newProof(t)
		proof.Decision = false
		valid, err := proof.Verify(map[string]core.GovernancePrimitive{
			"auth": &verificationPrimitive{version: "1.0.0"},
		})
		assert.False(t, valid)
		assert.Error(t, err)
	})

	t.Run("signal", func(t *testing.T) {
		proof := newProof(t)
		proof.Signals[0]["metadata"].(map[string]interface{})["reason"] = "tampered"
		valid, err := proof.Verify(map[string]core.GovernancePrimitive{
			"auth": &verificationPrimitive{version: "1.0.0"},
		})
		assert.False(t, valid)
		assert.Error(t, err)
	})

	t.Run("context", func(t *testing.T) {
		proof := newProof(t)
		proof.ContextSnapshot["tenant"] = "tampered"
		valid, err := proof.Verify(map[string]core.GovernancePrimitive{
			"auth": &verificationPrimitive{version: "1.0.0"},
		})
		assert.False(t, valid)
		assert.Error(t, err)
	})

	t.Run("primitive version", func(t *testing.T) {
		proof := newProof(t)
		valid, err := proof.Verify(map[string]core.GovernancePrimitive{
			"auth": &verificationPrimitive{version: "2.0.0"},
		})
		assert.False(t, valid)
		assert.Error(t, err)
	})
}

func TestProofReconstructContextReturnsOnlyBoundDefensiveCopy(t *testing.T) {
	evaluated, signals, versions, context := passingProofInputs()
	proof, err := (&core.ProofGenerator{}).GenerateProofForContext(
		true,
		evaluated,
		signals,
		versions,
		nil,
		context,
		7,
	)
	require.NoError(t, err)

	reconstructed := proof.ReconstructContext(999)
	assert.Equal(t, "example", reconstructed["tenant"])
	reconstructed["tenant"] = "mutated"
	assert.Equal(t, "example", proof.ContextSnapshot["tenant"])

	proof.ContextSnapshot["tenant"] = "tampered"
	assert.Empty(t, proof.ReconstructContext(0))

	unbound := (&core.ProofGenerator{}).GenerateProof(false, nil, nil, map[string]string{})
	require.NotNil(t, unbound)
	assert.Empty(t, unbound.ReconstructContext(0))
}

func TestFailClosedProofShapesAndDecisionRecomputation(t *testing.T) {
	generator := &core.ProofGenerator{}
	denied, err := generator.GenerateProofForContext(
		false,
		nil,
		nil,
		map[string]string{"not_evaluated": "1.0.0"},
		[]string{"no governance primitives registered"},
		map[string]interface{}{},
		11,
	)
	require.NoError(t, err)
	assert.Empty(t, denied.PrimitiveVersions)
	valid, err := denied.Verify(map[string]core.GovernancePrimitive{})
	require.NoError(t, err)
	assert.True(t, valid)

	_, err = generator.GenerateProofForContext(
		true,
		nil,
		nil,
		map[string]string{},
		nil,
		nil,
		11,
	)
	assert.Error(t, err)

	evaluated, signals, versions, context := passingProofInputs()
	_, err = generator.GenerateProofForContext(
		false,
		evaluated,
		signals,
		versions,
		[]string{"claimed denial"},
		context,
		11,
	)
	assert.Error(t, err)

	signals[0]["valid"] = false
	denied, err = generator.GenerateProofForContext(
		false,
		evaluated,
		signals,
		versions,
		[]string{"auth denied"},
		context,
		11,
	)
	require.NoError(t, err)
	valid, err = denied.Verify(map[string]core.GovernancePrimitive{
		"auth": &verificationPrimitive{version: "1.0.0"},
	})
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestLegacyGeneratorIsDeterministicAndFailsClosedOnInvalidSignals(t *testing.T) {
	generator := &core.ProofGenerator{}
	evaluated, signals, versions, _ := passingProofInputs()

	first := generator.GenerateProof(true, evaluated, signals, versions)
	second := generator.GenerateProof(true, evaluated, signals, versions)
	require.NotNil(t, first)
	require.NotNil(t, second)
	assert.False(t, first.Decision)
	assert.NotEmpty(t, first.FailureReasons)
	assert.Zero(t, first.GeneratedAt)
	assert.Equal(t, first.EnvelopeCommitment, second.EnvelopeCommitment)

	signals[0]["evidence"] = []interface{}{make(chan int)}
	legacy := generator.GenerateProof(true, evaluated, signals, versions)
	require.NotNil(t, legacy)
	assert.False(t, legacy.Decision)
	assert.Empty(t, legacy.SignalCommitments)
	assert.NotEmpty(t, legacy.FailureReasons)

	_, err := generator.GenerateProofForContext(
		true,
		evaluated,
		signals,
		versions,
		nil,
		nil,
		0,
	)
	assert.Error(t, err)
}

func TestProofContextCommitmentPreservesTypesAndAvoidsCustomMarshalers(t *testing.T) {
	engine := core.NewGovernanceEngine()
	primitive := &MockPrimitive{name: "allow", version: "1", valid: true}
	require.NoError(t, engine.RegisterPrimitive("allow", primitive))

	integerDecision := engine.Evaluate(core.NewDeterministicContext(
		map[string]interface{}{"value": int64(1)}, 5,
	))
	floatDecision := engine.Evaluate(core.NewDeterministicContext(
		map[string]interface{}{"value": float64(1)}, 5,
	))
	require.True(t, integerDecision.Permitted)
	require.True(t, floatDecision.Permitted)
	assert.NotEqual(t, integerDecision.Proof.ContextCommitment, floatDecision.Proof.ContextCommitment)
	assert.NotEqual(t, integerDecision.Proof.EnvelopeCommitment, floatDecision.Proof.EnvelopeCommitment)

	var marshaledDecision *core.GovernanceDecision
	assert.NotPanics(t, func() {
		marshaledDecision = engine.Evaluate(core.NewDeterministicContext(
			map[string]interface{}{"value": panickingJSONNumber(7)}, 5,
		))
	})
	require.NotNil(t, marshaledDecision)
	assert.True(t, marshaledDecision.Permitted)
	verified, err := marshaledDecision.Proof.Verify(map[string]core.GovernancePrimitive{"allow": primitive})
	assert.NoError(t, err)
	assert.True(t, verified)
}

func TestProofVerificationRejectsPanickingPublicValuesWithoutPanicking(t *testing.T) {
	evaluated, signals, versions, context := passingProofInputs()
	newProof := func() *core.GovernanceProof {
		proof, err := (&core.ProofGenerator{}).GenerateProofForContext(
			true, evaluated, signals, versions, nil, context, 1,
		)
		require.NoError(t, err)
		return proof
	}
	primitives := map[string]core.GovernancePrimitive{
		"auth": &verificationPrimitive{version: "1.0.0"},
	}

	proof := newProof()
	proof.ContextSnapshot["evil"] = panickingJSONNumber(1)
	assert.NotPanics(t, func() {
		valid, err := proof.Verify(primitives)
		assert.False(t, valid)
		assert.Error(t, err)
	})

	proof = newProof()
	proof.Signals[0]["metadata"].(map[string]interface{})["evil"] = panickingJSONNumber(1)
	assert.NotPanics(t, func() {
		valid, err := proof.Verify(primitives)
		assert.False(t, valid)
		assert.Error(t, err)
		assert.Empty(t, proof.ReconstructContext(0))
	})
}
