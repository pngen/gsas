package tests

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gsas/core"
)

type typedNilPrimitive struct{}

func (*typedNilPrimitive) Version() string { return "1.0.0" }
func (*typedNilPrimitive) Evaluate(interface{}) map[string]interface{} {
	return validResult(nil)
}

type countedPrimitive struct {
	calls       int
	panicAfter  int
	malformedAt int
	alternateAt int
	engine      *core.GovernanceEngine
}

func (p *countedPrimitive) Version() string { return "1.0.0" }
func (p *countedPrimitive) Evaluate(interface{}) map[string]interface{} {
	p.calls++
	if p.engine != nil && p.calls > 2 {
		p.engine.Clear()
	}
	if p.panicAfter > 0 && p.calls >= p.panicAfter {
		panic("primitive failure")
	}
	if p.malformedAt > 0 && p.calls >= p.malformedAt {
		return map[string]interface{}{
			"valid": true, "metadata": map[string]interface{}{"bad": func() {}}, "evidence": []interface{}{},
		}
	}
	valid := true
	if p.alternateAt > 0 && p.calls >= p.alternateAt {
		valid = p.calls%2 == 1
	}
	return validResult(map[string]interface{}{"call_class": "stable"}, valid)
}

type mutableVersionPrimitive struct {
	version string
}

func (p *mutableVersionPrimitive) Version() string { return p.version }
func (p *mutableVersionPrimitive) Evaluate(interface{}) map[string]interface{} {
	return validResult(nil)
}

type retainedMetadataPrimitive struct {
	metadata map[string]interface{}
}

type runtimeAliasedPrimitive struct {
	calls  int
	result map[string]interface{}
}

func (p *runtimeAliasedPrimitive) Version() string { return "1.0.0" }
func (p *runtimeAliasedPrimitive) Evaluate(interface{}) map[string]interface{} {
	p.calls++
	valid := true
	if p.calls > 2 {
		valid = p.calls%2 == 0
	}
	p.result["valid"] = valid
	return p.result
}

type mutableConfigurationPrimitive struct {
	threshold int
}

func (p *mutableConfigurationPrimitive) Version() string { return "1.0.0" }
func (p *mutableConfigurationPrimitive) ValidateConfiguration() error {
	if p.threshold <= 0 {
		return fmt.Errorf("threshold must be positive")
	}
	return nil
}
func (p *mutableConfigurationPrimitive) ConfigurationFingerprint() string {
	return fmt.Sprintf("threshold:%d", p.threshold)
}
func (p *mutableConfigurationPrimitive) Evaluate(interface{}) map[string]interface{} {
	return validResult(nil, p.threshold == 0)
}

type recursiveRegistrationPrimitive struct {
	engine    *core.GovernanceEngine
	attempted bool
	nestedErr error
}

func (p *recursiveRegistrationPrimitive) Version() string { return "1.0.0" }
func (p *recursiveRegistrationPrimitive) Evaluate(interface{}) map[string]interface{} {
	if !p.attempted {
		p.attempted = true
		p.nestedErr = p.engine.RegisterPrimitive("nested", p)
	}
	return validResult(nil)
}

type recursiveEvaluationPrimitive struct {
	engine       *core.GovernanceEngine
	calls        int
	nestedDenied bool
}

func (p *recursiveEvaluationPrimitive) Version() string { return "1.0.0" }
func (p *recursiveEvaluationPrimitive) Evaluate(context interface{}) map[string]interface{} {
	p.calls++
	if p.calls > 2 {
		ctx := context.(*core.DeterministicContext)
		cloned := core.NewDeterministicContext(ctx.Data(), ctx.Time())
		p.nestedDenied = !p.engine.Evaluate(cloned).Permitted
	}
	return validResult(nil)
}

type concurrentPrimitive struct {
	mu      sync.Mutex
	calls   int
	started chan struct{}
	release chan struct{}
}

func (p *concurrentPrimitive) Version() string { return "1.0.0" }
func (p *concurrentPrimitive) Evaluate(interface{}) map[string]interface{} {
	p.mu.Lock()
	p.calls++
	call := p.calls
	p.mu.Unlock()
	if call == 3 || call == 4 {
		p.started <- struct{}{}
		<-p.release
	}
	return validResult(nil)
}

type slowRegistrationPrimitive struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (p *slowRegistrationPrimitive) Version() string { return "1.0.0" }
func (p *slowRegistrationPrimitive) Evaluate(interface{}) map[string]interface{} {
	p.once.Do(func() {
		close(p.started)
		<-p.release
	})
	return validResult(nil)
}

func (p *retainedMetadataPrimitive) Version() string { return "1.0.0" }
func (p *retainedMetadataPrimitive) Evaluate(interface{}) map[string]interface{} {
	return map[string]interface{}{
		"valid": true, "metadata": p.metadata, "evidence": []interface{}{"checked"},
	}
}

func validResult(optional ...interface{}) map[string]interface{} {
	metadata := map[string]interface{}{}
	valid := true
	if len(optional) > 0 {
		if supplied, ok := optional[0].(map[string]interface{}); ok && supplied != nil {
			metadata = supplied
		}
	}
	if len(optional) > 1 {
		valid, _ = optional[1].(bool)
	}
	return map[string]interface{}{
		"valid": valid, "metadata": metadata, "evidence": []interface{}{},
	}
}

func TestEngineFailsClosedWithoutPolicyOrContext(t *testing.T) {
	engine := core.NewGovernanceEngine()
	ctx := core.NewDeterministicContext(nil, 7)

	empty := engine.Evaluate(ctx)
	assert.False(t, empty.Permitted)
	require.NotNil(t, empty.Proof)
	verified, err := empty.Proof.Verify(nil)
	assert.NoError(t, err)
	assert.True(t, verified)
	assert.Equal(t, int64(7), empty.Proof.GeneratedAt)

	require.NoError(t, engine.RegisterPrimitive("allow", &MockPrimitive{name: "allow", version: "1", valid: true}))
	missing := engine.Evaluate(nil)
	assert.False(t, missing.Permitted)
	assert.Contains(t, missing.FailureReasons[0], "context")
}

func TestInvalidContextCannotEraseDenialInput(t *testing.T) {
	engine := core.NewGovernanceEngine()
	require.NoError(t, engine.RegisterPrimitive("allow", &MockPrimitive{name: "allow", version: "1", valid: true}))
	ctx := core.NewDeterministicContext(map[string]interface{}{
		"authorized": false,
		"invalid":    func() {},
	}, 1)

	decision := engine.Evaluate(ctx)
	assert.False(t, decision.Permitted)
	assert.Contains(t, decision.FailureReasons[0], "invalid deterministic context")
	assert.Equal(t, false, ctx.Get("authorized", true))
}

func TestTypedNilPrimitiveIsRejected(t *testing.T) {
	engine := core.NewGovernanceEngine()
	var primitive *typedNilPrimitive
	assert.Error(t, engine.RegisterPrimitive("nil", primitive))
}

func TestPanicsMalformedResultsAndNonRepeatabilityBecomeDenials(t *testing.T) {
	tests := []struct {
		name      string
		primitive *countedPrimitive
		reason    string
	}{
		{name: "panic", primitive: &countedPrimitive{panicAfter: 3}, reason: "panicked"},
		{name: "malformed", primitive: &countedPrimitive{malformedAt: 3}, reason: "unsupported value type"},
		{name: "nonrepeatable", primitive: &countedPrimitive{alternateAt: 3}, reason: "non-deterministic"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			engine := core.NewGovernanceEngine()
			require.NoError(t, engine.RegisterPrimitive("policy", test.primitive))
			decision := engine.Evaluate(core.NewDeterministicContext(nil, 1))
			assert.False(t, decision.Permitted)
			assert.Contains(t, decision.FailureReasons[0], test.reason)
			require.NotNil(t, decision.Proof)
		})
	}
}

func TestEngineSnapshotsFirstAliasedResultBeforeSecondEvaluation(t *testing.T) {
	engine := core.NewGovernanceEngine()
	primitive := &runtimeAliasedPrimitive{result: map[string]interface{}{
		"valid": true, "metadata": map[string]interface{}{}, "evidence": []interface{}{},
	}}
	require.NoError(t, engine.RegisterPrimitive("aliased", primitive))

	decision := engine.Evaluate(core.NewDeterministicContext(nil, 1))
	assert.False(t, decision.Permitted)
	assert.Contains(t, decision.FailureReasons[0], "non-deterministic")
}

func TestPrimitiveCallbackCanReenterEngineWithoutDeadlock(t *testing.T) {
	engine := core.NewGovernanceEngine()
	primitive := &countedPrimitive{engine: engine}
	require.NoError(t, engine.RegisterPrimitive("reentrant", primitive))

	done := make(chan *core.GovernanceDecision, 1)
	go func() { done <- engine.Evaluate(core.NewDeterministicContext(nil, 1)) }()
	select {
	case decision := <-done:
		assert.False(t, decision.Permitted)
		assert.Contains(t, decision.FailureReasons[0], "configuration changed")
	case <-time.After(time.Second):
		t.Fatal("governance evaluation deadlocked while a primitive reentered the engine")
	}
}

func TestConcurrentEvaluationsCanShareImmutableContext(t *testing.T) {
	engine := core.NewGovernanceEngine()
	primitive := &concurrentPrimitive{
		started: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	require.NoError(t, engine.RegisterPrimitive("concurrent", primitive))
	ctx := core.NewDeterministicContext(map[string]interface{}{"request": "same"}, 3)

	decisions := make(chan *core.GovernanceDecision, 2)
	for index := 0; index < 2; index++ {
		go func() { decisions <- engine.Evaluate(ctx) }()
	}
	for index := 0; index < 2; index++ {
		select {
		case <-primitive.started:
		case <-time.After(time.Second):
			t.Fatal("concurrent evaluations did not enter primitive callbacks")
		}
	}
	close(primitive.release)
	for index := 0; index < 2; index++ {
		select {
		case decision := <-decisions:
			assert.True(t, decision.Permitted)
		case <-time.After(time.Second):
			t.Fatal("concurrent evaluation did not complete")
		}
	}
}

func TestVersionDriftFailsClosed(t *testing.T) {
	engine := core.NewGovernanceEngine()
	primitive := &mutableVersionPrimitive{version: "1.0.0"}
	require.NoError(t, engine.RegisterPrimitive("mutable", primitive))
	primitive.version = "2.0.0"

	decision := engine.Evaluate(core.NewDeterministicContext(nil, 1))
	assert.False(t, decision.Permitted)
	assert.Contains(t, decision.FailureReasons[0], "version drift")
	assert.Equal(t, "1.0.0", decision.Proof.PrimitiveVersions["mutable"])
}

func TestConfigurationDriftFailsClosed(t *testing.T) {
	engine := core.NewGovernanceEngine()
	primitive := &mutableConfigurationPrimitive{threshold: 1}
	require.NoError(t, engine.RegisterPrimitive("configured", primitive))
	primitive.threshold = 0

	decision := engine.Evaluate(core.NewDeterministicContext(nil, 1))
	assert.False(t, decision.Permitted)
	assert.Contains(t, decision.FailureReasons[0], "threshold must be positive")

	engine = core.NewGovernanceEngine()
	primitive = &mutableConfigurationPrimitive{threshold: 1}
	composite := (&core.PrimitiveComposer{}).SequentialAnd([]core.GovernancePrimitive{primitive})
	require.NoError(t, engine.RegisterPrimitive("composite", composite))
	primitive.threshold = 0
	decision = engine.Evaluate(core.NewDeterministicContext(nil, 1))
	assert.False(t, decision.Permitted)
	assert.Contains(t, decision.FailureReasons[0], "version drift")
}

func TestRecursiveRegistrationAndEvaluationFailClosedWithoutOverflow(t *testing.T) {
	engine := core.NewGovernanceEngine()
	registrationPrimitive := &recursiveRegistrationPrimitive{engine: engine}
	require.Error(t, engine.RegisterPrimitive("outer", registrationPrimitive))
	require.Error(t, registrationPrimitive.nestedErr)
	assert.Contains(t, registrationPrimitive.nestedErr.Error(), "recursively")

	engine = core.NewGovernanceEngine()
	evaluationPrimitive := &recursiveEvaluationPrimitive{engine: engine}
	require.NoError(t, engine.RegisterPrimitive("recursive", evaluationPrimitive))
	decision := engine.Evaluate(core.NewDeterministicContext(nil, 2))
	assert.True(t, evaluationPrimitive.nestedDenied)
	assert.False(t, decision.Permitted)
	assert.Contains(t, decision.FailureReasons[0], "recursive governance evaluation")
}

func TestClearReportsConflictInsteadOfDroppingRevocation(t *testing.T) {
	engine := core.NewGovernanceEngine()
	require.NoError(t, engine.RegisterPrimitive("existing", &MockPrimitive{name: "existing", version: "1", valid: true}))
	primitive := &slowRegistrationPrimitive{started: make(chan struct{}), release: make(chan struct{})}
	registrationResult := make(chan error, 1)
	go func() { registrationResult <- engine.RegisterPrimitive("slow", primitive) }()

	select {
	case <-primitive.started:
	case <-time.After(time.Second):
		t.Fatal("registration did not reach compliance callback")
	}
	clearErr := engine.Clear()
	assert.Error(t, clearErr)
	close(primitive.release)
	assert.Error(t, <-registrationResult)
	assert.Equal(t, 1, engine.PrimitiveCount())
}

func TestSignalsAndProofsSnapshotPrimitiveOwnedData(t *testing.T) {
	engine := core.NewGovernanceEngine()
	primitive := &retainedMetadataPrimitive{metadata: map[string]interface{}{"owner": "finance"}}
	require.NoError(t, engine.RegisterPrimitive("snapshot", primitive))
	decision := engine.Evaluate(core.NewDeterministicContext(map[string]interface{}{"request": "x"}, 4))
	require.True(t, decision.Permitted)

	primitive.metadata["owner"] = "attacker"
	metadata := decision.Signals[0]["metadata"].(map[string]interface{})
	assert.Equal(t, "finance", metadata["owner"])
	verified, err := decision.Proof.Verify(map[string]core.GovernancePrimitive{"snapshot": primitive})
	assert.NoError(t, err)
	assert.True(t, verified)
}

func TestProofUsesContextTimeAndOnlyEvaluatedVersions(t *testing.T) {
	engine := core.NewGovernanceEngine()
	require.NoError(t, engine.RegisterPrimitive("deny", &MockPrimitive{name: "deny", version: "1", valid: false}))
	require.NoError(t, engine.RegisterPrimitive("later", &MockPrimitive{name: "later", version: "1", valid: true}))
	ctx := core.NewDeterministicContext(map[string]interface{}{"request": 1}, 9)

	decision := engine.Evaluate(ctx)
	assert.False(t, decision.Permitted)
	assert.Equal(t, int64(9), decision.Proof.GeneratedAt)
	assert.Equal(t, []string{"deny"}, decision.Proof.EvaluationOrder)
	assert.Equal(t, map[string]string{"deny": "1"}, decision.Proof.PrimitiveVersions)

	mismatched := engine.EvaluateWithLogicalTime(ctx, 10)
	assert.False(t, mismatched.Permitted)
	assert.Contains(t, mismatched.FailureReasons[0], "does not match")
	assert.Equal(t, int64(9), mismatched.Proof.GeneratedAt)
}
