package tests

import (
	"math"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gsas/core"
)

func TestDeterministicContextPreservesNumbersAndIsolation(t *testing.T) {
	maximum := uint64(math.MaxUint64)
	nested := map[string]interface{}{
		"maximum": maximum,
		"signed":  int64(-9_007_199_254_740_993),
		"items":   []interface{}{map[string]interface{}{"allowed": true}},
	}

	ctx, err := core.NewDeterministicContextChecked(nested, 42)
	require.NoError(t, err)
	assert.Equal(t, maximum, ctx.Get("maximum", nil))
	assert.Equal(t, int64(-9_007_199_254_740_993), ctx.Get("signed", nil))

	nested["maximum"] = uint64(1)
	nested["items"].([]interface{})[0].(map[string]interface{})["allowed"] = false
	assert.Equal(t, maximum, ctx.Get("maximum", nil))
	items := ctx.Get("items", nil).([]interface{})
	assert.Equal(t, true, items[0].(map[string]interface{})["allowed"])

	items[0].(map[string]interface{})["allowed"] = false
	itemsAgain := ctx.Get("items", nil).([]interface{})
	assert.Equal(t, true, itemsAgain[0].(map[string]interface{})["allowed"])
}

func TestDeterministicContextCopiesTypedJSONContainers(t *testing.T) {
	typed := map[string][]uint64{
		"identifiers": {math.MaxUint64, 9_007_199_254_740_993},
	}

	ctx, err := core.NewDeterministicContextChecked(map[string]interface{}{"typed": typed}, 1)
	require.NoError(t, err)
	typed["identifiers"][0] = 0

	fromContext := ctx.Get("typed", nil).(map[string][]uint64)
	assert.Equal(t, uint64(math.MaxUint64), fromContext["identifiers"][0])
	assert.Equal(t, uint64(9_007_199_254_740_993), fromContext["identifiers"][1])
	fromContext["identifiers"][0] = 1
	assert.Equal(t, uint64(math.MaxUint64), ctx.Get("typed", nil).(map[string][]uint64)["identifiers"][0])
}

func TestDeterministicContextRetainsValidSiblingsAndReportsInvalidInput(t *testing.T) {
	ctx := core.NewDeterministicContext(map[string]interface{}{
		"deny": true,
		"bad":  func() {},
	}, 7)

	require.Error(t, ctx.ValidationError())
	assert.False(t, ctx.IsValid())
	assert.Equal(t, true, ctx.Get("deny", nil))
	assert.False(t, ctx.Has("bad"))
	_, err := ctx.Commitment()
	assert.Error(t, err)

	checked, err := core.NewDeterministicContextChecked(map[string]interface{}{
		"deny": true,
		"bad":  make(chan int),
	}, 7)
	assert.Nil(t, checked)
	assert.Error(t, err)
}

func TestDeterministicContextRejectsNonFiniteValuesAndCycles(t *testing.T) {
	cyclicMap := map[string]interface{}{"safe": "retained"}
	cyclicMap["self"] = cyclicMap
	cyclicSlice := make([]interface{}, 1)
	cyclicSlice[0] = cyclicSlice

	ctx := core.NewDeterministicContext(map[string]interface{}{
		"map":   cyclicMap,
		"slice": cyclicSlice,
		"nan":   math.NaN(),
		"pos":   math.Inf(1),
		"neg":   math.Inf(-1),
	}, 0)

	err := ctx.ValidationError()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cycle detected")
	assert.Contains(t, err.Error(), "non-finite floating-point value")
	retained := ctx.Get("map", nil).(map[string]interface{})
	assert.Equal(t, "retained", retained["safe"])
	assert.NotContains(t, retained, "self")
}

func TestDeterministicContextCommitmentIsCanonicalAndTypeAware(t *testing.T) {
	first, err := core.NewDeterministicContextChecked(map[string]interface{}{
		"b": []interface{}{true, "value"},
		"a": uint64(1),
	}, 12)
	require.NoError(t, err)
	second, err := core.NewDeterministicContextChecked(map[string]interface{}{
		"a": uint64(1),
		"b": []interface{}{true, "value"},
	}, 12)
	require.NoError(t, err)

	firstCommitment, err := first.Commitment()
	require.NoError(t, err)
	secondCommitment, err := second.Commitment()
	require.NoError(t, err)
	assert.Equal(t, firstCommitment, secondCommitment)
	assert.True(t, strings.HasPrefix(firstCommitment, "sha256:"))
	assert.Len(t, strings.TrimPrefix(firstCommitment, "sha256:"), 64)

	differentType, err := core.NewDeterministicContextChecked(map[string]interface{}{"a": int64(1), "b": []interface{}{true, "value"}}, 12)
	require.NoError(t, err)
	differentTime, err := core.NewDeterministicContextChecked(map[string]interface{}{"a": uint64(1), "b": []interface{}{true, "value"}}, 13)
	require.NoError(t, err)
	differentTypeCommitment, err := differentType.Commitment()
	require.NoError(t, err)
	differentTimeCommitment, err := differentTime.Commitment()
	require.NoError(t, err)
	assert.NotEqual(t, firstCommitment, differentTypeCommitment)
	assert.NotEqual(t, firstCommitment, differentTimeCommitment)
}
