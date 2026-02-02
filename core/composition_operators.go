/*
Primitive composition operators for GSAS.
*/

package core

import (
	"fmt"
	"hash/fnv"
)

// getPrimitiveName safely gets name from primitive
func getPrimitiveName(p GovernancePrimitive, index int) string {
	if np, ok := p.(NamedPrimitive); ok {
		return np.Name()
	}
	return fmt.Sprintf("primitive_%d", index)
}

// PrimitiveComposer composes primitives with explicit semantics
type PrimitiveComposer struct{}

// SequentialAnd returns a primitive that requires all input primitives to pass in order
func (pc *PrimitiveComposer) SequentialAnd(primitives []GovernancePrimitive) GovernancePrimitive {
	primitivesCaptured := primitives // Capture for closure

	return &sequentialAndPrimitive{
		primitives: primitivesCaptured,
	}
}

type sequentialAndPrimitive struct {
	primitives []GovernancePrimitive
}

func (p *sequentialAndPrimitive) Version() string {
	subVersions := make([]string, len(p.primitives))
	for i, primitive := range p.primitives {
		subVersions[i] = primitive.Version()
	}
	h := fnv.New64a()
	for _, v := range subVersions {
		h.Write([]byte(v))
	}
	return fmt.Sprintf("sequential-and-%d", h.Sum64()%1000000)
}

func (p *sequentialAndPrimitive) Evaluate(context interface{}) map[string]interface{} {
	for i, primitive := range p.primitives {
		result := primitive.Evaluate(context)
		valid, ok := result["valid"].(bool)
		if !ok || !valid {
			return map[string]interface{}{
				"valid": false,
				"metadata": map[string]interface{}{
					"reason":       fmt.Sprintf("Primitive %s failed", getPrimitiveName(primitive, i)),
					"failed_index": i,
				},
				"evidence": []interface{}{},
			}
		}
	}
	return map[string]interface{}{
		"valid": true,
		"metadata": map[string]interface{}{
			"message": "All primitives passed sequentially",
		},
		"evidence": []interface{}{},
	}
}

// ParallelAnd returns a primitive that requires all input primitives to pass, order independent
func (pc *PrimitiveComposer) ParallelAnd(primitives []GovernancePrimitive) GovernancePrimitive {
	primitivesCaptured := primitives

	return &parallelAndPrimitive{
		primitives: primitivesCaptured,
	}
}

type parallelAndPrimitive struct {
	primitives []GovernancePrimitive
}

func (p *parallelAndPrimitive) Version() string {
	subVersions := make([]string, len(p.primitives))
	for i, primitive := range p.primitives {
		subVersions[i] = primitive.Version()
	}
	h := fnv.New64a()
	for _, v := range subVersions {
		h.Write([]byte(v))
	}
	return fmt.Sprintf("parallel-and-%d", h.Sum64()%1000000)
}

func (p *parallelAndPrimitive) Evaluate(context interface{}) map[string]interface{} {
	results := make([]bool, len(p.primitives))
	for i, primitive := range p.primitives {
		result := primitive.Evaluate(context)
		valid, ok := result["valid"].(bool)
		results[i] = ok && valid
	}

	allPassed := true
	for _, r := range results {
		if !r {
			allPassed = false
			break
		}
	}

	if allPassed {
		return map[string]interface{}{
			"valid": true,
			"metadata": map[string]interface{}{
				"message": "All primitives passed in parallel",
			},
			"evidence": []interface{}{},
		}
	} else {
		failedPrimitives := make([]string, 0)
		for i, primitive := range p.primitives {
			if !results[i] {
				failedPrimitives = append(failedPrimitives, getPrimitiveName(primitive, i))
			}
		}
		return map[string]interface{}{
			"valid": false,
			"metadata": map[string]interface{}{
				"reason": fmt.Sprintf("Failed primitives: %v", failedPrimitives),
			},
			"evidence": []interface{}{},
		}
	}
}

// Threshold returns a primitive that requires at least k of the input primitives to pass
func (pc *PrimitiveComposer) Threshold(primitives []GovernancePrimitive, k int) GovernancePrimitive {
	primitivesCaptured := primitives
	kCaptured := k

	return &thresholdPrimitive{
		primitives: primitivesCaptured,
		k:          kCaptured,
	}
}

type thresholdPrimitive struct {
	primitives []GovernancePrimitive
	k          int
}

func (p *thresholdPrimitive) Version() string {
	subVersions := make([]string, len(p.primitives))
	for i, primitive := range p.primitives {
		subVersions[i] = primitive.Version()
	}
	h := fnv.New64a()
	for _, v := range subVersions {
		h.Write([]byte(v))
	}
	return fmt.Sprintf("threshold-%d-%d", p.k, h.Sum64()%1000000)
}

func (p *thresholdPrimitive) Evaluate(context interface{}) map[string]interface{} {
	results := make([]bool, len(p.primitives))
	for i, primitive := range p.primitives {
		result := primitive.Evaluate(context)
		valid, ok := result["valid"].(bool)
		results[i] = ok && valid
	}

	passedCount := 0
	for _, r := range results {
		if r {
			passedCount++
		}
	}

	if passedCount >= p.k {
		return map[string]interface{}{
			"valid": true,
			"metadata": map[string]interface{}{
				"message": fmt.Sprintf("%d of %d primitives passed", passedCount, len(p.primitives)),
			},
			"evidence": []interface{}{},
		}
	} else {
		return map[string]interface{}{
			"valid": false,
			"metadata": map[string]interface{}{
				"reason": fmt.Sprintf("Only %d of %d primitives passed, need at least %d", passedCount, len(p.primitives), p.k),
			},
			"evidence": []interface{}{},
		}
	}
}