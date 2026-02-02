/*
Type-safe contracts for GSAS governance primitives.
*/

package core

// EvaluationResult represents the result returned by governance primitive evaluation
type EvaluationResult map[string]interface{}

// GovernancePrimitive defines the interface for all governance primitives
type GovernancePrimitive interface {
	// Version returns a stable version identifier for this primitive
	Version() string

	// Evaluate evaluates the primitive against a deterministic context
	Evaluate(context interface{}) map[string]interface{}
}

// NamedPrimitive extends GovernancePrimitive with a name
type NamedPrimitive interface {
	GovernancePrimitive
	Name() string
}