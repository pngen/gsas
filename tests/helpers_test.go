/*
Shared test helpers and fixtures for GSAS tests.
*/

package tests

import "gsas/core"

// MockPrimitive is a test double for GovernancePrimitive
type MockPrimitive struct {
	name    string
	version string
	valid   bool
}

func (m *MockPrimitive) Name() string    { return m.name }
func (m *MockPrimitive) Version() string { return m.version }
func (m *MockPrimitive) Evaluate(ctx interface{}) map[string]interface{} {
	return map[string]interface{}{
		"valid":    m.valid,
		"metadata": map[string]interface{}{"primitive": m.name},
		"evidence": []interface{}{},
	}
}

// Ensure MockPrimitive implements interfaces
var _ core.GovernancePrimitive = (*MockPrimitive)(nil)
var _ core.NamedPrimitive = (*MockPrimitive)(nil)