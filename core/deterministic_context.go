/*
Deterministic execution context for GSAS.
*/

package core

import (
	"encoding/json"
	"fmt"
	"sync"
)

// DeterministicContext represents an immutable, deterministic evaluation context
type DeterministicContext struct {
	data map[string]interface{}
	time int
	mu   sync.RWMutex
}

// NewDeterministicContext creates a new deterministic context
func NewDeterministicContext(data map[string]interface{}, logicalTime int) *DeterministicContext {
	frozenData := deepCopy(data)
	return &DeterministicContext{
		data: frozenData,
		time: logicalTime,
	}
}

// deepCopy creates a deep copy using JSON marshaling for true immutability
func deepCopy(d map[string]interface{}) map[string]interface{} {
	if d == nil {
		return make(map[string]interface{})
	}
	bytes, err := json.Marshal(d)
	if err != nil {
		return make(map[string]interface{})
	}
	var result map[string]interface{}
	if err := json.Unmarshal(bytes, &result); err != nil {
		return make(map[string]interface{})
	}
	return result
}

// deepCopyValue recursively copies a value
func deepCopyValue(d interface{}) interface{} {
	if d == nil {
		return nil
	}

	switch v := d.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{})
		for k, val := range v {
			result[k] = deepCopyValue(val)
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, val := range v {
			result[i] = deepCopyValue(val)
		}
		return result
	default:
		return d
	}
}

// Get retrieves a value from the context with default fallback
func (dc *DeterministicContext) Get(key string, defaultValue interface{}) interface{} {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	if val, exists := dc.data[key]; exists {
		return deepCopyValue(val)
	}
	return defaultValue
}

// Has checks if a key exists in the context
func (dc *DeterministicContext) Has(key string) bool {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	_, exists := dc.data[key]
	return exists
}

// Time returns the logical time of the context
func (dc *DeterministicContext) Time() int {
	return dc.time
}

// Data returns a copy of the internal data map
func (dc *DeterministicContext) Data() map[string]interface{} {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	return deepCopy(dc.data)
}

// String returns a string representation of the context
func (dc *DeterministicContext) String() string {
	return fmt.Sprintf("DeterministicContext(time=%d, data=%v)", dc.time, dc.data)
}

// GetItem retrieves a value from the context by key
func (dc *DeterministicContext) GetItem(key string) (interface{}, error) {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	if val, exists := dc.data[key]; exists {
		return deepCopyValue(val), nil
	}
	return nil, fmt.Errorf("key '%s' not found", key)
}

// SetItem prevents modification of the context (not implemented in Go due to immutability)
func (dc *DeterministicContext) SetItem(key string, value interface{}) error {
	return fmt.Errorf("context is immutable")
}

// DeleteItem prevents modification of the context (not implemented in Go due to immutability)
func (dc *DeterministicContext) DeleteItem(key string) error {
	return fmt.Errorf("context is immutable")
}