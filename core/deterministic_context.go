/*
Deterministic execution context for GSAS.
*/

package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const maxContextDepth = 256

var jsonNumberType = reflect.TypeOf(json.Number(""))

// ValidationIssue identifies one value that could not be represented safely in
// a deterministic context.
type ValidationIssue struct {
	Path   string
	Reason string
}

// ValidationError reports invalid context values. Issues are ordered
// deterministically so identical invalid inputs produce identical errors.
type ValidationError struct {
	Issues []ValidationIssue
}

func (e *ValidationError) Error() string {
	if e == nil || len(e.Issues) == 0 {
		return "invalid deterministic context"
	}

	parts := make([]string, len(e.Issues))
	for i, issue := range e.Issues {
		parts[i] = fmt.Sprintf("%s: %s", issue.Path, issue.Reason)
	}
	return "invalid deterministic context: " + strings.Join(parts, "; ")
}

// DeterministicContext represents an immutable, deterministic evaluation context.
type DeterministicContext struct {
	data             map[string]interface{}
	time             int
	validationIssues []ValidationIssue
	commitment       string
	mu               sync.RWMutex
}

// NewDeterministicContext creates a deterministic context while preserving the
// historical constructor signature. Call ValidationError before evaluation;
// invalid values are excluded, valid siblings are retained, and the error is
// never silently discarded.
func NewDeterministicContext(data map[string]interface{}, logicalTime int) *DeterministicContext {
	return buildDeterministicContext(data, logicalTime)
}

// NewDeterministicContextChecked creates a context only when every value can be
// copied and committed deterministically.
func NewDeterministicContextChecked(data map[string]interface{}, logicalTime int) (*DeterministicContext, error) {
	ctx := buildDeterministicContext(data, logicalTime)
	if err := ctx.ValidationError(); err != nil {
		return nil, err
	}
	return ctx, nil
}

func buildDeterministicContext(data map[string]interface{}, logicalTime int) *DeterministicContext {
	frozenData, validationErr := cloneContextData(data)
	ctx := &DeterministicContext{
		data: frozenData,
		time: logicalTime,
	}
	if validationErr != nil {
		ctx.validationIssues = cloneValidationIssues(validationErr.Issues)
		return ctx
	}

	commitment, err := computeContextCommitment(frozenData, logicalTime)
	if err != nil {
		ctx.validationIssues = []ValidationIssue{{Path: "$", Reason: err.Error()}}
		return ctx
	}
	ctx.commitment = commitment
	return ctx
}

func cloneValidationIssues(issues []ValidationIssue) []ValidationIssue {
	return append([]ValidationIssue(nil), issues...)
}

// ValidationError returns the construction error, if any. The returned value is
// a copy and cannot mutate the context's validation state.
func (dc *DeterministicContext) ValidationError() error {
	if dc == nil {
		return &ValidationError{Issues: []ValidationIssue{{Path: "$", Reason: "context is nil"}}}
	}

	dc.mu.RLock()
	defer dc.mu.RUnlock()
	if len(dc.validationIssues) == 0 {
		return nil
	}
	return &ValidationError{Issues: cloneValidationIssues(dc.validationIssues)}
}

// IsValid reports whether the context was constructed entirely from supported,
// deterministic values.
func (dc *DeterministicContext) IsValid() bool {
	return dc != nil && dc.ValidationError() == nil
}

// Commitment returns a SHA-256 commitment binding the exact supported value
// types, values, container structure, and logical time.
func (dc *DeterministicContext) Commitment() (string, error) {
	if err := dc.ValidationError(); err != nil {
		return "", err
	}

	dc.mu.RLock()
	defer dc.mu.RUnlock()
	return dc.commitment, nil
}

type contextVisit struct {
	kind   reflect.Kind
	typeID string
	ptr    uintptr
}

type contextCloner struct {
	active map[contextVisit]struct{}
	issues []ValidationIssue
}

func cloneContextData(data map[string]interface{}) (map[string]interface{}, *ValidationError) {
	if data == nil {
		return make(map[string]interface{}), nil
	}

	cloner := &contextCloner{active: make(map[contextVisit]struct{})}
	cloned, keep := cloner.cloneValue(reflect.ValueOf(data), "$", 0)
	if !keep || !cloned.IsValid() {
		cloned = reflect.ValueOf(make(map[string]interface{}))
	}

	result := cloned.Interface().(map[string]interface{})
	if len(cloner.issues) == 0 {
		return result, nil
	}
	return result, &ValidationError{Issues: cloneValidationIssues(cloner.issues)}
}

func (c *contextCloner) addIssue(path, reason string) {
	c.issues = append(c.issues, ValidationIssue{Path: path, Reason: reason})
}

func (c *contextCloner) cloneValue(value reflect.Value, path string, depth int) (reflect.Value, bool) {
	if depth > maxContextDepth {
		c.addIssue(path, fmt.Sprintf("maximum nesting depth of %d exceeded", maxContextDepth))
		return reflect.Value{}, false
	}
	if !value.IsValid() {
		return reflect.Value{}, true
	}

	if value.Kind() == reflect.Interface {
		if value.IsNil() {
			return reflect.Zero(value.Type()), true
		}
		cloned, keep := c.cloneValue(value.Elem(), path, depth+1)
		if !keep {
			return reflect.Value{}, false
		}
		wrapped := reflect.New(value.Type()).Elem()
		wrapped.Set(cloned)
		return wrapped, true
	}

	switch value.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return copyScalar(value), true
	case reflect.String:
		if value.Type() == jsonNumberType && !validJSONNumber(value.String()) {
			c.addIssue(path, fmt.Sprintf("invalid JSON number %q", value.String()))
			return reflect.Value{}, false
		}
		return copyScalar(value), true
	case reflect.Float32, reflect.Float64:
		if math.IsNaN(value.Float()) || math.IsInf(value.Float(), 0) {
			c.addIssue(path, "non-finite floating-point value")
			return reflect.Value{}, false
		}
		return copyScalar(value), true
	case reflect.Map:
		return c.cloneMap(value, path, depth)
	case reflect.Slice:
		return c.cloneSlice(value, path, depth)
	case reflect.Array:
		return c.cloneArray(value, path, depth)
	default:
		c.addIssue(path, fmt.Sprintf("unsupported value type %s", value.Type()))
		return reflect.Value{}, false
	}
}

func copyScalar(value reflect.Value) reflect.Value {
	cloned := reflect.New(value.Type()).Elem()
	cloned.Set(value)
	return cloned
}

func validJSONNumber(number string) bool {
	_, err := json.Marshal(json.Number(number))
	return err == nil
}

func (c *contextCloner) cloneMap(value reflect.Value, path string, depth int) (reflect.Value, bool) {
	if value.Type().Key().Kind() != reflect.String {
		c.addIssue(path, fmt.Sprintf("map key type %s is not a string", value.Type().Key()))
		return reflect.Value{}, false
	}
	if value.IsNil() {
		return reflect.Zero(value.Type()), true
	}

	visit := contextVisit{kind: value.Kind(), typeID: canonicalTypeID(value.Type()), ptr: value.Pointer()}
	if _, exists := c.active[visit]; exists {
		c.addIssue(path, "cycle detected")
		return reflect.Value{}, false
	}
	c.active[visit] = struct{}{}
	defer delete(c.active, visit)

	keys := value.MapKeys()
	sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
	cloned := reflect.MakeMapWithSize(value.Type(), len(keys))
	for _, key := range keys {
		childPath := path + "[" + strconv.Quote(key.String()) + "]"
		child, keep := c.cloneValue(value.MapIndex(key), childPath, depth+1)
		if keep {
			cloned.SetMapIndex(key, child)
		}
	}
	return cloned, true
}

func (c *contextCloner) cloneSlice(value reflect.Value, path string, depth int) (reflect.Value, bool) {
	if value.IsNil() {
		return reflect.Zero(value.Type()), true
	}

	visit := contextVisit{kind: value.Kind(), typeID: canonicalTypeID(value.Type()), ptr: value.Pointer()}
	if _, exists := c.active[visit]; exists {
		c.addIssue(path, "cycle detected")
		return reflect.Value{}, false
	}
	c.active[visit] = struct{}{}
	defer delete(c.active, visit)

	cloned := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
	for i := 0; i < value.Len(); i++ {
		child, keep := c.cloneValue(value.Index(i), fmt.Sprintf("%s[%d]", path, i), depth+1)
		if keep {
			cloned.Index(i).Set(child)
		}
	}
	return cloned, true
}

func (c *contextCloner) cloneArray(value reflect.Value, path string, depth int) (reflect.Value, bool) {
	cloned := reflect.New(value.Type()).Elem()
	for i := 0; i < value.Len(); i++ {
		child, keep := c.cloneValue(value.Index(i), fmt.Sprintf("%s[%d]", path, i), depth+1)
		if keep {
			cloned.Index(i).Set(child)
		}
	}
	return cloned, true
}

// deepCopy and deepCopyValue operate only on already validated context data.
func deepCopy(data map[string]interface{}) map[string]interface{} {
	cloned, _ := cloneContextData(data)
	return cloned
}

func deepCopyValue(data interface{}) interface{} {
	if data == nil {
		return nil
	}
	cloner := &contextCloner{active: make(map[contextVisit]struct{})}
	cloned, keep := cloner.cloneValue(reflect.ValueOf(data), "$", 0)
	if !keep || !cloned.IsValid() {
		return nil
	}
	return cloned.Interface()
}

func computeContextCommitment(data map[string]interface{}, logicalTime int) (string, error) {
	var canonical bytes.Buffer
	writeFrame(&canonical, "GSAS-DETERMINISTIC-CONTEXT-v1")
	writeFrame(&canonical, strconv.FormatInt(int64(logicalTime), 10))
	if err := writeCanonicalValue(&canonical, reflect.ValueOf(data)); err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical.Bytes())
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func writeCanonicalValue(output *bytes.Buffer, value reflect.Value) error {
	if !value.IsValid() {
		output.WriteByte('n')
		return nil
	}
	if value.Kind() == reflect.Interface {
		if value.IsNil() {
			output.WriteByte('n')
			return nil
		}
		return writeCanonicalValue(output, value.Elem())
	}

	writeFrame(output, canonicalTypeID(value.Type()))
	switch value.Kind() {
	case reflect.Bool:
		output.WriteByte('b')
		if value.Bool() {
			output.WriteByte(1)
		} else {
			output.WriteByte(0)
		}
	case reflect.String:
		output.WriteByte('s')
		writeFrame(output, value.String())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		output.WriteByte('i')
		writeFrame(output, strconv.FormatInt(value.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		output.WriteByte('u')
		writeFrame(output, strconv.FormatUint(value.Uint(), 10))
	case reflect.Float32, reflect.Float64:
		output.WriteByte('f')
		writeFrame(output, strconv.FormatFloat(value.Float(), 'g', -1, value.Type().Bits()))
	case reflect.Map:
		output.WriteByte('m')
		if value.IsNil() {
			output.WriteByte(0)
			return nil
		}
		output.WriteByte(1)
		keys := value.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
		writeLength(output, len(keys))
		for _, key := range keys {
			writeFrame(output, key.String())
			if err := writeCanonicalValue(output, value.MapIndex(key)); err != nil {
				return err
			}
		}
	case reflect.Slice:
		output.WriteByte('l')
		if value.IsNil() {
			output.WriteByte(0)
			return nil
		}
		output.WriteByte(1)
		writeLength(output, value.Len())
		for i := 0; i < value.Len(); i++ {
			if err := writeCanonicalValue(output, value.Index(i)); err != nil {
				return err
			}
		}
	case reflect.Array:
		output.WriteByte('a')
		writeLength(output, value.Len())
		for i := 0; i < value.Len(); i++ {
			if err := writeCanonicalValue(output, value.Index(i)); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("cannot commit unsupported value type %s", value.Type())
	}
	return nil
}

func canonicalTypeID(valueType reflect.Type) string {
	if valueType.Name() != "" {
		if valueType.PkgPath() == "" {
			return valueType.Name()
		}
		return valueType.PkgPath() + "." + valueType.Name()
	}
	switch valueType.Kind() {
	case reflect.Map:
		return "map[" + canonicalTypeID(valueType.Key()) + "]" + canonicalTypeID(valueType.Elem())
	case reflect.Slice:
		return "[]" + canonicalTypeID(valueType.Elem())
	case reflect.Array:
		return fmt.Sprintf("[%d]%s", valueType.Len(), canonicalTypeID(valueType.Elem()))
	case reflect.Interface:
		return valueType.String()
	default:
		return valueType.String()
	}
}

func writeFrame(output *bytes.Buffer, value string) {
	writeLength(output, len(value))
	output.WriteString(value)
}

func writeLength(output *bytes.Buffer, length int) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(length))
	output.Write(encoded[:])
}

// Get retrieves a value from the context with default fallback.
func (dc *DeterministicContext) Get(key string, defaultValue interface{}) interface{} {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	if val, exists := dc.data[key]; exists {
		return deepCopyValue(val)
	}
	return defaultValue
}

// Has checks if a key exists in the context.
func (dc *DeterministicContext) Has(key string) bool {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	_, exists := dc.data[key]
	return exists
}

// Time returns the logical time of the context.
func (dc *DeterministicContext) Time() int {
	return dc.time
}

// Data returns a copy of the internal data map.
func (dc *DeterministicContext) Data() map[string]interface{} {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	return deepCopy(dc.data)
}

// String returns a string representation of the context.
func (dc *DeterministicContext) String() string {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	return fmt.Sprintf("DeterministicContext(time=%d, data=%v)", dc.time, dc.data)
}

// GetItem retrieves a value from the context by key.
func (dc *DeterministicContext) GetItem(key string) (interface{}, error) {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	if val, exists := dc.data[key]; exists {
		return deepCopyValue(val), nil
	}
	return nil, fmt.Errorf("key '%s' not found", key)
}

// SetItem prevents modification of the context.
func (dc *DeterministicContext) SetItem(key string, value interface{}) error {
	return fmt.Errorf("context is immutable")
}

// DeleteItem prevents modification of the context.
func (dc *DeterministicContext) DeleteItem(key string) error {
	return fmt.Errorf("context is immutable")
}
