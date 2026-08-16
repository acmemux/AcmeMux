package integrations

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/sgurden-certleap/AcmeMux/internal/compatibility"
)

// SelectorSegment is an immutable server-side YAML selector component.
type SelectorSegment struct {
	key     string
	binding BindingID
}

// YAMLKey creates one literal native mapping-key selector.
func YAMLKey(key string) SelectorSegment { return SelectorSegment{key: key} }

// YAMLBinding creates one logical named-map selector.
func YAMLBinding(binding BindingID) SelectorSegment { return SelectorSegment{binding: binding} }

func (s SelectorSegment) Key() (string, bool) { return s.key, s.key != "" }

func (s SelectorSegment) Binding() (BindingID, bool) { return s.binding, s.binding != "" }

// FieldDefinition is accepted only from trusted server manifest code.
type FieldDefinition struct {
	ID          FieldID
	Label       string
	Kind        FieldKind
	Target      FieldTarget
	Sensitivity Sensitivity
	Disposition Disposition
	// Selector addresses the YAML value for TargetYAML. For TargetDotenv it
	// addresses the YAML envFile scalar whose resolved file owns EnvironmentKey.
	Selector       []SelectorSegment
	EnvironmentKey string
	// PruneEmptyParents removes empty structural mappings below the last
	// binding after a leaf removal. It is reserved for native objects such as
	// EAB whose empty mapping is schema-invalid; most empty native objects carry
	// defaults and must remain intact.
	PruneEmptyParents bool
	Default           *Value
	Rules             Rules
}

// FieldSpec is an immutable logical-to-native mapping.
type FieldSpec struct {
	id             FieldID
	label          string
	kind           FieldKind
	target         FieldTarget
	sensitivity    Sensitivity
	disposition    Disposition
	selector       []SelectorSegment
	environmentKey string
	pruneEmpty     bool
	bindings       []BindingID
	defaultVal     *Value
	rules          Rules
}

func NewFieldSpec(definition FieldDefinition) (FieldSpec, error) {
	if !validFieldID(definition.ID) {
		return FieldSpec{}, fmt.Errorf("invalid field ID")
	}
	if definition.Label == "" || len(definition.Label) > 128 || !utf8.ValidString(definition.Label) ||
		strings.TrimSpace(definition.Label) != definition.Label || strings.IndexFunc(definition.Label, func(character rune) bool {
		return character < 0x20 || character == 0x7f
	}) >= 0 {
		return FieldSpec{}, fmt.Errorf("invalid field label")
	}
	if definition.Kind != FieldString && definition.Kind != FieldBoolean && definition.Kind != FieldInteger && definition.Kind != FieldStringList {
		return FieldSpec{}, fmt.Errorf("invalid field kind")
	}
	if definition.Target != TargetYAML && definition.Target != TargetDotenv {
		return FieldSpec{}, fmt.Errorf("invalid field target")
	}
	if definition.Target == TargetYAML && definition.EnvironmentKey != "" {
		return FieldSpec{}, fmt.Errorf("YAML field has an environment key")
	}
	if definition.Target == TargetDotenv {
		if len(definition.EnvironmentKey) > 128 || !environmentKeyPattern.MatchString(definition.EnvironmentKey) {
			return FieldSpec{}, fmt.Errorf("dotenv field has an invalid environment key")
		}
		if definition.Kind != FieldString {
			return FieldSpec{}, fmt.Errorf("dotenv field must be a string")
		}
		if definition.Sensitivity != SensitivitySecret {
			return FieldSpec{}, fmt.Errorf("dotenv field must be secret")
		}
	}
	if definition.Sensitivity != SensitivityPublic && definition.Sensitivity != SensitivitySecret {
		return FieldSpec{}, fmt.Errorf("invalid field sensitivity")
	}
	if definition.Sensitivity == SensitivitySecret && definition.Kind != FieldString {
		return FieldSpec{}, fmt.Errorf("secret field must be a string")
	}
	if definition.Disposition != DispositionManaged && definition.Disposition != DispositionPreservedSafe {
		return FieldSpec{}, fmt.Errorf("invalid field disposition")
	}
	if len(definition.Selector) == 0 || len(definition.Selector) > 16 {
		return FieldSpec{}, fmt.Errorf("invalid selector length")
	}
	bindings := make([]BindingID, 0, len(definition.Selector))
	for _, segment := range definition.Selector {
		hasKey := segment.key != ""
		hasBinding := segment.binding != ""
		if hasKey == hasBinding {
			return FieldSpec{}, fmt.Errorf("selector segment must name one key or binding")
		}
		if hasKey && !validYAMLKey(segment.key) {
			return FieldSpec{}, fmt.Errorf("invalid YAML selector key")
		}
		if hasBinding {
			if !validBindingID(segment.binding) || slices.Contains(bindings, segment.binding) {
				return FieldSpec{}, fmt.Errorf("invalid or duplicate selector binding")
			}
			bindings = append(bindings, segment.binding)
		}
	}
	if err := definition.Rules.validate(definition.Kind); err != nil {
		return FieldSpec{}, fmt.Errorf("invalid field rules: %w", err)
	}
	if err := validateWireRules(definition); err != nil {
		return FieldSpec{}, err
	}
	var defaultValue *Value
	if definition.Default != nil {
		if definition.Sensitivity == SensitivitySecret {
			return FieldSpec{}, fmt.Errorf("secret field has a default")
		}
		value := cloneValue(*definition.Default)
		candidate := FieldSpec{kind: definition.Kind, rules: definition.Rules}
		if err := candidate.ValidateValue(value); err != nil {
			return FieldSpec{}, fmt.Errorf("invalid field default: %w", err)
		}
		defaultValue = &value
	}
	return FieldSpec{
		id:             definition.ID,
		label:          definition.Label,
		kind:           definition.Kind,
		target:         definition.Target,
		sensitivity:    definition.Sensitivity,
		disposition:    definition.Disposition,
		selector:       slices.Clone(definition.Selector),
		environmentKey: definition.EnvironmentKey,
		pruneEmpty:     definition.PruneEmptyParents,
		bindings:       bindings,
		defaultVal:     defaultValue,
		rules:          definition.Rules.clone(),
	}, nil
}

func validateWireRules(definition FieldDefinition) error {
	switch definition.Kind {
	case FieldString:
		maximum := 4096
		if definition.Sensitivity == SensitivitySecret {
			maximum = 64 << 10
		}
		if definition.Rules.MaxBytes <= 0 || definition.Rules.MaxBytes > maximum {
			return fmt.Errorf("string field exceeds the shared wire bound")
		}
	case FieldStringList:
		if definition.Rules.MaxItems <= 0 || definition.Rules.MaxItems > 256 ||
			definition.Rules.MaxBytes <= 0 || definition.Rules.MaxBytes > 4096 {
			return fmt.Errorf("list field exceeds the shared wire bound")
		}
	case FieldInteger:
		if definition.Rules.Minimum == nil || definition.Rules.Maximum == nil ||
			*definition.Rules.Minimum < -maximumSafeInteger || *definition.Rules.Maximum > maximumSafeInteger {
			return fmt.Errorf("integer field exceeds the shared wire bound")
		}
	}
	for _, item := range definition.Rules.Enum {
		if !validManagedText(item, false) || len(item) > 4096 {
			return fmt.Errorf("field enum is not safe for the shared wire contract")
		}
	}
	return nil
}

func (s FieldSpec) ID() FieldID                 { return s.id }
func (s FieldSpec) Label() string               { return s.label }
func (s FieldSpec) Kind() FieldKind             { return s.kind }
func (s FieldSpec) Target() FieldTarget         { return s.target }
func (s FieldSpec) Sensitivity() Sensitivity    { return s.sensitivity }
func (s FieldSpec) Disposition() Disposition    { return s.disposition }
func (s FieldSpec) Editable() bool              { return s.disposition == DispositionManaged }
func (s FieldSpec) PruneEmptyParents() bool     { return s.pruneEmpty }
func (s FieldSpec) BindingIDs() []BindingID     { return slices.Clone(s.bindings) }
func (s FieldSpec) Selector() []SelectorSegment { return slices.Clone(s.selector) }
func (s FieldSpec) EnvironmentKey() (string, bool) {
	return s.environmentKey, s.target == TargetDotenv
}
func (s FieldSpec) Default() (Value, bool) {
	if s.defaultVal == nil {
		return Value{}, false
	}
	return cloneValue(*s.defaultVal), true
}

// Match binds an actual YAML key path to this logical field.
func (s FieldSpec) Match(path []string) (map[BindingID]string, bool) {
	if len(path) != len(s.selector) {
		return nil, false
	}
	bindings := make(map[BindingID]string, len(s.bindings))
	for index, segment := range s.selector {
		if segment.key != "" {
			if path[index] != segment.key {
				return nil, false
			}
			continue
		}
		if !validBindingValue(path[index]) {
			return nil, false
		}
		bindings[segment.binding] = path[index]
	}
	return bindings, true
}

// HasPathPrefix reports whether an existing mapping path can lead to this
// field. It lets the editor distinguish a reviewed container from a wholly
// unsupported subtree.
func (s FieldSpec) HasPathPrefix(path []string) bool {
	if len(path) > len(s.selector) {
		return false
	}
	for index := range path {
		segment := s.selector[index]
		if segment.key != "" && segment.key != path[index] || segment.binding != "" && !validBindingValue(path[index]) {
			return false
		}
	}
	return true
}

// Resolve converts logical binding values into a native path using only the
// selector retained by trusted server code.
func (s FieldSpec) Resolve(bindings map[BindingID]string) ([]string, error) {
	if len(bindings) != len(s.bindings) {
		return nil, fmt.Errorf("field bindings are incomplete")
	}
	path := make([]string, len(s.selector))
	for index, segment := range s.selector {
		if segment.key != "" {
			path[index] = segment.key
			continue
		}
		value, ok := bindings[segment.binding]
		if !ok || !validBindingValue(value) {
			return nil, fmt.Errorf("field binding is missing or invalid")
		}
		path[index] = value
	}
	for key := range bindings {
		if !slices.Contains(s.bindings, key) {
			return nil, fmt.Errorf("field binding is not declared")
		}
	}
	return path, nil
}

func cloneSpec(spec FieldSpec) FieldSpec {
	spec.selector = slices.Clone(spec.selector)
	spec.bindings = slices.Clone(spec.bindings)
	spec.rules = spec.rules.clone()
	if spec.defaultVal != nil {
		value := cloneValue(*spec.defaultVal)
		spec.defaultVal = &value
	}
	return spec
}

// ManifestID identifies one revision of a curated integration contract.
type ManifestID string

// Manifest is immutable after construction.
type Manifest struct {
	id         ManifestID
	runtimeIDs []compatibility.ManifestID
	fields     map[FieldID]FieldSpec
}

func NewManifest(id ManifestID, runtimeIDs []compatibility.ManifestID, fields ...FieldSpec) (Manifest, error) {
	if id == "" || len(id) > 128 || strings.TrimSpace(string(id)) != string(id) {
		return Manifest{}, fmt.Errorf("invalid manifest ID")
	}
	if len(runtimeIDs) == 0 {
		return Manifest{}, fmt.Errorf("manifest has no runtime identities")
	}
	runtimeIDs = slices.Clone(runtimeIDs)
	slices.Sort(runtimeIDs)
	for index, runtimeID := range runtimeIDs {
		if runtimeID == "" || index > 0 && runtimeID == runtimeIDs[index-1] {
			return Manifest{}, fmt.Errorf("runtime identities are empty or duplicate")
		}
	}
	fieldMap := make(map[FieldID]FieldSpec, len(fields))
	for _, field := range fields {
		if !validFieldID(field.id) || len(field.selector) == 0 {
			return Manifest{}, fmt.Errorf("manifest contains an invalid field")
		}
		if _, duplicate := fieldMap[field.id]; duplicate {
			return Manifest{}, fmt.Errorf("manifest contains duplicate field ID")
		}
		for _, existing := range fieldMap {
			if sameNativeTarget(existing, field) {
				return Manifest{}, fmt.Errorf("manifest maps two fields to one selector")
			}
		}
		fieldMap[field.id] = cloneSpec(field)
	}
	return Manifest{id: id, runtimeIDs: runtimeIDs, fields: fieldMap}, nil
}

func (m Manifest) ID() ManifestID { return m.id }

func (m Manifest) SupportsRuntime(id compatibility.ManifestID) bool {
	return slices.Contains(m.runtimeIDs, id)
}

func (m Manifest) RuntimeManifestIDs() []compatibility.ManifestID {
	return slices.Clone(m.runtimeIDs)
}

func (m Manifest) Field(id FieldID) (FieldSpec, bool) {
	field, ok := m.fields[id]
	return cloneSpec(field), ok
}

func (m Manifest) Fields() []FieldSpec {
	result := make([]FieldSpec, 0, len(m.fields))
	for _, field := range m.fields {
		result = append(result, cloneSpec(field))
	}
	sort.Slice(result, func(left, right int) bool { return result[left].id < result[right].id })
	return result
}

func (m Manifest) Match(path []string) (FieldSpec, map[BindingID]string, bool) {
	return m.MatchTarget(path, TargetYAML)
}

// MatchTarget binds a native path only within the requested server-curated
// target. Dotenv selectors address the YAML scalar containing the reference,
// never an environment key supplied by a caller.
func (m Manifest) MatchTarget(path []string, target FieldTarget) (FieldSpec, map[BindingID]string, bool) {
	for _, field := range m.Fields() {
		if field.target != target {
			continue
		}
		if bindings, ok := field.Match(path); ok {
			return field, bindings, true
		}
	}
	return FieldSpec{}, nil, false
}

func (m Manifest) HasPathPrefix(path []string) bool {
	return m.HasPathPrefixForTarget(path, TargetYAML)
}

func (m Manifest) HasPathPrefixForTarget(path []string, target FieldTarget) bool {
	for _, field := range m.fields {
		if field.target != target {
			continue
		}
		if field.HasPathPrefix(path) {
			return true
		}
	}
	return false
}

// Extend returns a new manifest without mutating the base contract.
func (m Manifest) Extend(id ManifestID, fields ...FieldSpec) (Manifest, error) {
	all := m.Fields()
	all = append(all, fields...)
	return NewManifest(id, m.runtimeIDs, all...)
}

func sameNativeTarget(left, right FieldSpec) bool {
	if left.target != right.target || !slices.Equal(left.selector, right.selector) {
		return false
	}
	return left.target == TargetYAML || left.environmentKey == right.environmentKey
}
