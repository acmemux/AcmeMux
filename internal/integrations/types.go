package integrations

import (
	"bytes"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// FieldID is the stable logical name accepted by trusted application code.
// It is deliberately not a YAML path.
type FieldID string

// BindingID names a logical entity selected by a field, such as an account or
// certificate name. Binding values remain native map keys, not path syntax.
type BindingID string

// FieldKind identifies the only value shapes accepted by generic patches.
type FieldKind string

const (
	FieldString     FieldKind = "string"
	FieldBoolean    FieldKind = "boolean"
	FieldInteger    FieldKind = "integer"
	FieldStringList FieldKind = "string_list"
)

const maximumSafeInteger = int64(1<<53 - 1)

// FieldTarget states which native file owns a field value.
type FieldTarget string

const (
	TargetYAML   FieldTarget = "yaml"
	TargetDotenv FieldTarget = "dotenv"
)

// Sensitivity controls whether a projected or summarized value may be shown.
type Sensitivity string

const (
	SensitivityPublic Sensitivity = "public"
	SensitivitySecret Sensitivity = "secret"
)

// Disposition distinguishes a managed form field from schema-recognized
// content that a manifest has explicitly reviewed as safe to preserve.
type Disposition string

const (
	DispositionManaged       Disposition = "managed"
	DispositionPreservedSafe Disposition = "preserved_safe"
)

var (
	fieldIDWithUnderscore = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
	bindingIDPattern      = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	bindingValuePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]*$`)
	environmentKeyPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
)

// Value is a closed typed field value. Its payload is private so an arbitrary
// interface value cannot bypass a FieldSpec's declared kind.
type Value struct {
	kind        FieldKind
	stringValue string
	boolValue   bool
	intValue    int64
	listValue   []string
}

// ValidateSecretBytes applies the immutable dotenv string contract without
// converting a confidential value to an immutable Go string.
func (s FieldSpec) ValidateSecretBytes(value []byte) error {
	if s.target != TargetDotenv || s.sensitivity != SensitivitySecret || s.kind != FieldString {
		return fmt.Errorf("field is not a managed dotenv secret")
	}
	rules := s.rules
	if !rules.AllowEmpty && len(value) == 0 {
		return fmt.Errorf("value must not be empty")
	}
	if !utf8.Valid(value) || bytes.IndexFunc(value, func(character rune) bool {
		return character < 0x20 || character == 0x7f
	}) >= 0 {
		return fmt.Errorf("value contains unsupported text")
	}
	if len(value) < rules.MinBytes || rules.MaxBytes > 0 && len(value) > rules.MaxBytes {
		return fmt.Errorf("value length is outside field bounds")
	}
	if len(rules.Enum) != 0 {
		matched := false
		for _, allowed := range rules.Enum {
			if len(allowed) == len(value) && bytes.Equal([]byte(allowed), value) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("value is outside the field enum")
		}
	}
	return nil
}

func StringValue(value string) Value { return Value{kind: FieldString, stringValue: value} }

func BooleanValue(value bool) Value { return Value{kind: FieldBoolean, boolValue: value} }

func IntegerValue(value int64) Value { return Value{kind: FieldInteger, intValue: value} }

func StringListValue(value []string) Value {
	return Value{kind: FieldStringList, listValue: slices.Clone(value)}
}

func (v Value) Kind() FieldKind { return v.kind }

func (v Value) String() (string, bool) {
	return v.stringValue, v.kind == FieldString
}

func (v Value) Boolean() (bool, bool) { return v.boolValue, v.kind == FieldBoolean }

func (v Value) Integer() (int64, bool) { return v.intValue, v.kind == FieldInteger }

func (v Value) StringList() ([]string, bool) {
	if v.kind != FieldStringList {
		return nil, false
	}
	return slices.Clone(v.listValue), true
}

func cloneValue(value Value) Value {
	value.listValue = slices.Clone(value.listValue)
	return value
}

// Rules supplies generic, source-independent field bounds. Feature manifests
// layer their semantic validators on top of these mechanical constraints.
type Rules struct {
	AllowEmpty bool
	MinBytes   int
	MaxBytes   int
	MinItems   int
	MaxItems   int
	Minimum    *int64
	Maximum    *int64
	Enum       []string
}

func (r Rules) clone() Rules {
	r.Enum = slices.Clone(r.Enum)
	if r.Minimum != nil {
		value := *r.Minimum
		r.Minimum = &value
	}
	if r.Maximum != nil {
		value := *r.Maximum
		r.Maximum = &value
	}
	return r
}

func (r Rules) validate(kind FieldKind) error {
	if r.MinBytes < 0 || r.MaxBytes < 0 || r.MinItems < 0 || r.MaxItems < 0 {
		return fmt.Errorf("negative rule bound")
	}
	if r.MaxBytes > 0 && r.MinBytes > r.MaxBytes {
		return fmt.Errorf("string bounds are inverted")
	}
	if r.MaxItems > 0 && r.MinItems > r.MaxItems {
		return fmt.Errorf("list bounds are inverted")
	}
	if r.Minimum != nil && r.Maximum != nil && *r.Minimum > *r.Maximum {
		return fmt.Errorf("integer bounds are inverted")
	}
	if len(r.Enum) > 0 && kind != FieldString {
		return fmt.Errorf("enum requires a string field")
	}
	if len(r.Enum) > 0 {
		seen := make(map[string]struct{}, len(r.Enum))
		for _, item := range r.Enum {
			if item == "" || !slices.IsSorted(r.Enum) {
				return fmt.Errorf("enum is empty or unsorted")
			}
			if _, exists := seen[item]; exists {
				return fmt.Errorf("enum contains a duplicate")
			}
			seen[item] = struct{}{}
		}
	}
	return nil
}

// ValidateValue applies the field's generic bounds without returning the
// rejected value in an error.
func (s FieldSpec) ValidateValue(value Value) error {
	if value.Kind() != s.kind {
		return fmt.Errorf("value kind does not match field")
	}
	rules := s.rules
	switch s.kind {
	case FieldString:
		text, _ := value.String()
		if !rules.AllowEmpty && text == "" {
			return fmt.Errorf("value must not be empty")
		}
		if !validManagedText(text, rules.AllowEmpty) {
			return fmt.Errorf("value contains unsupported text")
		}
		if len(text) < rules.MinBytes || rules.MaxBytes > 0 && len(text) > rules.MaxBytes {
			return fmt.Errorf("value length is outside field bounds")
		}
		if len(rules.Enum) > 0 && !slices.Contains(rules.Enum, text) {
			return fmt.Errorf("value is outside the field enum")
		}
	case FieldStringList:
		values, _ := value.StringList()
		if !rules.AllowEmpty && len(values) == 0 {
			return fmt.Errorf("value must not be empty")
		}
		if len(values) < rules.MinItems || rules.MaxItems > 0 && len(values) > rules.MaxItems {
			return fmt.Errorf("list length is outside field bounds")
		}
		for _, item := range values {
			if !rules.AllowEmpty && item == "" {
				return fmt.Errorf("list item must not be empty")
			}
			if len(item) < rules.MinBytes || rules.MaxBytes > 0 && len(item) > rules.MaxBytes {
				return fmt.Errorf("list item length is outside field bounds")
			}
			if !validManagedText(item, rules.AllowEmpty) {
				return fmt.Errorf("list item contains unsupported text")
			}
		}
	case FieldInteger:
		integer, _ := value.Integer()
		if rules.Minimum != nil && integer < *rules.Minimum || rules.Maximum != nil && integer > *rules.Maximum {
			return fmt.Errorf("integer is outside field bounds")
		}
	case FieldBoolean:
	default:
		return fmt.Errorf("field kind is invalid")
	}
	return nil
}

func validManagedText(value string, allowEmpty bool) bool {
	if value == "" {
		return allowEmpty
	}
	return utf8.ValidString(value) && strings.IndexFunc(value, func(character rune) bool {
		return character < 0x20 || character == 0x7f
	}) < 0
}

func validFieldID(value FieldID) bool {
	return len(value) <= 128 && fieldIDWithUnderscore.MatchString(string(value))
}

func validBindingID(value BindingID) bool {
	return len(value) <= 64 && bindingIDPattern.MatchString(string(value))
}

func validBindingValue(value string) bool {
	return len(value) <= 64 && bindingValuePattern.MatchString(value)
}

func validYAMLKey(value string) bool {
	return value != "" && len(value) <= 256 && utf8.ValidString(value) && strings.TrimSpace(value) == value &&
		strings.IndexFunc(value, func(character rune) bool { return character < 0x20 || character == 0x7f }) < 0
}
