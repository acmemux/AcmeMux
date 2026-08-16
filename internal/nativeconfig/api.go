package nativeconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"

	"github.com/sgurden-certleap/AcmeMux/internal/integrations"
)

// Limits bounds every input-derived allocation and diagnostic collection.
type Limits struct {
	MaxBytes            int
	MaxNodes            int
	MaxDepth            int
	MaxIssues           int
	MaxProjectionFields int
	MaxChanges          int
}

// DefaultLimits are deliberately generous for a home-lab lego workspace but
// small enough to keep hostile configuration input bounded.
func DefaultLimits() Limits {
	return Limits{
		MaxBytes:            1 << 20,
		MaxNodes:            50_000,
		MaxDepth:            64,
		MaxIssues:           256,
		MaxProjectionFields: 1_024,
		MaxChanges:          256,
	}
}

type ErrorCode string

const (
	ErrorInvalidLimits     ErrorCode = "invalid_limits"
	ErrorRuntimeMismatch   ErrorCode = "runtime_mismatch"
	ErrorManifestInvalid   ErrorCode = "manifest_invalid"
	ErrorSchemaInvalid     ErrorCode = "schema_invalid"
	ErrorSourceEmpty       ErrorCode = "source_empty"
	ErrorSourceTooLarge    ErrorCode = "source_too_large"
	ErrorInvalidUTF8       ErrorCode = "invalid_utf8"
	ErrorMalformedYAML     ErrorCode = "malformed_yaml"
	ErrorMultipleDocuments ErrorCode = "multiple_documents"
	ErrorRootNotMapping    ErrorCode = "root_not_mapping"
	ErrorStructureComplex  ErrorCode = "structure_too_complex"
	ErrorAliasUnsupported  ErrorCode = "alias_not_supported"
	ErrorMergeUnsupported  ErrorCode = "merge_not_supported"
	ErrorTagUnsupported    ErrorCode = "tag_not_supported"
	ErrorDuplicateKey      ErrorCode = "duplicate_key"
	ErrorInvalidChange     ErrorCode = "invalid_change"
)

// Error contains only a stable code and fixed, value-free description.
type Error struct {
	Code   ErrorCode
	Detail string
}

func (e *Error) Error() string { return string(e.Code) + ": " + e.Detail }

// CodeOf extracts a stable native-configuration error code through wrapped
// errors. It returns the empty code for nil or foreign errors.
func CodeOf(err error) ErrorCode {
	var configurationError *Error
	if errors.As(err, &configurationError) {
		return configurationError.Code
	}
	return ""
}

type IssueClass string

const (
	IssueSchema      IssueClass = "schema"
	IssueSemantic    IssueClass = "semantic"
	IssueUnsupported IssueClass = "unsupported"
	IssueUnknown     IssueClass = "unknown"
)

// Issue describes a native location without including the value found there.
type Issue struct {
	Class             IssueClass
	Path              string
	Line              int
	Column            int
	Summary           string
	BlocksReplacement bool
	BlocksExecution   bool
}

// Binding is a logical entity identity, never a YAML selector component.
type Binding struct {
	ID    integrations.BindingID
	Value string
}

type ProjectedField struct {
	FieldID       integrations.FieldID
	Bindings      []Binding
	Label         string
	Kind          integrations.FieldKind
	Present       bool
	Defaulted     bool
	Configured    bool
	PresenceKnown bool
	Secret        bool
	value         integrations.Value
	hasValue      bool
}

// Value returns a projected public value. Secret values are never retained in
// a ProjectedField and therefore always return false.
func (p ProjectedField) Value() (integrations.Value, bool) {
	if p.Secret || !p.hasValue {
		return integrations.Value{}, false
	}
	return p.value, true
}

// DotenvPresence lets the trusted service layer add exact-key presence after
// consulting internal/dotenv. It carries logical IDs only.
type DotenvPresence struct {
	FieldID  integrations.FieldID
	Bindings []Binding
	Present  bool
	Valid    bool
}

// DotenvRoute is server-only lookup metadata derived from a curated manifest
// and the native YAML. None of its sensitive routing fields are exported for
// accidental JSON serialization.
type DotenvRoute struct {
	fieldID        integrations.FieldID
	bindings       []Binding
	reference      string
	environmentKey string
	secret         bool
	spec           integrations.FieldSpec
}

func (r DotenvRoute) FieldID() integrations.FieldID { return r.fieldID }
func (r DotenvRoute) Bindings() []Binding           { return slices.Clone(r.bindings) }
func (r DotenvRoute) Label() string                 { return r.spec.Label() }
func (r DotenvRoute) Reference() string             { return r.reference }
func (r DotenvRoute) EnvironmentKey() string        { return r.environmentKey }
func (r DotenvRoute) Secret() bool                  { return r.secret }
func (r DotenvRoute) ValidValue(value []byte) bool  { return r.spec.ValidateSecretBytes(value) == nil }

type Inspection struct {
	SourceSHA256  string
	Projection    []ProjectedField
	Issues        []Issue
	SchemaValid   bool
	SemanticValid bool
	Replaceable   bool
	Executable    bool
	routes        []DotenvRoute
	maxIssues     int
}

func (i Inspection) DotenvRoutes() []DotenvRoute { return cloneRoutes(i.routes) }

// WithDotenvPresence returns a defensive projection copy with trusted
// exact-key lookup results applied. Unknown logical identities are ignored.
func (i Inspection) WithDotenvPresence(presence []DotenvPresence) Inspection {
	i.Projection = cloneProjection(i.Projection)
	for _, item := range presence {
		for index := range i.Projection {
			field := &i.Projection[index]
			if field.FieldID != item.FieldID || !equalBindings(field.Bindings, item.Bindings) {
				continue
			}
			field.PresenceKnown = true
			field.Present = item.Present
			field.Configured = item.Present && item.Valid
			if item.Present && !item.Valid {
				i.Executable = false
				if len(i.Issues) < i.maxIssues {
					i.Issues = append(i.Issues, Issue{
						Class: IssueUnsupported, Summary: "Credential value is outside the curated integration contract.",
						BlocksExecution: true,
					})
				}
			}
		}
	}
	return i
}

type Operation string

const (
	OperationSet    Operation = "set"
	OperationRemove Operation = "remove"
)

// Change is a logical typed edit. Native selectors and dotenv keys never
// cross the request boundary.
type Change struct {
	FieldID   integrations.FieldID
	Bindings  []Binding
	Operation Operation
	Value     integrations.Value
}

type SummaryAction string

const (
	SummarySet    SummaryAction = "set"
	SummaryRemove SummaryAction = "remove"
)

type ChangeSummary struct {
	FieldID   integrations.FieldID
	Bindings  []Binding
	Label     string
	Target    integrations.FieldTarget
	Action    SummaryAction
	Secret    bool
	before    integrations.Value
	after     integrations.Value
	hasBefore bool
	hasAfter  bool
}

func (s ChangeSummary) Before() (integrations.Value, bool) {
	if s.Secret || !s.hasBefore {
		return integrations.Value{}, false
	}
	return s.before, true
}

func (s ChangeSummary) After() (integrations.Value, bool) {
	if s.Secret || !s.hasAfter {
		return integrations.Value{}, false
	}
	return s.after, true
}

// ExternalChange routes one normalized dotenv edit. Its exact reference and
// environment key are derived server-side and are not exported as fields.
type ExternalChange struct {
	fieldID        integrations.FieldID
	bindings       []Binding
	operation      Operation
	reference      string
	environmentKey string
	secret         bool
	value          integrations.Value
}

func (c ExternalChange) FieldID() integrations.FieldID { return c.fieldID }
func (c ExternalChange) Bindings() []Binding           { return slices.Clone(c.bindings) }
func (c ExternalChange) Operation() Operation          { return c.operation }
func (c ExternalChange) Reference() string             { return c.reference }
func (c ExternalChange) EnvironmentKey() string        { return c.environmentKey }
func (c ExternalChange) Secret() bool                  { return c.secret }
func (c ExternalChange) Value() (integrations.Value, bool) {
	return c.value, c.operation == OperationSet
}

// Candidate owns secret-bearing candidate bytes. Call Clear when the caller
// no longer needs them.
type Candidate struct {
	yaml            []byte
	SourceSHA256    string
	CandidateSHA256 string
	Changed         bool
	Inspection      Inspection
	Summary         []ChangeSummary
	external        []ExternalChange
}

func (c *Candidate) YAML() []byte {
	if c == nil {
		return nil
	}
	return slices.Clone(c.yaml)
}

func (c *Candidate) ExternalChanges() []ExternalChange {
	if c == nil {
		return nil
	}
	result := slices.Clone(c.external)
	for index := range result {
		result[index].bindings = slices.Clone(result[index].bindings)
	}
	return result
}

func (c *Candidate) Clear() {
	if c == nil {
		return
	}
	clear(c.yaml)
	c.yaml = nil
	for index := range c.external {
		c.external[index].value = integrations.Value{}
	}
	c.external = nil
}

func digest(source []byte) string {
	sum := sha256.Sum256(source)
	return hex.EncodeToString(sum[:])
}

func cloneProjection(source []ProjectedField) []ProjectedField {
	result := slices.Clone(source)
	for index := range result {
		result[index].Bindings = slices.Clone(result[index].Bindings)
	}
	return result
}

func cloneRoutes(source []DotenvRoute) []DotenvRoute {
	result := slices.Clone(source)
	for index := range result {
		result[index].bindings = slices.Clone(result[index].bindings)
	}
	return result
}

func equalBindings(left, right []Binding) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
