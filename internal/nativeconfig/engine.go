package nativeconfig

import (
	"errors"
	"slices"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/sgurden-certleap/AcmeMux/internal/compatibility"
	"github.com/sgurden-certleap/AcmeMux/internal/integrations"
	"go.yaml.in/yaml/v3"
)

const schemaResourceURL = "https://acmemux.invalid/schema/lego-configuration.json"

type rejectingLoader struct{}

func (rejectingLoader) Load(string) (any, error) {
	return nil, errors.New("external schema resources are disabled")
}

type Engine struct {
	runtimeID compatibility.ManifestID
	manifest  integrations.Manifest
	schema    *jsonschema.Schema
	limits    Limits
}

// NewEngine binds one exact upstream schema and one curated integration
// manifest to an admitted runtime identity. Compilation performs no filesystem
// or network resolution.
func NewEngine(runtimeID compatibility.ManifestID, exactSchema []byte, manifest integrations.Manifest, limits Limits) (*Engine, error) {
	normalized, err := normalizeLimits(limits)
	if err != nil {
		return nil, err
	}
	if runtimeID == "" || !manifest.SupportsRuntime(runtimeID) {
		return nil, &Error{Code: ErrorRuntimeMismatch, Detail: "integration manifest does not support the runtime identity"}
	}
	for _, field := range manifest.Fields() {
		if !compatibleManifestField(field) {
			return nil, &Error{Code: ErrorManifestInvalid, Detail: "integration field does not match the admitted native configuration model"}
		}
	}
	if len(exactSchema) == 0 || len(exactSchema) > 8<<20 {
		return nil, &Error{Code: ErrorSchemaInvalid, Detail: "exact schema bytes are empty or too large"}
	}
	runtimeManifest, ok := compatibility.Lookup(runtimeID)
	if !ok || digest(exactSchema) != runtimeManifest.Schema.SHA256 {
		return nil, &Error{Code: ErrorSchemaInvalid, Detail: "schema bytes do not match the exact runtime manifest"}
	}
	compiled, err := compileSchema(exactSchema)
	if err != nil {
		return nil, err
	}
	return &Engine{runtimeID: runtimeID, manifest: manifest, schema: compiled, limits: normalized}, nil
}

func compileSchema(exactSchema []byte) (*jsonschema.Schema, error) {
	document, err := jsonschema.UnmarshalJSON(strings.NewReader(string(exactSchema)))
	if err != nil {
		return nil, &Error{Code: ErrorSchemaInvalid, Detail: "exact schema is not valid JSON"}
	}
	root, ok := document.(map[string]any)
	if !ok || root["$schema"] != "http://json-schema.org/draft-07/schema#" {
		return nil, &Error{Code: ErrorSchemaInvalid, Detail: "exact schema does not declare JSON Schema Draft 7"}
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft7)
	compiler.UseLoader(rejectingLoader{})
	if err := compiler.AddResource(schemaResourceURL, document); err != nil {
		return nil, &Error{Code: ErrorSchemaInvalid, Detail: "exact schema resource could not be registered"}
	}
	compiled, err := compiler.Compile(schemaResourceURL)
	if err != nil || compiled.DraftVersion != 7 {
		return nil, &Error{Code: ErrorSchemaInvalid, Detail: "exact Draft 7 schema could not be compiled without external resources"}
	}
	return compiled, nil
}

func normalizeLimits(limits Limits) (Limits, error) {
	defaults := DefaultLimits()
	values := []*int{
		&limits.MaxBytes, &limits.MaxNodes, &limits.MaxDepth,
		&limits.MaxIssues, &limits.MaxProjectionFields, &limits.MaxChanges,
	}
	fallbacks := []int{
		defaults.MaxBytes, defaults.MaxNodes, defaults.MaxDepth,
		defaults.MaxIssues, defaults.MaxProjectionFields, defaults.MaxChanges,
	}
	for index, value := range values {
		if *value < 0 {
			return Limits{}, &Error{Code: ErrorInvalidLimits, Detail: "configuration engine limits must not be negative"}
		}
		if *value == 0 {
			*value = fallbacks[index]
		}
	}
	if limits.MaxDepth > limits.MaxNodes || limits.MaxIssues > limits.MaxNodes || limits.MaxProjectionFields > limits.MaxNodes {
		return Limits{}, &Error{Code: ErrorInvalidLimits, Detail: "configuration engine limits are inconsistent"}
	}
	return limits, nil
}

func (e *Engine) RuntimeID() compatibility.ManifestID { return e.runtimeID }
func (e *Engine) ManifestID() integrations.ManifestID { return e.manifest.ID() }

func (e *Engine) Inspect(source []byte) (Inspection, error) {
	document, err := parseDocument(source, e.limits)
	if err != nil {
		return Inspection{}, err
	}
	instance, err := nodeToAny(document.Content[0])
	if err != nil {
		return Inspection{}, &Error{Code: ErrorMalformedYAML, Detail: "configuration contains an unsupported scalar"}
	}
	schemaIssues := e.validateSchema(document, instance)
	schemaValid := len(schemaIssues) == 0
	semanticIssues := []Issue(nil)
	semanticValid := false
	if schemaValid {
		semanticIssues = validateSemantics(document, e.limits.MaxIssues)
		semanticValid = len(semanticIssues) == 0
	}
	projection, routes, classification, projectionOverflow := e.projectAndClassify(document)
	if projectionOverflow {
		return Inspection{}, &Error{
			Code: ErrorStructureComplex, Detail: "configuration projection exceeds the bounded field limit",
		}
	}
	issues := make([]Issue, 0, min(e.limits.MaxIssues, len(schemaIssues)+len(semanticIssues)+len(classification)))
	for _, group := range [][]Issue{schemaIssues, semanticIssues, classification} {
		for _, issue := range group {
			issues = appendIssue(issues, e.limits.MaxIssues, issue)
		}
	}
	replaceable := schemaValid && semanticValid
	executable := replaceable
	for _, issue := range issues {
		if issue.BlocksReplacement {
			replaceable = false
		}
		if issue.BlocksExecution {
			executable = false
		}
	}
	return Inspection{
		SourceSHA256: digest(source), Projection: projection, Issues: issues,
		SchemaValid: schemaValid, SemanticValid: semanticValid,
		Replaceable: replaceable, Executable: executable, routes: routes, maxIssues: e.limits.MaxIssues,
	}, nil
}

func (e *Engine) validateSchema(document *yaml.Node, instance any) []Issue {
	err := e.schema.Validate(instance)
	if err == nil {
		return nil
	}
	var validation *jsonschema.ValidationError
	if !errors.As(err, &validation) {
		return []Issue{{
			Class: IssueSchema, Path: "/", Summary: "Configuration violates the exact upstream schema.",
			BlocksReplacement: true, BlocksExecution: true,
		}}
	}
	result := make([]Issue, 0)
	seen := make(map[string]struct{})
	var collect func(*jsonschema.ValidationError)
	collect = func(current *jsonschema.ValidationError) {
		if len(result) >= e.limits.MaxIssues {
			return
		}
		if len(current.Causes) > 0 {
			for _, cause := range current.Causes {
				collect(cause)
			}
			return
		}
		path := current.InstanceLocation
		keyword := "constraint"
		if current.ErrorKind != nil {
			parts := current.ErrorKind.KeywordPath()
			if len(parts) > 0 && parts[len(parts)-1] != "" {
				keyword = parts[len(parts)-1]
			}
		}
		identity := pointer(path) + "\x00" + keyword
		if _, duplicate := seen[identity]; duplicate {
			return
		}
		seen[identity] = struct{}{}
		line, column := position(document, path)
		result = append(result, Issue{
			Class: IssueSchema, Path: pointer(path), Line: line, Column: column,
			Summary:           "Configuration violates the exact upstream schema (" + keyword + ").",
			BlocksReplacement: true, BlocksExecution: true,
		})
	}
	collect(validation)
	return result
}

type preparedChange struct {
	spec     integrations.FieldSpec
	bindings []Binding
	values   map[integrations.BindingID]string
	path     []string
	op       Operation
	value    integrations.Value
}

func (e *Engine) Preview(source []byte, changes []Change) (*Candidate, error) {
	document, err := parseDocument(source, e.limits)
	if err != nil {
		return nil, err
	}
	if len(changes) > e.limits.MaxChanges {
		return nil, &Error{Code: ErrorInvalidChange, Detail: "change count exceeds the limit"}
	}
	prepared := make([]preparedChange, len(changes))
	seen := make(map[string]struct{}, len(changes))
	for index, change := range changes {
		spec, ok := e.manifest.Field(change.FieldID)
		if !ok || !spec.Editable() {
			return nil, &Error{Code: ErrorInvalidChange, Detail: "field is not managed by the integration"}
		}
		if change.Operation != OperationSet && change.Operation != OperationRemove {
			return nil, &Error{Code: ErrorInvalidChange, Detail: "field operation is invalid"}
		}
		if change.Operation == OperationSet {
			if err := spec.ValidateValue(change.Value); err != nil {
				return nil, &Error{Code: ErrorInvalidChange, Detail: "field value violates its integration contract"}
			}
		}
		bindingValues, canonicalBindings, err := normalizeBindings(spec, change.Bindings)
		if err != nil {
			return nil, err
		}
		identity := projectionKey(spec.ID(), canonicalBindings)
		if _, duplicate := seen[identity]; duplicate {
			return nil, &Error{Code: ErrorInvalidChange, Detail: "logical field is changed more than once"}
		}
		seen[identity] = struct{}{}
		path, err := spec.Resolve(bindingValues)
		if err != nil {
			return nil, &Error{Code: ErrorInvalidChange, Detail: "field bindings do not resolve"}
		}
		prepared[index] = preparedChange{
			spec: spec, bindings: canonicalBindings, values: bindingValues,
			path: path, op: change.Operation, value: change.Value,
		}
	}

	candidateDocument := cloneNode(document)
	summary := make([]ChangeSummary, 0, len(changes))
	yamlChanged := false
	for _, change := range prepared {
		if change.spec.Target() != integrations.TargetYAML {
			continue
		}
		before, changed, err := e.applyYAMLChange(candidateDocument, change)
		if err != nil {
			return nil, err
		}
		if !changed {
			continue
		}
		yamlChanged = true
		summary = append(summary, summarizeYAML(change, before))
	}

	external := make([]ExternalChange, 0)
	for _, change := range prepared {
		if change.spec.Target() != integrations.TargetDotenv {
			continue
		}
		referenceNode, ok := nodeAtPath(candidateDocument, change.path)
		if !ok || referenceNode.Kind != yaml.ScalarNode || referenceNode.Tag != "!!str" || referenceNode.Value == "" {
			return nil, &Error{Code: ErrorInvalidChange, Detail: "dotenv field has no configured native reference"}
		}
		environmentKey, _ := change.spec.EnvironmentKey()
		external = append(external, ExternalChange{
			fieldID: change.spec.ID(), bindings: slices.Clone(change.bindings), operation: change.op,
			reference: referenceNode.Value, environmentKey: environmentKey,
			secret: change.spec.Sensitivity() == integrations.SensitivitySecret, value: change.value,
		})
		summary = append(summary, summarizeExternal(change))
	}

	candidateYAML := slices.Clone(source)
	if yamlChanged {
		candidateYAML, err = encodeDocument(candidateDocument)
		if err != nil {
			return nil, &Error{Code: ErrorMalformedYAML, Detail: "candidate configuration could not be encoded"}
		}
		if len(candidateYAML) > e.limits.MaxBytes {
			return nil, &Error{Code: ErrorSourceTooLarge, Detail: "candidate configuration exceeds the byte limit"}
		}
	}
	inspection, err := e.Inspect(candidateYAML)
	if err != nil {
		return nil, err
	}
	if len(external) > 0 {
		presence := make([]DotenvPresence, len(external))
		for index, change := range external {
			presence[index] = DotenvPresence{
				FieldID: change.fieldID, Bindings: slices.Clone(change.bindings),
				Present: change.operation == OperationSet, Valid: true,
			}
		}
		inspection = inspection.WithDotenvPresence(presence)
	}
	changed := yamlChanged || len(external) > 0
	return &Candidate{
		yaml: candidateYAML, SourceSHA256: digest(source), CandidateSHA256: digest(candidateYAML),
		Changed: changed, Inspection: inspection, Summary: summary, external: external,
	}, nil
}

func normalizeBindings(spec integrations.FieldSpec, supplied []Binding) (map[integrations.BindingID]string, []Binding, error) {
	values := make(map[integrations.BindingID]string, len(supplied))
	for _, binding := range supplied {
		if binding.ID == "" || binding.Value == "" {
			return nil, nil, &Error{Code: ErrorInvalidChange, Detail: "field binding is empty"}
		}
		if _, duplicate := values[binding.ID]; duplicate {
			return nil, nil, &Error{Code: ErrorInvalidChange, Detail: "field binding is duplicated"}
		}
		values[binding.ID] = binding.Value
	}
	path, err := spec.Resolve(values)
	if err != nil || len(path) == 0 {
		return nil, nil, &Error{Code: ErrorInvalidChange, Detail: "field bindings do not match the integration contract"}
	}
	return values, orderedBindings(spec, values), nil
}

func (e *Engine) applyYAMLChange(document *yaml.Node, change preparedChange) (*yaml.Node, bool, error) {
	switch change.op {
	case OperationSet:
		node, err := nodeFromIntegrationValue(change.value)
		if err != nil {
			return nil, false, err
		}
		return setNodeAtPath(
			document,
			change.path,
			node,
			change.spec.Sensitivity() == integrations.SensitivitySecret,
		)
	case OperationRemove:
		return removeNodeAtPath(document, change.path)
	default:
		return nil, false, &Error{Code: ErrorInvalidChange, Detail: "field operation is invalid"}
	}
}

func nodeFromIntegrationValue(value integrations.Value) (*yaml.Node, error) {
	switch value.Kind() {
	case integrations.FieldString:
		text, _ := value.String()
		return valueNode(text), nil
	case integrations.FieldBoolean:
		boolean, _ := value.Boolean()
		return valueNode(boolean), nil
	case integrations.FieldInteger:
		integer, _ := value.Integer()
		return valueNode(integer), nil
	case integrations.FieldStringList:
		list, _ := value.StringList()
		return valueNode(list), nil
	default:
		return nil, &Error{Code: ErrorInvalidChange, Detail: "field value kind is invalid"}
	}
}

func summarizeYAML(change preparedChange, before *yaml.Node) ChangeSummary {
	secret := change.spec.Sensitivity() == integrations.SensitivitySecret
	summary := ChangeSummary{
		FieldID: change.spec.ID(), Bindings: slices.Clone(change.bindings), Label: change.spec.Label(),
		Target: change.spec.Target(), Action: SummarySet, Secret: secret,
	}
	if change.op == OperationRemove {
		summary.Action = SummaryRemove
		if !secret {
			if defaultValue, ok := change.spec.Default(); ok {
				summary.after = defaultValue
				summary.hasAfter = true
			}
		}
	}
	if !secret {
		if value, ok := integrationValue(change.spec.Kind(), before); ok {
			if change.spec.ValidateValue(value) == nil {
				summary.before = value
				summary.hasBefore = true
			}
		}
		if change.op == OperationSet {
			summary.after = change.value
			summary.hasAfter = true
		}
	}
	return summary
}

func summarizeExternal(change preparedChange) ChangeSummary {
	secret := change.spec.Sensitivity() == integrations.SensitivitySecret
	summary := ChangeSummary{
		FieldID: change.spec.ID(), Bindings: slices.Clone(change.bindings), Label: change.spec.Label(),
		Target: change.spec.Target(), Action: SummarySet, Secret: secret,
	}
	if change.op == OperationRemove {
		summary.Action = SummaryRemove
	} else if !secret {
		summary.after = change.value
		summary.hasAfter = true
	}
	return summary
}
