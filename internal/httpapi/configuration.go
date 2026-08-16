package httpapi

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/sgurden-certleap/AcmeMux/internal/configuration"
	"github.com/sgurden-certleap/AcmeMux/internal/identity"
	"github.com/sgurden-certleap/AcmeMux/internal/integrations"
	"github.com/sgurden-certleap/AcmeMux/internal/nativeconfig"
	"github.com/sgurden-certleap/AcmeMux/internal/workspace"
)

const (
	maximumConfigurationBodyBytes    = 1 << 20
	maximumConfigurationChanges      = 128
	maximumConfigurationBindings     = 16
	maximumConfigurationFieldBytes   = 128
	maximumConfigurationBindingBytes = 256
	maximumConfigurationStringBytes  = 64 << 10
	maximumConfigurationListItems    = 256
	maximumConfigurationItemBytes    = 4096
	maximumConfigurationSafeInteger  = int64(1<<53 - 1)
)

var (
	configurationTokenPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	configurationFieldPattern   = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
	configurationBindingPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

type ConfigurationService interface {
	Snapshot(context.Context) (configuration.View, error)
	Preview(context.Context, string, []nativeconfig.Change) (configuration.Preview, error)
	Save(context.Context, string, []nativeconfig.Change, string, workspace.CommitGuard) (configuration.View, error)
	ResolveRecovery(context.Context, string, workspace.RecoveryResolution, workspace.CommitGuard) (configuration.View, error)
}

type ConfigurationDependencies struct {
	Service ConfigurationService
}

func (dependencies ConfigurationDependencies) validate() (ConfigurationDependencies, error) {
	if dependencies.Service == nil {
		return ConfigurationDependencies{}, errors.New("native configuration service is required")
	}
	return dependencies, nil
}

type configurationEndpoints struct {
	identity *identityEndpoints
	service  ConfigurationService
}

type configurationAuthorization struct {
	sessionToken string
	csrfToken    string
}

type configurationRequest struct {
	BaseRevisionToken    string
	Changes              []nativeconfig.Change
	ReviewedPreviewToken string
}

type configurationRecoveryRequest struct {
	BaseRevisionToken string
	Resolution        workspace.RecoveryResolution
}

type configurationSnapshot struct {
	State        string                    `json:"state"`
	Source       configurationSource       `json:"source"`
	Projection   *[]configurationField     `json:"projection,omitempty"`
	Diagnostics  []configurationDiagnostic `json:"diagnostics"`
	Capabilities configurationCapabilities `json:"capabilities"`
	Recovery     *configurationRecovery    `json:"recovery,omitempty"`
}

type configurationSource struct {
	BaseRevisionToken string   `json:"baseRevisionToken"`
	ConfigurationPath string   `json:"configurationPath"`
	DotenvPaths       []string `json:"dotenvPaths"`
	RuntimeManifestID string   `json:"runtimeManifestId"`
}

type configurationCapabilities struct {
	Editing   bool `json:"editing"`
	Execution bool `json:"execution"`
}

type configurationBinding struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}

type configurationField struct {
	FieldID       string                 `json:"fieldId"`
	Bindings      []configurationBinding `json:"bindings"`
	Label         string                 `json:"label"`
	Kind          string                 `json:"kind"`
	Present       bool                   `json:"present"`
	Configured    bool                   `json:"configured"`
	Defaulted     bool                   `json:"defaulted"`
	PresenceKnown bool                   `json:"presenceKnown"`
	Value         any                    `json:"value,omitempty"`
}

type configurationDiagnostic struct {
	Code     string                 `json:"code"`
	Severity string                 `json:"severity"`
	Role     string                 `json:"role"`
	Message  string                 `json:"message"`
	FieldID  *string                `json:"fieldId"`
	Bindings []configurationBinding `json:"bindings"`
	Path     *string                `json:"path"`
	Line     *int                   `json:"line"`
	Column   *int                   `json:"column"`
}

type configurationRecovery struct {
	Phase   string                        `json:"phase"`
	State   string                        `json:"state"`
	Targets []configurationRecoveryTarget `json:"targets"`
}

type configurationRecoveryTarget struct {
	Role  string `json:"role"`
	Path  string `json:"path"`
	State string `json:"state"`
}

type configurationPreview struct {
	State                string                     `json:"state"`
	BaseRevisionToken    string                     `json:"baseRevisionToken"`
	ReviewedPreviewToken string                     `json:"reviewedPreviewToken,omitempty"`
	ResultingState       string                     `json:"resultingState,omitempty"`
	Summary              *[]configurationSummary    `json:"summary,omitempty"`
	Diagnostics          *[]configurationDiagnostic `json:"diagnostics,omitempty"`
	ExecutionAllowed     *bool                      `json:"executionAllowed,omitempty"`
}

type configurationSummary struct {
	FieldID   string                    `json:"fieldId"`
	Bindings  []configurationBinding    `json:"bindings"`
	Label     string                    `json:"label"`
	File      string                    `json:"file"`
	Action    string                    `json:"action"`
	Sensitive bool                      `json:"sensitive"`
	Before    configurationSummaryValue `json:"before"`
	After     configurationSummaryValue `json:"after"`
}

type configurationSummaryValue struct {
	State string `json:"state"`
	Value any    `json:"value,omitempty"`
}

func newConfigurationEndpoints(identityAPI *identityEndpoints, dependencies ConfigurationDependencies) (*configurationEndpoints, error) {
	if identityAPI == nil {
		return nil, errors.New("identity endpoints are required")
	}
	validated, err := dependencies.validate()
	if err != nil {
		return nil, err
	}
	return &configurationEndpoints{identity: identityAPI, service: validated.Service}, nil
}

func (endpoints *configurationEndpoints) register(multiplexer *http.ServeMux) {
	multiplexer.HandleFunc("GET /api/v1/configuration", endpoints.getConfiguration)
	multiplexer.HandleFunc("POST /api/v1/configuration/previews", endpoints.previewConfiguration)
	multiplexer.HandleFunc("PUT /api/v1/configuration", endpoints.saveConfiguration)
	multiplexer.HandleFunc("PUT /api/v1/configuration/recovery", endpoints.resolveConfigurationRecovery)
}

func (endpoints *configurationEndpoints) resolveConfigurationRecovery(response http.ResponseWriter, request *http.Request) {
	authorization, ok := endpoints.authorize(response, request, true)
	if !ok {
		return
	}
	payload, ok := readConfigurationRecoveryRequest(response, request)
	if !ok {
		return
	}
	guardResponded := false
	guard := func(context.Context) error {
		if !endpoints.reauthorizeMutation(response, request, authorization) {
			guardResponded = true
			return errors.New("native configuration recovery authorization failed")
		}
		return nil
	}
	view, err := endpoints.service.ResolveRecovery(
		request.Context(), payload.BaseRevisionToken, payload.Resolution, guard,
	)
	if guardResponded {
		return
	}
	if err != nil {
		writeConfigurationServiceError(response, err)
		return
	}
	presented, err := presentConfigurationSnapshot(view)
	if err != nil {
		writeConfigurationUnavailable(response)
		return
	}
	writeJSON(response, http.StatusOK, presented)
}

func (endpoints *configurationEndpoints) getConfiguration(response http.ResponseWriter, request *http.Request) {
	if _, ok := endpoints.authorize(response, request, false); !ok {
		return
	}
	view, err := endpoints.service.Snapshot(request.Context())
	if err != nil {
		writeConfigurationServiceError(response, err)
		return
	}
	presented, err := presentConfigurationSnapshot(view)
	if err != nil {
		writeConfigurationUnavailable(response)
		return
	}
	writeJSON(response, http.StatusOK, presented)
}

func (endpoints *configurationEndpoints) previewConfiguration(response http.ResponseWriter, request *http.Request) {
	if _, ok := endpoints.authorize(response, request, true); !ok {
		return
	}
	payload, ok := readConfigurationRequest(response, request, false)
	if !ok {
		return
	}
	defer clearConfigurationChanges(payload.Changes)
	preview, err := endpoints.service.Preview(request.Context(), payload.BaseRevisionToken, payload.Changes)
	if err != nil {
		writeConfigurationServiceError(response, err)
		return
	}
	presented, err := presentConfigurationPreview(preview)
	if err != nil {
		writeConfigurationUnavailable(response)
		return
	}
	writeJSON(response, http.StatusOK, presented)
}

func (endpoints *configurationEndpoints) saveConfiguration(response http.ResponseWriter, request *http.Request) {
	authorization, ok := endpoints.authorize(response, request, true)
	if !ok {
		return
	}
	payload, ok := readConfigurationRequest(response, request, true)
	if !ok {
		return
	}
	defer clearConfigurationChanges(payload.Changes)
	guardResponded := false
	guard := func(context.Context) error {
		if !endpoints.reauthorizeMutation(response, request, authorization) {
			guardResponded = true
			return errors.New("native configuration commit authorization failed")
		}
		return nil
	}
	view, err := endpoints.service.Save(
		request.Context(), payload.BaseRevisionToken, payload.Changes,
		payload.ReviewedPreviewToken, guard,
	)
	if guardResponded {
		return
	}
	if err != nil {
		writeConfigurationServiceError(response, err)
		return
	}
	presented, err := presentConfigurationSnapshot(view)
	if err != nil {
		writeConfigurationUnavailable(response)
		return
	}
	writeJSON(response, http.StatusOK, presented)
}

func (endpoints *configurationEndpoints) authorize(response http.ResponseWriter, request *http.Request, mutation bool) (configurationAuthorization, bool) {
	rawSession, present := sessionToken(request)
	if !present {
		clearSessionCookies(response)
		writeAuthenticationRequired(response)
		return configurationAuthorization{}, false
	}
	active, rawCSRF, err := endpoints.identity.validateBrowserSession(request, rawSession)
	if errors.Is(err, identity.ErrInvalidSession) || errors.Is(err, identity.ErrSessionExpired) {
		clearSessionCookies(response)
		writeAuthenticationRequired(response)
		return configurationAuthorization{}, false
	}
	if err != nil {
		writeServiceUnavailable(response)
		return configurationAuthorization{}, false
	}
	pairedCSRF := ""
	if mutation {
		var validPair bool
		pairedCSRF, validPair = csrfToken(request)
		if !validPair || !active.ValidCSRF(pairedCSRF) {
			writeAPIError(response, http.StatusForbidden, "request_not_allowed", "The request could not be verified.")
			return configurationAuthorization{}, false
		}
	}
	if err := endpoints.identity.refreshCookies(response, rawCSRF, active); err != nil {
		_ = endpoints.identity.service.Logout(request.Context(), rawSession)
		clearSessionCookies(response)
		writeServiceUnavailable(response)
		return configurationAuthorization{}, false
	}
	effectiveSession := rawSession
	if active.ReplacementToken != "" {
		effectiveSession = active.ReplacementToken
	}
	return configurationAuthorization{sessionToken: effectiveSession, csrfToken: pairedCSRF}, true
}

func (endpoints *configurationEndpoints) reauthorizeMutation(response http.ResponseWriter, request *http.Request, authorization configurationAuthorization) bool {
	active, err := endpoints.identity.service.ValidateSession(request.Context(), authorization.sessionToken)
	if errors.Is(err, identity.ErrInvalidSession) || errors.Is(err, identity.ErrSessionExpired) {
		writeAuthenticationRequired(response)
		return false
	}
	if err != nil {
		writeServiceUnavailable(response)
		return false
	}
	pairedCSRF, validPair := csrfToken(request)
	if !validPair || subtle.ConstantTimeCompare([]byte(pairedCSRF), []byte(authorization.csrfToken)) != 1 || !active.ValidCSRF(pairedCSRF) {
		writeAPIError(response, http.StatusForbidden, "request_not_allowed", "The request could not be verified.")
		return false
	}
	if err := endpoints.identity.refreshCookies(response, pairedCSRF, active); err != nil {
		writeServiceUnavailable(response)
		return false
	}
	return true
}

func presentConfigurationSnapshot(view configuration.View) (configurationSnapshot, error) {
	source := configurationSource{
		BaseRevisionToken: view.Source.BaseRevisionToken,
		ConfigurationPath: view.Source.ConfigurationPath,
		DotenvPaths:       append([]string{}, view.Source.DotenvPaths...),
		RuntimeManifestID: string(view.Source.RuntimeManifestID),
	}
	result := configurationSnapshot{
		State: string(view.State), Source: source,
		Diagnostics:  presentConfigurationDiagnostics(view.Diagnostics),
		Capabilities: configurationCapabilities{Editing: view.Editing, Execution: view.Execution},
	}
	if view.State == configuration.StateRecoveryRequired {
		if view.Recovery == nil {
			return configurationSnapshot{}, errors.New("configuration recovery evidence is missing")
		}
		recovery := configurationRecovery{
			Phase: string(view.Recovery.Phase), State: string(view.Recovery.State),
			Targets: make([]configurationRecoveryTarget, 0, len(view.Recovery.Files)),
		}
		for _, file := range view.Recovery.Files {
			recovery.Targets = append(recovery.Targets, configurationRecoveryTarget{
				Role: string(file.Role), Path: file.Path, State: string(file.State),
			})
		}
		result.Recovery = &recovery
		return result, nil
	}
	projection, err := presentConfigurationProjection(view.Inspection.Projection)
	if err != nil {
		return configurationSnapshot{}, err
	}
	result.Projection = &projection
	return result, nil
}

func presentConfigurationProjection(fields []nativeconfig.ProjectedField) ([]configurationField, error) {
	result := make([]configurationField, 0, len(fields))
	for _, field := range fields {
		kind := string(field.Kind)
		if field.Secret {
			kind = "secret"
		}
		presented := configurationField{
			FieldID: string(field.FieldID), Bindings: presentConfigurationBindings(field.Bindings),
			Label: field.Label, Kind: kind, Present: field.Present, Configured: field.Configured,
			Defaulted: field.Defaulted, PresenceKnown: field.PresenceKnown,
		}
		if !field.Secret && field.Configured {
			value, present := field.Value()
			if !present {
				return nil, errors.New("configured projection has no value")
			}
			converted, ok := presentConfigurationValue(value)
			if !ok {
				return nil, errors.New("configured projection has an invalid value")
			}
			presented.Value = converted
		}
		result = append(result, presented)
	}
	return result, nil
}

func presentConfigurationBindings(bindings []nativeconfig.Binding) []configurationBinding {
	result := make([]configurationBinding, 0, len(bindings))
	for _, binding := range bindings {
		result = append(result, configurationBinding{ID: string(binding.ID), Value: binding.Value})
	}
	return result
}

func presentConfigurationDiagnostics(diagnostics []configuration.Diagnostic) []configurationDiagnostic {
	result := make([]configurationDiagnostic, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		var fieldID *string
		if diagnostic.FieldID != "" {
			value := string(diagnostic.FieldID)
			fieldID = &value
		}
		var path *string
		if validWorkspacePath(diagnostic.Path) {
			value := diagnostic.Path
			path = &value
		}
		var line, column *int
		if diagnostic.Line > 0 && diagnostic.Column > 0 {
			lineValue, columnValue := diagnostic.Line, diagnostic.Column
			line, column = &lineValue, &columnValue
		}
		result = append(result, configurationDiagnostic{
			Code: string(diagnostic.Code), Severity: string(diagnostic.Severity), Role: string(diagnostic.Role),
			Message: configurationDiagnosticMessage(diagnostic.Code), FieldID: fieldID,
			Bindings: presentConfigurationBindings(diagnostic.Bindings), Path: path, Line: line, Column: column,
		})
	}
	return result
}

func presentConfigurationPreview(preview configuration.Preview) (configurationPreview, error) {
	result := configurationPreview{State: string(preview.State), BaseRevisionToken: preview.BaseRevisionToken}
	switch preview.State {
	case configuration.PreviewUnchanged:
		return result, nil
	case configuration.PreviewInvalid:
		summary := presentConfigurationSummary(preview.Summary, preview.BaseInspection, preview.Inspection)
		diagnostics := presentConfigurationDiagnostics(preview.Diagnostics)
		result.Summary = &summary
		result.Diagnostics = &diagnostics
		return result, nil
	case configuration.PreviewReviewRequired:
		if preview.ResultingState != configuration.StateReady && preview.ResultingState != configuration.StateUnsupported {
			return configurationPreview{}, errors.New("configuration preview has an invalid resulting state")
		}
		result.ReviewedPreviewToken = preview.ReviewedPreviewToken
		result.ResultingState = string(preview.ResultingState)
		summary := presentConfigurationSummary(preview.Summary, preview.BaseInspection, preview.Inspection)
		diagnostics := presentConfigurationDiagnostics(preview.Diagnostics)
		result.Summary = &summary
		result.Diagnostics = &diagnostics
		execution := preview.Execution
		result.ExecutionAllowed = &execution
		return result, nil
	default:
		return configurationPreview{}, errors.New("configuration preview state is invalid")
	}
}

func presentConfigurationSummary(
	summaries []nativeconfig.ChangeSummary,
	beforeInspection nativeconfig.Inspection,
	afterInspection nativeconfig.Inspection,
) []configurationSummary {
	result := make([]configurationSummary, 0, len(summaries))
	for _, summary := range summaries {
		beforeField, beforeFound := findProjectedField(beforeInspection.Projection, summary.FieldID, summary.Bindings)
		afterField, afterFound := findProjectedField(afterInspection.Projection, summary.FieldID, summary.Bindings)
		if summary.Secret && summary.Action == nativeconfig.SummaryRemove && (!beforeFound || !beforeField.Present) && (!afterFound || !afterField.Present) {
			continue
		}
		file := "configuration"
		if summary.Target == integrations.TargetDotenv {
			file = "dotenv"
		}
		presented := configurationSummary{
			FieldID: string(summary.FieldID), Bindings: presentConfigurationBindings(summary.Bindings),
			Label: summary.Label, File: file, Sensitive: summary.Secret,
			Before: configurationSummaryValue{State: "absent"},
			After:  configurationSummaryValue{State: "absent"},
		}
		if summary.Secret {
			if beforeFound && beforeField.Present {
				presented.Before.State = "present_secret"
			}
			if afterFound && afterField.Present {
				presented.After.State = "present_secret"
			}
			if summary.Action == nativeconfig.SummaryRemove {
				presented.Action = "secret_removed"
			} else {
				presented.Action = "secret_replaced"
			}
		} else {
			if beforeFound && beforeField.Present && !beforeField.Configured {
				presented.Before.State = "present_unsupported"
			}
			if afterFound && afterField.Present && !afterField.Configured {
				presented.After.State = "present_unsupported"
			}
			if before, ok := summary.Before(); ok {
				if value, valid := presentConfigurationValue(before); valid {
					presented.Before = configurationSummaryValue{State: "value", Value: value}
				}
			}
			if after, ok := summary.After(); ok {
				if value, valid := presentConfigurationValue(after); valid {
					presented.After = configurationSummaryValue{State: "value", Value: value}
				}
			}
			switch summary.Action {
			case nativeconfig.SummaryRemove:
				if presented.After.State == "value" {
					presented.Action = "changed"
				} else {
					presented.Action = "removed"
				}
			case nativeconfig.SummarySet:
				if presented.Before.State == "absent" {
					presented.Action = "added"
				} else {
					presented.Action = "changed"
				}
			}
		}
		result = append(result, presented)
	}
	return result
}

func findProjectedField(fields []nativeconfig.ProjectedField, fieldID integrations.FieldID, bindings []nativeconfig.Binding) (nativeconfig.ProjectedField, bool) {
	for _, field := range fields {
		if field.FieldID == fieldID && slices.Equal(field.Bindings, bindings) {
			return field, true
		}
	}
	return nativeconfig.ProjectedField{}, false
}

func presentConfigurationValue(value integrations.Value) (any, bool) {
	switch value.Kind() {
	case integrations.FieldString:
		return value.String()
	case integrations.FieldBoolean:
		return value.Boolean()
	case integrations.FieldInteger:
		return value.Integer()
	case integrations.FieldStringList:
		return value.StringList()
	default:
		return nil, false
	}
}

func configurationDiagnosticMessage(code configuration.DiagnosticCode) string {
	switch code {
	case configuration.CodeUnsupportedCA:
		return "A native ACME server is preserved but is not managed by this integration."
	case configuration.CodeUnsupportedProvider:
		return "A native DNS provider is preserved but is not managed by this integration."
	case configuration.CodeUnsupportedChallenge:
		return "A native challenge mode is preserved but is not managed by this integration."
	case configuration.CodeUnsupportedHooks:
		return "Native hook commands are preserved but are never exposed or executed by AcmeMux."
	case configuration.CodeUnsupportedOutput:
		return "Native output settings are preserved outside the supported workflow."
	case configuration.CodeUnsupportedContent:
		return "Recognized native content is preserved but is outside this integration."
	case configuration.CodeUnknownField:
		return "An unrecognized native field is preserved and blocks managed execution."
	case configuration.CodeYAMLAliasUnsupported, configuration.CodeYAMLMergeUnsupported, configuration.CodeYAMLTagUnsupported:
		return "This YAML structure cannot be edited without risking a change in native meaning."
	case configuration.CodeMultipleDocuments:
		return "The native file must contain exactly one YAML document."
	case configuration.CodeDuplicateKey:
		return "A duplicate YAML key makes the native value ambiguous."
	case configuration.CodeInvalidUTF8:
		return "A native source is not valid UTF-8."
	case configuration.CodeDocumentEmpty, configuration.CodeDocumentMalformed:
		return "The native YAML document cannot be parsed safely."
	case configuration.CodeDocumentTooLarge, configuration.CodeDocumentTooComplex:
		return "The native document exceeds a bounded editing limit."
	case configuration.CodeDotenvMalformed:
		return "A referenced credential file cannot be parsed without risking line loss."
	case configuration.CodeDotenvDuplicateKey:
		return "A referenced credential file repeats a key and is ambiguous."
	case configuration.CodeDotenvKeyNotAllowed:
		return "An unmanaged credential key is preserved and blocks managed execution."
	case configuration.CodeDotenvExpansionNotAllowed:
		return "A managed credential value uses variable expansion and cannot be edited safely."
	case configuration.CodeSchemaValidationFailed:
		return "The native document violates the exact schema for the selected runtime."
	case configuration.CodeSemanticValidationFailed:
		return "The native document violates source-backed configuration semantics."
	case configuration.CodeRuntimeManifestChanged:
		return "The selected runtime no longer matches the reviewed compatibility manifest."
	case configuration.CodeSourceChanged:
		return "A native source changed after review and must be loaded again."
	case configuration.CodeUnsafePath:
		return "A candidate native path does not satisfy the adopted filesystem boundary."
	case configuration.CodeSynchronizationFailed:
		return "A native file or directory could not be synchronized safely."
	case configuration.CodeReplacementInterrupted, configuration.CodeRecoveryRequired:
		return "A prior native replacement has an incomplete or ambiguous outcome."
	default:
		return "The native configuration failed a bounded safety check."
	}
}

func readConfigurationRequest(response http.ResponseWriter, request *http.Request, save bool) (configurationRequest, bool) {
	if !requireJSON(request) {
		writeAPIError(response, http.StatusUnsupportedMediaType, "invalid_request", "A JSON request body is required.")
		return configurationRequest{}, false
	}
	request.Body = http.MaxBytesReader(response, request.Body, maximumConfigurationBodyBytes)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		writeConfigurationJSONError(response, err)
		return configurationRequest{}, false
	}
	defer clear(body)
	if !utf8.Valid(body) {
		writeInvalidConfigurationRequest(response)
		return configurationRequest{}, false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	opening, err := decoder.Token()
	if err != nil {
		writeInvalidConfigurationRequest(response)
		return configurationRequest{}, false
	}
	if delimiter, ok := opening.(json.Delim); !ok || delimiter != '{' {
		writeInvalidConfigurationRequest(response)
		return configurationRequest{}, false
	}
	required := 2
	if save {
		required = 3
	}
	seen := make(map[string]struct{}, required)
	var payload configurationRequest
	for decoder.More() {
		rawKey, err := decoder.Token()
		key, ok := rawKey.(string)
		if err != nil || !ok {
			writeInvalidConfigurationRequest(response)
			return configurationRequest{}, false
		}
		if _, duplicate := seen[key]; duplicate {
			writeInvalidConfigurationRequest(response)
			return configurationRequest{}, false
		}
		seen[key] = struct{}{}
		switch key {
		case "baseRevisionToken":
			if err := decoder.Decode(&payload.BaseRevisionToken); err != nil {
				writeInvalidConfigurationRequest(response)
				return configurationRequest{}, false
			}
		case "reviewedPreviewToken":
			if !save || decoder.Decode(&payload.ReviewedPreviewToken) != nil {
				writeInvalidConfigurationRequest(response)
				return configurationRequest{}, false
			}
		case "changes":
			var rawChanges []json.RawMessage
			if err := decoder.Decode(&rawChanges); err != nil || len(rawChanges) == 0 || len(rawChanges) > maximumConfigurationChanges {
				clearRawMessages(rawChanges)
				writeInvalidConfigurationRequest(response)
				return configurationRequest{}, false
			}
			for _, raw := range rawChanges {
				change, err := decodeConfigurationChange(raw)
				if err != nil {
					clearRawMessages(rawChanges)
					clearConfigurationChanges(payload.Changes)
					writeInvalidConfigurationRequest(response)
					return configurationRequest{}, false
				}
				payload.Changes = append(payload.Changes, change)
			}
			clearRawMessages(rawChanges)
		default:
			clearConfigurationChanges(payload.Changes)
			writeInvalidConfigurationRequest(response)
			return configurationRequest{}, false
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		clearConfigurationChanges(payload.Changes)
		writeInvalidConfigurationRequest(response)
		return configurationRequest{}, false
	}
	if delimiter, ok := closing.(json.Delim); !ok || delimiter != '}' || len(seen) != required {
		clearConfigurationChanges(payload.Changes)
		writeInvalidConfigurationRequest(response)
		return configurationRequest{}, false
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) ||
		!configurationTokenPattern.MatchString(payload.BaseRevisionToken) ||
		(save && !configurationTokenPattern.MatchString(payload.ReviewedPreviewToken)) {
		clearConfigurationChanges(payload.Changes)
		writeInvalidConfigurationRequest(response)
		return configurationRequest{}, false
	}
	return payload, true
}

func readConfigurationRecoveryRequest(response http.ResponseWriter, request *http.Request) (configurationRecoveryRequest, bool) {
	if !requireJSON(request) {
		writeAPIError(response, http.StatusUnsupportedMediaType, "invalid_request", "A JSON request body is required.")
		return configurationRecoveryRequest{}, false
	}
	request.Body = http.MaxBytesReader(response, request.Body, 4096)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		writeConfigurationJSONError(response, err)
		return configurationRecoveryRequest{}, false
	}
	defer clear(body)
	if !utf8.Valid(body) {
		writeInvalidConfigurationRequest(response)
		return configurationRecoveryRequest{}, false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	opening, err := decoder.Token()
	if err != nil {
		writeInvalidConfigurationRequest(response)
		return configurationRecoveryRequest{}, false
	}
	if delimiter, ok := opening.(json.Delim); !ok || delimiter != '{' {
		writeInvalidConfigurationRequest(response)
		return configurationRecoveryRequest{}, false
	}
	seen := make(map[string]struct{}, 2)
	var base, resolution string
	for decoder.More() {
		rawKey, keyErr := decoder.Token()
		key, keyOK := rawKey.(string)
		if keyErr != nil || !keyOK {
			writeInvalidConfigurationRequest(response)
			return configurationRecoveryRequest{}, false
		}
		if _, duplicate := seen[key]; duplicate {
			writeInvalidConfigurationRequest(response)
			return configurationRecoveryRequest{}, false
		}
		seen[key] = struct{}{}
		switch key {
		case "baseRevisionToken":
			if decoder.Decode(&base) != nil {
				writeInvalidConfigurationRequest(response)
				return configurationRecoveryRequest{}, false
			}
		case "resolution":
			if decoder.Decode(&resolution) != nil {
				writeInvalidConfigurationRequest(response)
				return configurationRecoveryRequest{}, false
			}
		default:
			writeInvalidConfigurationRequest(response)
			return configurationRecoveryRequest{}, false
		}
	}
	closing, closeErr := decoder.Token()
	if closeErr != nil {
		writeInvalidConfigurationRequest(response)
		return configurationRecoveryRequest{}, false
	}
	if delimiter, ok := closing.(json.Delim); !ok || delimiter != '}' || len(seen) != 2 ||
		!configurationTokenPattern.MatchString(base) {
		writeInvalidConfigurationRequest(response)
		return configurationRecoveryRequest{}, false
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		writeInvalidConfigurationRequest(response)
		return configurationRecoveryRequest{}, false
	}
	result := configurationRecoveryRequest{BaseRevisionToken: base, Resolution: workspace.RecoveryResolution(resolution)}
	if result.Resolution != workspace.ResolutionDiscardUnapplied &&
		result.Resolution != workspace.ResolutionFinalizeApplied &&
		result.Resolution != workspace.ResolutionAdoptCurrent {
		writeInvalidConfigurationRequest(response)
		return configurationRecoveryRequest{}, false
	}
	return result, true
}

func decodeConfigurationChange(raw []byte) (nativeconfig.Change, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	opening, err := decoder.Token()
	if err != nil {
		return nativeconfig.Change{}, err
	}
	if delimiter, ok := opening.(json.Delim); !ok || delimiter != '{' {
		return nativeconfig.Change{}, errors.New("configuration change must be an object")
	}
	seen := make(map[string]struct{}, 4)
	var fieldID, operation string
	var bindings []nativeconfig.Binding
	var value integrations.Value
	valuePresent := false
	for decoder.More() {
		rawKey, err := decoder.Token()
		key, ok := rawKey.(string)
		if err != nil || !ok {
			return nativeconfig.Change{}, errors.New("configuration change key is invalid")
		}
		if _, duplicate := seen[key]; duplicate {
			return nativeconfig.Change{}, errors.New("configuration change field is duplicated")
		}
		seen[key] = struct{}{}
		switch key {
		case "fieldId":
			if decoder.Decode(&fieldID) != nil {
				return nativeconfig.Change{}, errors.New("configuration field ID is invalid")
			}
		case "operation":
			if decoder.Decode(&operation) != nil {
				return nativeconfig.Change{}, errors.New("configuration operation is invalid")
			}
		case "bindings":
			var rawBindings []json.RawMessage
			if decoder.Decode(&rawBindings) != nil || len(rawBindings) > maximumConfigurationBindings {
				clearRawMessages(rawBindings)
				return nativeconfig.Change{}, errors.New("configuration bindings are invalid")
			}
			for _, rawBinding := range rawBindings {
				binding, err := decodeConfigurationBinding(rawBinding)
				if err != nil {
					clearRawMessages(rawBindings)
					return nativeconfig.Change{}, err
				}
				bindings = append(bindings, binding)
			}
			clearRawMessages(rawBindings)
		case "value":
			var rawValue json.RawMessage
			if decoder.Decode(&rawValue) != nil {
				return nativeconfig.Change{}, errors.New("configuration value is invalid")
			}
			value, err = decodeConfigurationValue(rawValue)
			clear(rawValue)
			if err != nil {
				return nativeconfig.Change{}, err
			}
			valuePresent = true
		default:
			return nativeconfig.Change{}, errors.New("configuration change field is unknown")
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return nativeconfig.Change{}, err
	}
	if delimiter, ok := closing.(json.Delim); !ok || delimiter != '}' {
		return nativeconfig.Change{}, errors.New("configuration change is incomplete")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) ||
		len(fieldID) > maximumConfigurationFieldBytes || !configurationFieldPattern.MatchString(fieldID) ||
		hasDuplicateBindings(bindings) {
		return nativeconfig.Change{}, errors.New("configuration change identity is invalid")
	}
	change := nativeconfig.Change{FieldID: integrations.FieldID(fieldID), Bindings: bindings}
	switch operation {
	case string(nativeconfig.OperationSet):
		if len(seen) != 4 || !valuePresent {
			return nativeconfig.Change{}, errors.New("configuration set value is missing")
		}
		change.Operation = nativeconfig.OperationSet
		change.Value = value
	case string(nativeconfig.OperationRemove):
		if len(seen) != 3 || valuePresent {
			return nativeconfig.Change{}, errors.New("configuration removal contains a value")
		}
		change.Operation = nativeconfig.OperationRemove
	default:
		return nativeconfig.Change{}, errors.New("configuration operation is unknown")
	}
	return change, nil
}

func decodeConfigurationBinding(raw []byte) (nativeconfig.Binding, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil {
		return nativeconfig.Binding{}, err
	}
	if delimiter, ok := opening.(json.Delim); !ok || delimiter != '{' {
		return nativeconfig.Binding{}, errors.New("configuration binding must be an object")
	}
	seen := make(map[string]struct{}, 2)
	var id, value string
	for decoder.More() {
		rawKey, err := decoder.Token()
		key, ok := rawKey.(string)
		if err != nil || !ok {
			return nativeconfig.Binding{}, errors.New("configuration binding key is invalid")
		}
		if _, duplicate := seen[key]; duplicate {
			return nativeconfig.Binding{}, errors.New("configuration binding field is duplicated")
		}
		seen[key] = struct{}{}
		switch key {
		case "id":
			if decoder.Decode(&id) != nil {
				return nativeconfig.Binding{}, errors.New("configuration binding ID is invalid")
			}
		case "value":
			if decoder.Decode(&value) != nil {
				return nativeconfig.Binding{}, errors.New("configuration binding value is invalid")
			}
		default:
			return nativeconfig.Binding{}, errors.New("configuration binding field is unknown")
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return nativeconfig.Binding{}, err
	}
	if delimiter, ok := closing.(json.Delim); !ok || delimiter != '}' || len(seen) != 2 {
		return nativeconfig.Binding{}, errors.New("configuration binding is incomplete")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) || !configurationBindingPattern.MatchString(id) ||
		!validConfigurationBindingValue(value) {
		return nativeconfig.Binding{}, errors.New("configuration binding is invalid")
	}
	return nativeconfig.Binding{ID: integrations.BindingID(id), Value: value}, nil
}

func decodeConfigurationValue(raw []byte) (integrations.Value, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return integrations.Value{}, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return integrations.Value{}, errors.New("configuration value has trailing data")
	}
	switch value := decoded.(type) {
	case string:
		if value == "" || len(value) > maximumConfigurationStringBytes || strings.ContainsRune(value, 0) {
			return integrations.Value{}, errors.New("configuration string is invalid")
		}
		return integrations.StringValue(value), nil
	case bool:
		return integrations.BooleanValue(value), nil
	case json.Number:
		integer, err := strconv.ParseInt(value.String(), 10, 64)
		if err != nil || integer < -maximumConfigurationSafeInteger || integer > maximumConfigurationSafeInteger {
			return integrations.Value{}, errors.New("configuration integer is invalid")
		}
		return integrations.IntegerValue(integer), nil
	case []any:
		if len(value) > maximumConfigurationListItems {
			return integrations.Value{}, errors.New("configuration list is too large")
		}
		items := make([]string, len(value))
		for index, item := range value {
			text, ok := item.(string)
			if !ok || !validConfigurationListItem(text) {
				return integrations.Value{}, errors.New("configuration list item is invalid")
			}
			items[index] = text
		}
		return integrations.StringListValue(items), nil
	default:
		return integrations.Value{}, errors.New("configuration value type is invalid")
	}
}

func validConfigurationBindingValue(value string) bool {
	return value != "" && len(value) <= maximumConfigurationBindingBytes && utf8.ValidString(value) &&
		strings.TrimSpace(value) == value && strings.IndexFunc(value, func(character rune) bool {
		return character < 0x20 || character == 0x7f
	}) < 0
}

func validConfigurationListItem(value string) bool {
	return value != "" && len(value) <= maximumConfigurationItemBytes && utf8.ValidString(value) &&
		strings.IndexFunc(value, func(character rune) bool {
			return character < 0x20 || character == 0x7f
		}) < 0
}

func hasDuplicateBindings(bindings []nativeconfig.Binding) bool {
	seen := make(map[integrations.BindingID]struct{}, len(bindings))
	for _, binding := range bindings {
		if _, duplicate := seen[binding.ID]; duplicate {
			return true
		}
		seen[binding.ID] = struct{}{}
	}
	return false
}

func clearConfigurationChanges(changes []nativeconfig.Change) {
	for index := range changes {
		changes[index].Value = integrations.Value{}
		clear(changes[index].Bindings)
		changes[index].Bindings = nil
	}
	clear(changes)
}

func clearRawMessages(messages []json.RawMessage) {
	for index := range messages {
		clear(messages[index])
	}
}

func writeConfigurationJSONError(response http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeAPIError(response, http.StatusRequestEntityTooLarge, "invalid_request", "The request body is too large.")
		return
	}
	writeInvalidConfigurationRequest(response)
}

func writeInvalidConfigurationRequest(response http.ResponseWriter) {
	writeAPIError(response, http.StatusBadRequest, "invalid_request", "The native configuration request is invalid.")
}

func writeConfigurationServiceError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, configuration.ErrBusy):
		response.Header().Set("Retry-After", "1")
		writeAPIError(response, http.StatusTooManyRequests, "service_busy", "Another native workspace action is in progress.")
	case errors.Is(err, configuration.ErrChanged), errors.Is(err, workspace.ErrSourceChanged):
		writeAPIError(response, http.StatusConflict, "configuration_changed", "The native configuration no longer matches the reviewed sources.")
	case errors.Is(err, configuration.ErrInvalid):
		writeInvalidConfigurationRequest(response)
	default:
		writeConfigurationUnavailable(response)
	}
}

func writeConfigurationUnavailable(response http.ResponseWriter) {
	writeAPIError(response, http.StatusServiceUnavailable, "service_unavailable", "Native configuration status is unavailable.")
}
