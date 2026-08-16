package httpapi

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sgurden-certleap/AcmeMux/internal/identity"
	"github.com/sgurden-certleap/AcmeMux/internal/integrations"
	"github.com/sgurden-certleap/AcmeMux/internal/jobs"
	"github.com/sgurden-certleap/AcmeMux/internal/operation"
	"github.com/sgurden-certleap/AcmeMux/internal/workspace"
)

const maximumOperationRequestBytes = 4096

var (
	operationIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)
	operationIDPattern         = regexp.MustCompile(`^[a-f0-9]{32}$`)
	operationReasonPattern     = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	operationManifestPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	operationReleasePattern    = regexp.MustCompile(`^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$`)
	operationRevisionPattern   = regexp.MustCompile(`^[a-f0-9]{40}$`)
	acceptedOperationCAs       = map[string]struct{}{
		"googletrust": {}, "googletrust-staging": {},
		"https://acme-staging-v02.api.letsencrypt.org/directory": {},
		"https://acme.godaddy.com/v1/acme/directory":             {},
		"https://acme.ssl.com/sslcom-dv-ecc":                     {},
		"https://acme.ssl.com/sslcom-dv-rsa":                     {},
		"https://acme.zerossl.com/v2/DV90":                       {},
		"https://acme-v02.api.letsencrypt.org/directory":         {},
		"https://dv.acme-v02.api.pki.goog/directory":             {},
		"https://dv.acme-v02.test-api.pki.goog/directory":        {},
		"letsencrypt": {}, "letsencrypt-staging": {}, "sslcomecc": {}, "sslcomrsa": {}, "zerossl": {},
	}
)

type OperationService interface {
	Preview(context.Context) (operation.Preview, error)
	Enqueue(context.Context, string, workspace.CommitGuard) (jobs.Operation, error)
	Status(context.Context) (jobs.Operation, error)
	Latest(context.Context) (jobs.Operation, error)
	Policy() operation.Policy
}

type OperationDependencies struct {
	Service OperationService
}

func (dependencies OperationDependencies) validate() (OperationDependencies, error) {
	if dependencies.Service == nil {
		return OperationDependencies{}, errors.New("native operation service is required")
	}
	return dependencies, nil
}

type operationEndpoints struct {
	identity *identityEndpoints
	service  OperationService
}

type operationAuthorization struct {
	sessionToken string
	csrfToken    string
}

type operationPolicy struct {
	BrowserDisconnect string `json:"browserDisconnect"`
	Cancellation      string `json:"cancellation"`
	Retry             string `json:"retry"`
	TimeoutSeconds    int64  `json:"timeoutSeconds"`
}

type operationPolicyResponse struct {
	Policy operationPolicy `json:"policy"`
}

type operationPreview struct {
	State                string          `json:"state"`
	ReviewedPreviewToken string          `json:"reviewedPreviewToken"`
	Intent               operationIntent `json:"intent"`
	Policy               operationPolicy `json:"policy"`
}

type operationIntent struct {
	Kind              string                 `json:"kind"`
	WorkingDirectory  string                 `json:"workingDirectory"`
	ConfigurationPath string                 `json:"configurationPath"`
	StoragePath       string                 `json:"storagePath"`
	Runtime           operationRuntime       `json:"runtime"`
	Certificates      []operationCertificate `json:"certificates"`
	NativeEffects     []string               `json:"nativeEffects"`
}

type operationRuntime struct {
	Identity   string `json:"identity"`
	ManifestID string `json:"manifestId"`
}

type operationCertificate struct {
	Name      string             `json:"name"`
	Domains   []string           `json:"domains"`
	Account   string             `json:"account"`
	CA        string             `json:"ca"`
	Challenge operationChallenge `json:"challenge"`
}

type operationChallenge struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	Mode string `json:"mode"`
}

type operationEnqueueRequest struct {
	ReviewedPreviewToken string
}

type operationStatus struct {
	State     string                   `json:"state"`
	Operation *activeOperationResponse `json:"operation,omitempty"`
}

type operationEnqueueResponse struct {
	Operation activeOperationResponse `json:"operation"`
}

type activeOperationResponse struct {
	ID          string  `json:"id"`
	Kind        string  `json:"kind"`
	State       string  `json:"state"`
	Phase       string  `json:"phase"`
	RequestedAt string  `json:"requestedAt"`
	StartedAt   *string `json:"startedAt"`
}

type latestOperationResponse struct {
	State  string                   `json:"state"`
	Result *terminalOperationResult `json:"result,omitempty"`
}

type terminalOperationResult struct {
	ID             string                       `json:"id"`
	Kind           string                       `json:"kind"`
	State          string                       `json:"state"`
	ReasonCode     string                       `json:"reasonCode"`
	RequestedAt    string                       `json:"requestedAt"`
	StartedAt      *string                      `json:"startedAt"`
	FinishedAt     string                       `json:"finishedAt"`
	MayHaveChanged bool                         `json:"mayHaveChanged"`
	Output         operationOutput              `json:"output"`
	Certificates   []operationCertificateResult `json:"certificates"`
	Inventory      operationInventoryResult     `json:"inventory"`
}

type operationOutput struct {
	Text      string `json:"text"`
	Truncated bool   `json:"truncated"`
}

type operationCertificateResult struct {
	Name       string `json:"name"`
	State      string `json:"state"`
	ReasonCode string `json:"reasonCode"`
}

type operationInventoryResult struct {
	State            string `json:"state"`
	CertificateCount *int   `json:"certificateCount"`
	Summary          string `json:"summary"`
}

func newOperationEndpoints(identityAPI *identityEndpoints, dependencies OperationDependencies) (*operationEndpoints, error) {
	if identityAPI == nil {
		return nil, errors.New("identity endpoints are required")
	}
	validated, err := dependencies.validate()
	if err != nil {
		return nil, err
	}
	return &operationEndpoints{identity: identityAPI, service: validated.Service}, nil
}

func (endpoints *operationEndpoints) register(multiplexer *http.ServeMux) {
	multiplexer.HandleFunc("GET /api/v1/operations/status", endpoints.getStatus)
	multiplexer.HandleFunc("GET /api/v1/operations/latest", endpoints.getLatest)
	multiplexer.HandleFunc("GET /api/v1/operations/cancel-policy", endpoints.getCancelPolicy)
	multiplexer.HandleFunc("POST /api/v1/operations/manual/previews", endpoints.previewManual)
	multiplexer.HandleFunc("POST /api/v1/operations/manual", endpoints.enqueueManual)
}

func (endpoints *operationEndpoints) getStatus(response http.ResponseWriter, request *http.Request) {
	if _, ok := endpoints.authorize(response, request, false); !ok {
		return
	}
	active, err := endpoints.service.Status(request.Context())
	if errors.Is(err, jobs.ErrNotFound) {
		writeJSON(response, http.StatusOK, operationStatus{State: "idle"})
		return
	}
	if err != nil {
		writeServiceUnavailable(response)
		return
	}
	presented, ok := presentActiveOperation(active)
	if !ok {
		writeServiceUnavailable(response)
		return
	}
	writeJSON(response, http.StatusOK, operationStatus{State: "active", Operation: &presented})
}

func (endpoints *operationEndpoints) getLatest(response http.ResponseWriter, request *http.Request) {
	if _, ok := endpoints.authorize(response, request, false); !ok {
		return
	}
	latest, err := endpoints.service.Latest(request.Context())
	if errors.Is(err, jobs.ErrNotFound) {
		writeJSON(response, http.StatusOK, latestOperationResponse{State: "empty"})
		return
	}
	if err != nil {
		writeServiceUnavailable(response)
		return
	}
	presented, ok := presentTerminalOperation(latest)
	if !ok {
		writeServiceUnavailable(response)
		return
	}
	writeJSON(response, http.StatusOK, latestOperationResponse{State: "available", Result: &presented})
}

func (endpoints *operationEndpoints) getCancelPolicy(response http.ResponseWriter, request *http.Request) {
	if _, ok := endpoints.authorize(response, request, false); !ok {
		return
	}
	policy, ok := presentOperationPolicy(endpoints.service.Policy())
	if !ok {
		writeServiceUnavailable(response)
		return
	}
	writeJSON(response, http.StatusOK, operationPolicyResponse{Policy: policy})
}

func (endpoints *operationEndpoints) previewManual(response http.ResponseWriter, request *http.Request) {
	if _, ok := endpoints.authorize(response, request, true); !ok {
		return
	}
	if !readEmptyOperationRequest(response, request) {
		return
	}
	preview, err := endpoints.service.Preview(request.Context())
	if err != nil {
		writeOperationError(response, err)
		return
	}
	presented, ok := presentOperationPreview(preview)
	if !ok {
		writeServiceUnavailable(response)
		return
	}
	writeJSON(response, http.StatusOK, presented)
}

func (endpoints *operationEndpoints) enqueueManual(response http.ResponseWriter, request *http.Request) {
	authorization, ok := endpoints.authorize(response, request, true)
	if !ok {
		return
	}
	payload, ok := readOperationEnqueueRequest(response, request)
	if !ok {
		return
	}
	guardResponded := false
	guard := func(context.Context) error {
		if !endpoints.reauthorizeMutation(response, request, authorization) {
			guardResponded = true
			return errors.New("manual operation authorization failed")
		}
		return nil
	}
	active, err := endpoints.service.Enqueue(request.Context(), payload.ReviewedPreviewToken, guard)
	if guardResponded {
		return
	}
	if err != nil {
		writeOperationError(response, err)
		return
	}
	presented, ok := presentActiveOperation(active)
	if !ok {
		writeServiceUnavailable(response)
		return
	}
	writeJSON(response, http.StatusAccepted, operationEnqueueResponse{Operation: presented})
}

func (endpoints *operationEndpoints) authorize(response http.ResponseWriter, request *http.Request, mutation bool) (operationAuthorization, bool) {
	rawSession, present := sessionToken(request)
	if !present {
		clearSessionCookies(response)
		writeAuthenticationRequired(response)
		return operationAuthorization{}, false
	}
	active, rawCSRF, err := endpoints.identity.validateBrowserSession(request, rawSession)
	if errors.Is(err, identity.ErrInvalidSession) || errors.Is(err, identity.ErrSessionExpired) {
		clearSessionCookies(response)
		writeAuthenticationRequired(response)
		return operationAuthorization{}, false
	}
	if err != nil {
		writeServiceUnavailable(response)
		return operationAuthorization{}, false
	}
	pairedCSRF := ""
	if mutation {
		var valid bool
		pairedCSRF, valid = csrfToken(request)
		if !valid || !active.ValidCSRF(pairedCSRF) {
			writeAPIError(response, http.StatusForbidden, "request_not_allowed", "The request could not be verified.")
			return operationAuthorization{}, false
		}
	}
	if err := endpoints.identity.refreshCookies(response, rawCSRF, active); err != nil {
		_ = endpoints.identity.service.Logout(request.Context(), rawSession)
		clearSessionCookies(response)
		writeServiceUnavailable(response)
		return operationAuthorization{}, false
	}
	effectiveSession := rawSession
	if active.ReplacementToken != "" {
		effectiveSession = active.ReplacementToken
	}
	return operationAuthorization{sessionToken: effectiveSession, csrfToken: pairedCSRF}, true
}

func (endpoints *operationEndpoints) reauthorizeMutation(
	response http.ResponseWriter,
	request *http.Request,
	authorization operationAuthorization,
) bool {
	active, err := endpoints.identity.service.ValidateSession(request.Context(), authorization.sessionToken)
	if errors.Is(err, identity.ErrInvalidSession) || errors.Is(err, identity.ErrSessionExpired) {
		writeAuthenticationRequired(response)
		return false
	}
	if err != nil {
		writeServiceUnavailable(response)
		return false
	}
	pairedCSRF, valid := csrfToken(request)
	if !valid || subtle.ConstantTimeCompare([]byte(pairedCSRF), []byte(authorization.csrfToken)) != 1 ||
		!active.ValidCSRF(pairedCSRF) {
		writeAPIError(response, http.StatusForbidden, "request_not_allowed", "The request could not be verified.")
		return false
	}
	if err := endpoints.identity.refreshCookies(response, pairedCSRF, active); err != nil {
		writeServiceUnavailable(response)
		return false
	}
	return true
}

func presentOperationPreview(preview operation.Preview) (operationPreview, bool) {
	policy, ok := presentOperationPolicy(preview.Policy)
	if !ok || !validReviewToken(preview.ReviewedPreviewToken) || len(preview.Intent.Certificates) == 0 ||
		len(preview.Intent.Certificates) > 64 || !validWorkspacePath(preview.Intent.WorkingDirectory) ||
		!validWorkspacePath(preview.Intent.ConfigurationPath) || !validWorkspacePath(preview.Intent.StoragePath) ||
		(!operationReleasePattern.MatchString(preview.Intent.RuntimeIdentity) &&
			!operationRevisionPattern.MatchString(preview.Intent.RuntimeIdentity)) ||
		!operationManifestPattern.MatchString(string(preview.Intent.RuntimeManifestID)) {
		return operationPreview{}, false
	}
	certificates := make([]operationCertificate, 0, len(preview.Intent.Certificates))
	seenCertificates := make(map[string]struct{}, len(preview.Intent.Certificates))
	for _, certificate := range preview.Intent.Certificates {
		if !operationIdentifierPattern.MatchString(certificate.Name) ||
			!operationIdentifierPattern.MatchString(certificate.Account) ||
			!operationIdentifierPattern.MatchString(certificate.ChallengeName) ||
			len(certificate.Domains) == 0 || len(certificate.Domains) > 100 ||
			!validOperationChallenge(certificate.ChallengeKind, certificate.ChallengeMode) {
			return operationPreview{}, false
		}
		if _, ok := acceptedOperationCAs[certificate.CA]; !ok {
			return operationPreview{}, false
		}
		if _, duplicate := seenCertificates[certificate.Name]; duplicate {
			return operationPreview{}, false
		}
		seenCertificates[certificate.Name] = struct{}{}
		seenDomains := make(map[string]struct{}, len(certificate.Domains))
		for _, domain := range certificate.Domains {
			if !validOperationText(domain, 253, false) {
				return operationPreview{}, false
			}
			if _, duplicate := seenDomains[domain]; duplicate {
				return operationPreview{}, false
			}
			seenDomains[domain] = struct{}{}
		}
		certificates = append(certificates, operationCertificate{
			Name: certificate.Name, Domains: append([]string{}, certificate.Domains...),
			Account: certificate.Account, CA: certificate.CA,
			Challenge: operationChallenge{
				Name: certificate.ChallengeName, Kind: certificate.ChallengeKind, Mode: certificate.ChallengeMode,
			},
		})
	}
	return operationPreview{
		State: "review_required", ReviewedPreviewToken: preview.ReviewedPreviewToken,
		Intent: operationIntent{
			Kind: "manual_workspace_run", WorkingDirectory: preview.Intent.WorkingDirectory,
			ConfigurationPath: preview.Intent.ConfigurationPath, StoragePath: preview.Intent.StoragePath,
			Runtime:      operationRuntime{Identity: preview.Intent.RuntimeIdentity, ManifestID: string(preview.Intent.RuntimeManifestID)},
			Certificates: certificates,
			NativeEffects: []string{
				"acme_accounts_may_change", "certificate_artifacts_may_change",
				"native_configuration_backup_may_change", "external_acme_state_may_change",
			},
		},
		Policy: policy,
	}, true
}

func validOperationChallenge(kind, mode string) bool {
	if kind == "http-01" {
		return mode == "listener" || mode == "webroot"
	}
	return kind == "dns-01" && integrations.SupportsCoreDNSProvider(mode)
}

func presentOperationPolicy(policy operation.Policy) (operationPolicy, bool) {
	seconds := int64(policy.Timeout / time.Second)
	if policy.Timeout <= 0 || time.Duration(seconds)*time.Second != policy.Timeout || seconds > 3600 {
		return operationPolicy{}, false
	}
	return operationPolicy{
		BrowserDisconnect: "continues", Cancellation: "not_supported", Retry: "manual_only",
		TimeoutSeconds: seconds,
	}, true
}

func presentActiveOperation(value jobs.Operation) (activeOperationResponse, bool) {
	if value.Kind != jobs.KindManual || (value.State != jobs.StateQueued && value.State != jobs.StateRunning) ||
		!operationIDPattern.MatchString(value.ID) || value.RequestedAt.IsZero() {
		return activeOperationResponse{}, false
	}
	if value.State == jobs.StateQueued && (value.Phase != jobs.PhaseQueued || !value.StartedAt.IsZero()) ||
		value.State == jobs.StateRunning &&
			(value.StartedAt.IsZero() || value.Phase != jobs.PhaseRevalidating &&
				value.Phase != jobs.PhaseExecuting && value.Phase != jobs.PhaseRefreshingInventory) {
		return activeOperationResponse{}, false
	}
	result := activeOperationResponse{
		ID: value.ID, Kind: "manual", State: string(value.State), Phase: string(value.Phase),
		RequestedAt: value.RequestedAt.UTC().Format(time.RFC3339Nano),
	}
	if !value.StartedAt.IsZero() {
		formatted := value.StartedAt.UTC().Format(time.RFC3339Nano)
		result.StartedAt = &formatted
	}
	return result, true
}

func presentTerminalOperation(value jobs.Operation) (terminalOperationResult, bool) {
	if value.Kind != jobs.KindManual || !value.Terminal() || !operationIDPattern.MatchString(value.ID) ||
		!operationReasonPattern.MatchString(value.Code) || value.RequestedAt.IsZero() ||
		value.StartedAt.IsZero() || value.FinishedAt.IsZero() || len(value.Items) == 0 || len(value.Items) > 256 ||
		len(value.Output) > 256<<10 || !utf8.ValidString(value.Output) ||
		strings.IndexFunc(value.Output, func(character rune) bool {
			return character != '\n' && character != '\r' && character != '\t' &&
				(character < 0x20 || character == 0x7f)
		}) >= 0 {
		return terminalOperationResult{}, false
	}
	result := terminalOperationResult{
		ID: value.ID, Kind: "manual", State: string(value.State), ReasonCode: value.Code,
		RequestedAt: value.RequestedAt.UTC().Format(time.RFC3339Nano),
		FinishedAt:  value.FinishedAt.UTC().Format(time.RFC3339Nano), MayHaveChanged: value.MayHaveChanged,
		Output:       operationOutput{Text: value.Output, Truncated: value.OutputTruncated},
		Certificates: make([]operationCertificateResult, 0, len(value.Items)),
	}
	if !value.StartedAt.IsZero() {
		formatted := value.StartedAt.UTC().Format(time.RFC3339Nano)
		result.StartedAt = &formatted
	}
	for _, item := range value.Items {
		if !operationIdentifierPattern.MatchString(item.Name) || !operationReasonPattern.MatchString(item.Code) ||
			(item.State != jobs.ItemCompleted && item.State != jobs.ItemFailed &&
				item.State != jobs.ItemNotAttempted && item.State != jobs.ItemAmbiguous) {
			return terminalOperationResult{}, false
		}
		result.Certificates = append(result.Certificates, operationCertificateResult{
			Name: item.Name, State: string(item.State), ReasonCode: item.Code,
		})
	}
	switch value.Inventory.State {
	case jobs.InventoryRefreshed:
		if value.Inventory.CertificateCount == nil {
			return terminalOperationResult{}, false
		}
		result.Inventory = operationInventoryResult{
			State: "refreshed", CertificateCount: value.Inventory.CertificateCount,
			Summary: "Native certificate inventory was refreshed.",
		}
	case jobs.InventoryUnavailable:
		result.Inventory = operationInventoryResult{
			State: "refresh_failed", CertificateCount: nil,
			Summary: "Native certificate inventory could not be refreshed; native state may have changed.",
		}
	default:
		return terminalOperationResult{}, false
	}
	return result, true
}

func validOperationText(value string, maximum int, multiline bool) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	return strings.IndexFunc(value, func(character rune) bool {
		if multiline && (character == '\n' || character == '\t') {
			return false
		}
		return character < 0x20 || character == 0x7f
	}) < 0
}

func readEmptyOperationRequest(response http.ResponseWriter, request *http.Request) bool {
	if !requireJSON(request) {
		writeAPIError(response, http.StatusUnsupportedMediaType, "invalid_request", "A JSON request body is required.")
		return false
	}
	request.Body = http.MaxBytesReader(response, request.Body, maximumOperationRequestBytes)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		writeOperationJSONError(response, err)
		return false
	}
	defer clear(body)
	if !utf8.Valid(body) {
		writeInvalidOperationRequest(response)
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	opening, err := decoder.Token()
	if err != nil {
		writeInvalidOperationRequest(response)
		return false
	}
	delimiter, ok := opening.(json.Delim)
	if !ok || delimiter != '{' || decoder.More() {
		writeInvalidOperationRequest(response)
		return false
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		writeInvalidOperationRequest(response)
		return false
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		writeInvalidOperationRequest(response)
		return false
	}
	return true
}

func readOperationEnqueueRequest(response http.ResponseWriter, request *http.Request) (operationEnqueueRequest, bool) {
	if !requireJSON(request) {
		writeAPIError(response, http.StatusUnsupportedMediaType, "invalid_request", "A JSON request body is required.")
		return operationEnqueueRequest{}, false
	}
	request.Body = http.MaxBytesReader(response, request.Body, maximumOperationRequestBytes)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		writeOperationJSONError(response, err)
		return operationEnqueueRequest{}, false
	}
	defer clear(body)
	if !utf8.Valid(body) {
		writeInvalidOperationRequest(response)
		return operationEnqueueRequest{}, false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		writeInvalidOperationRequest(response)
		return operationEnqueueRequest{}, false
	}
	seen := false
	var result operationEnqueueRequest
	for decoder.More() {
		keyToken, keyErr := decoder.Token()
		key, keyOK := keyToken.(string)
		if keyErr != nil || !keyOK || key != "reviewedPreviewToken" || seen || decoder.Decode(&result.ReviewedPreviewToken) != nil {
			writeInvalidOperationRequest(response)
			return operationEnqueueRequest{}, false
		}
		seen = true
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || !seen || !validReviewToken(result.ReviewedPreviewToken) {
		writeInvalidOperationRequest(response)
		return operationEnqueueRequest{}, false
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		writeInvalidOperationRequest(response)
		return operationEnqueueRequest{}, false
	}
	return result, true
}

func validReviewToken(value string) bool {
	if len(value) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func writeOperationJSONError(response http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeAPIError(response, http.StatusRequestEntityTooLarge, "invalid_request", "The operation request is too large.")
		return
	}
	writeInvalidOperationRequest(response)
}

func writeInvalidOperationRequest(response http.ResponseWriter) {
	writeAPIError(response, http.StatusBadRequest, "invalid_request", "The operation request is invalid.")
}

func writeOperationError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, operation.ErrActive):
		writeAPIError(response, http.StatusConflict, "operation_active", "A native workspace operation is already active.")
	case errors.Is(err, operation.ErrChanged):
		writeAPIError(response, http.StatusConflict, "operation_changed", "The reviewed operation is no longer current.")
	case errors.Is(err, operation.ErrRecovery):
		writeAPIError(response, http.StatusConflict, "recovery_required", "Native configuration recovery is required before an operation can start.")
	case errors.Is(err, operation.ErrWorkspace):
		writeAPIError(response, http.StatusConflict, "workspace_invalid", "The native workspace is not eligible for managed execution.")
	case errors.Is(err, operation.ErrConfiguration):
		writeAPIError(response, http.StatusConflict, "configuration_invalid", "The native configuration is not eligible for managed execution.")
	case errors.Is(err, operation.ErrBusy):
		response.Header().Set("Retry-After", "1")
		writeAPIError(response, http.StatusTooManyRequests, "service_busy", "Another native workspace action is in progress.")
	case errors.Is(err, operation.ErrInvalid):
		writeInvalidOperationRequest(response)
	default:
		writeServiceUnavailable(response)
	}
}
