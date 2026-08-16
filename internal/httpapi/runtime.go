package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sgurden-certleap/AcmeMux/internal/compatibility"
	"github.com/sgurden-certleap/AcmeMux/internal/identity"
	acmeruntime "github.com/sgurden-certleap/AcmeMux/internal/runtime"
	"github.com/sgurden-certleap/AcmeMux/internal/workspace"
)

const (
	maximumRuntimeBodyBytes = 16 * 1024
	maximumRuntimePathBytes = 4095
	maximumManifestIDBytes  = 128
)

var (
	runtimeDigestPattern   = regexp.MustCompile(`^[a-f0-9]{64}$`)
	runtimeManifestPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
)

// RuntimeInspector is the non-mutating executable inspection surface used by
// the browser API. The concrete runtime.Inspector performs the Linux trust
// boundary checks and the one allowed identity probe.
type RuntimeInspector interface {
	Inspect(context.Context, string) (acmeruntime.Observation, error)
	Verify(context.Context, acmeruntime.Observation) (acmeruntime.Observation, error)
}

// RuntimeSelections persists the exact evidence explicitly reviewed by the
// administrator. The concrete runtime.SelectionStore stores metadata only.
type RuntimeSelections interface {
	Load(context.Context) (acmeruntime.Selection, error)
	Save(context.Context, acmeruntime.Selection) error
}

// RuntimeClassifier makes a fail-closed exact-manifest compatibility decision.
type RuntimeClassifier func(acmeruntime.Observation) compatibility.Result

// RuntimeDependencies are the runtime capabilities required by the HTTP API.
// They are explicit so tests cannot accidentally invoke a host executable.
type RuntimeDependencies struct {
	Inspector        RuntimeInspector
	Selections       RuntimeSelections
	Classify         RuntimeClassifier
	AcquireWorkspace WorkspaceLeaseFunc
	EditJournal      NativeEditJournal
	Now              func() time.Time
}

func (dependencies RuntimeDependencies) validate() (RuntimeDependencies, error) {
	if dependencies.Inspector == nil {
		return RuntimeDependencies{}, errors.New("runtime inspector is required")
	}
	if dependencies.Selections == nil {
		return RuntimeDependencies{}, errors.New("runtime selection store is required")
	}
	if dependencies.Classify == nil {
		return RuntimeDependencies{}, errors.New("runtime compatibility classifier is required")
	}
	if dependencies.AcquireWorkspace == nil {
		return RuntimeDependencies{}, errors.New("runtime workspace coordinator is required")
	}
	if dependencies.EditJournal == nil {
		return RuntimeDependencies{}, errors.New("runtime native edit journal is required")
	}
	if dependencies.Now == nil {
		dependencies.Now = time.Now
	}
	return dependencies, nil
}

type runtimeEndpoints struct {
	identity   *identityEndpoints
	inspector  RuntimeInspector
	selections RuntimeSelections
	classify   RuntimeClassifier
	acquire    WorkspaceLeaseFunc
	journal    NativeEditJournal
	now        func() time.Time
}

type runtimePathRequest struct {
	Path string `json:"path"`
}

type runtimeAdoptionRequest struct {
	Path                   string `json:"path"`
	ReviewedSHA256         string `json:"reviewedSha256"`
	ReviewedManifestID     string `json:"reviewedManifestId"`
	ReviewedEvidenceSHA256 string `json:"reviewedEvidenceSha256"`
}

type runtimeEvidence struct {
	CanonicalPath string          `json:"canonicalPath"`
	Version       *string         `json:"version"`
	Commit        *string         `json:"commit"`
	VersionOutput string          `json:"versionOutput"`
	Platform      runtimePlatform `json:"platform"`
	Metadata      runtimeMetadata `json:"metadata"`
	Build         runtimeBuild    `json:"build"`
	SHA256        string          `json:"sha256"`
}

type runtimePlatform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
}

type runtimeMetadata struct {
	SizeBytes    int64  `json:"sizeBytes"`
	ModifiedAt   string `json:"modifiedAt"`
	ChangedAt    string `json:"changedAt"`
	Mode         string `json:"mode"`
	Capabilities string `json:"capabilities"`
	UID          uint32 `json:"uid"`
	GID          uint32 `json:"gid"`
	Device       string `json:"device"`
	Inode        string `json:"inode"`
}

type runtimeBuild struct {
	Available             bool   `json:"available"`
	ProvenanceComplete    bool   `json:"provenanceComplete"`
	GoVersion             string `json:"goVersion"`
	CommandPath           string `json:"commandPath"`
	MainPath              string `json:"mainPath"`
	MainVersion           string `json:"mainVersion"`
	DependencyGraphSHA256 string `json:"dependencyGraphSha256"`
	GOOS                  string `json:"goos"`
	GOARCH                string `json:"goarch"`
	VCSRevision           string `json:"vcsRevision"`
	VCSModifiedKnown      bool   `json:"vcsModifiedKnown"`
	VCSModifiedValid      bool   `json:"vcsModifiedValid"`
	VCSModified           bool   `json:"vcsModified"`
}

type runtimeCompatibility struct {
	State      string `json:"state"`
	Code       string `json:"code"`
	ManifestID string `json:"manifestId,omitempty"`
	Summary    string `json:"summary"`
}

type runtimeSnapshot struct {
	State         string                `json:"state"`
	Runtime       *runtimeEvidence      `json:"runtime,omitempty"`
	Compatibility *runtimeCompatibility `json:"compatibility,omitempty"`
	Path          string                `json:"path,omitempty"`
	Diagnostic    *runtimeDiagnostic    `json:"diagnostic,omitempty"`
}

type runtimeCandidate struct {
	State                  string                `json:"state"`
	Candidate              *runtimeEvidence      `json:"candidate,omitempty"`
	Compatibility          *runtimeCompatibility `json:"compatibility,omitempty"`
	ReviewedEvidenceSHA256 string                `json:"reviewedEvidenceSha256,omitempty"`
	Path                   string                `json:"path,omitempty"`
	Diagnostic             *runtimeDiagnostic    `json:"diagnostic,omitempty"`
}

type runtimeAuthorization struct {
	sessionToken string
	csrfToken    string
}

type runtimeDiagnostic struct {
	Code    acmeruntime.ErrorCode `json:"code"`
	Message string                `json:"message"`
}

func newRuntimeEndpoints(identityAPI *identityEndpoints, dependencies RuntimeDependencies) (*runtimeEndpoints, error) {
	if identityAPI == nil {
		return nil, errors.New("identity endpoints are required")
	}
	validated, err := dependencies.validate()
	if err != nil {
		return nil, err
	}
	return &runtimeEndpoints{
		identity:   identityAPI,
		inspector:  validated.Inspector,
		selections: validated.Selections,
		classify:   validated.Classify,
		acquire:    validated.AcquireWorkspace,
		journal:    validated.EditJournal,
		now:        validated.Now,
	}, nil
}

func (endpoints *runtimeEndpoints) register(multiplexer *http.ServeMux) {
	multiplexer.HandleFunc("GET /api/v1/runtime", endpoints.getRuntime)
	multiplexer.HandleFunc("POST /api/v1/runtime/candidates", endpoints.inspectCandidate)
	multiplexer.HandleFunc("PUT /api/v1/runtime", endpoints.adoptRuntime)
}

func (endpoints *runtimeEndpoints) getRuntime(response http.ResponseWriter, request *http.Request) {
	if _, ok := endpoints.authorize(response, request, false); !ok {
		return
	}
	selection, err := endpoints.selections.Load(request.Context())
	if errors.Is(err, acmeruntime.ErrNoSelection) {
		writeJSON(response, http.StatusOK, runtimeSnapshot{State: "unselected"})
		return
	}
	if err != nil {
		writeRuntimeUnavailable(response)
		return
	}

	current, err := endpoints.inspector.Verify(request.Context(), selection.Observation)
	if err != nil {
		if isRuntimeInspectionBusy(err) {
			writeRuntimeBusy(response)
			return
		}
		diagnostic, ok := selectedRuntimeDiagnostic(err)
		if !ok {
			writeRuntimeUnavailable(response)
			return
		}
		writeJSON(response, http.StatusOK, runtimeSnapshot{
			State:      diagnosticState(diagnostic.Code, true),
			Path:       selection.Observation.File.CanonicalPath,
			Diagnostic: &diagnostic,
			Runtime:    ptrRuntimeEvidence(presentRuntimeEvidence(selection.Observation)),
		})
		return
	}

	decision := endpoints.classify(current)
	presentation := presentCompatibility(decision)
	if decision.Compatible() && string(decision.ManifestID) != selection.ManifestID {
		presentation = runtimeCompatibility{
			State:   "incompatible",
			Code:    "manifest_changed",
			Summary: "The reviewed compatibility manifest no longer matches this executable.",
		}
	}
	evidence := presentRuntimeEvidence(current)
	writeJSON(response, http.StatusOK, runtimeSnapshot{
		State:         presentation.State,
		Runtime:       &evidence,
		Compatibility: &presentation,
	})
}

func (endpoints *runtimeEndpoints) inspectCandidate(response http.ResponseWriter, request *http.Request) {
	if _, ok := endpoints.authorize(response, request, true); !ok {
		return
	}
	var payload runtimePathRequest
	if !readRuntimeObject(response, request, map[string]*string{
		"path": &payload.Path,
	}) {
		return
	}
	if !validRuntimePath(payload.Path) {
		writeInvalidRuntimeRequest(response)
		return
	}

	observation, err := endpoints.inspector.Inspect(request.Context(), payload.Path)
	if err != nil {
		if isRuntimeInspectionBusy(err) {
			writeRuntimeBusy(response)
			return
		}
		diagnostic, ok := directRuntimeDiagnostic(err)
		if !ok {
			writeRuntimeUnavailable(response)
			return
		}
		writeJSON(response, http.StatusOK, runtimeCandidate{
			State:      diagnosticState(diagnostic.Code, false),
			Path:       payload.Path,
			Diagnostic: &diagnostic,
		})
		return
	}

	evidence := presentRuntimeEvidence(observation)
	decision := endpoints.classify(observation)
	presentation := presentCompatibility(decision)
	reviewedEvidenceSHA256 := ""
	if decision.ManifestID != "" {
		reviewedEvidenceSHA256 = acmeruntime.ReviewFingerprint(observation, string(decision.ManifestID))
	}
	writeJSON(response, http.StatusOK, runtimeCandidate{
		State:                  "review_required",
		Candidate:              &evidence,
		Compatibility:          &presentation,
		ReviewedEvidenceSHA256: reviewedEvidenceSHA256,
	})
}

func (endpoints *runtimeEndpoints) adoptRuntime(response http.ResponseWriter, request *http.Request) {
	authorization, ok := endpoints.authorize(response, request, true)
	if !ok {
		return
	}
	var payload runtimeAdoptionRequest
	if !readRuntimeObject(response, request, map[string]*string{
		"path":                   &payload.Path,
		"reviewedSha256":         &payload.ReviewedSHA256,
		"reviewedManifestId":     &payload.ReviewedManifestID,
		"reviewedEvidenceSha256": &payload.ReviewedEvidenceSHA256,
	}) {
		return
	}
	if !validRuntimePath(payload.Path) ||
		!runtimeDigestPattern.MatchString(payload.ReviewedSHA256) ||
		!runtimeDigestPattern.MatchString(payload.ReviewedEvidenceSHA256) ||
		!validManifestID(payload.ReviewedManifestID) {
		writeInvalidRuntimeRequest(response)
		return
	}
	release, ok := acquireWorkspaceLease(response, request, endpoints.acquire, workspace.PurposeSave)
	if !ok {
		return
	}
	defer func() { _ = release() }()
	if !requireClearNativeEditJournal(response, request, endpoints.journal) {
		return
	}

	observation, err := endpoints.inspector.Inspect(request.Context(), payload.Path)
	if err != nil {
		if isRuntimeInspectionBusy(err) {
			writeRuntimeBusy(response)
			return
		}
		if acmeruntime.CodeOf(err) == "" {
			writeRuntimeUnavailable(response)
			return
		}
		writeRuntimeChanged(response)
		return
	}
	decision := endpoints.classify(observation)
	if !decision.Compatible() ||
		string(decision.ManifestID) != payload.ReviewedManifestID ||
		observation.File.SHA256 != payload.ReviewedSHA256 ||
		acmeruntime.ReviewFingerprint(observation, payload.ReviewedManifestID) != payload.ReviewedEvidenceSHA256 {
		writeRuntimeChanged(response)
		return
	}
	if !endpoints.reauthorizeMutation(response, request, authorization) {
		return
	}

	if err := endpoints.selections.Save(request.Context(), acmeruntime.Selection{
		Observation: observation,
		ManifestID:  payload.ReviewedManifestID,
		ReviewedAt:  endpoints.now().UTC(),
	}); err != nil {
		writeRuntimeUnavailable(response)
		return
	}

	evidence := presentRuntimeEvidence(observation)
	presentation := presentCompatibility(decision)
	writeJSON(response, http.StatusOK, runtimeSnapshot{
		State:         presentation.State,
		Runtime:       &evidence,
		Compatibility: &presentation,
	})
}

func (endpoints *runtimeEndpoints) authorize(response http.ResponseWriter, request *http.Request, mutation bool) (runtimeAuthorization, bool) {
	rawSession, present := sessionToken(request)
	if !present {
		clearSessionCookies(response)
		writeAuthenticationRequired(response)
		return runtimeAuthorization{}, false
	}
	active, rawCSRF, err := endpoints.identity.validateBrowserSession(request, rawSession)
	if errors.Is(err, identity.ErrInvalidSession) || errors.Is(err, identity.ErrSessionExpired) {
		clearSessionCookies(response)
		writeAuthenticationRequired(response)
		return runtimeAuthorization{}, false
	}
	if err != nil {
		writeServiceUnavailable(response)
		return runtimeAuthorization{}, false
	}
	pairedCSRF := ""
	if mutation {
		var validPair bool
		pairedCSRF, validPair = csrfToken(request)
		if !validPair || !active.ValidCSRF(pairedCSRF) {
			writeAPIError(response, http.StatusForbidden, "request_not_allowed", "The request could not be verified.")
			return runtimeAuthorization{}, false
		}
	}
	if err := endpoints.identity.refreshCookies(response, rawCSRF, active); err != nil {
		_ = endpoints.identity.service.Logout(request.Context(), rawSession)
		clearSessionCookies(response)
		writeServiceUnavailable(response)
		return runtimeAuthorization{}, false
	}
	effectiveSession := rawSession
	if active.ReplacementToken != "" {
		effectiveSession = active.ReplacementToken
	}
	return runtimeAuthorization{sessionToken: effectiveSession, csrfToken: pairedCSRF}, true
}

func (endpoints *runtimeEndpoints) reauthorizeMutation(
	response http.ResponseWriter,
	request *http.Request,
	authorization runtimeAuthorization,
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

func readRuntimeObject(response http.ResponseWriter, request *http.Request, fields map[string]*string) bool {
	if !requireJSON(request) {
		writeAPIError(response, http.StatusUnsupportedMediaType, "invalid_request", "A JSON request body is required.")
		return false
	}
	request.Body = http.MaxBytesReader(response, request.Body, maximumRuntimeBodyBytes)
	decoder := json.NewDecoder(request.Body)
	opening, err := decoder.Token()
	if err != nil {
		writeRuntimeJSONError(response, err)
		return false
	}
	if delimiter, ok := opening.(json.Delim); !ok || delimiter != '{' {
		writeInvalidRuntimeRequest(response)
		return false
	}
	seen := make(map[string]struct{}, len(fields))
	for decoder.More() {
		rawKey, err := decoder.Token()
		if err != nil {
			writeRuntimeJSONError(response, err)
			return false
		}
		key, ok := rawKey.(string)
		target, accepted := fields[key]
		if !ok || !accepted || target == nil {
			writeInvalidRuntimeRequest(response)
			return false
		}
		if _, duplicate := seen[key]; duplicate {
			writeInvalidRuntimeRequest(response)
			return false
		}
		var value string
		if err := decoder.Decode(&value); err != nil {
			writeRuntimeJSONError(response, err)
			return false
		}
		*target = value
		seen[key] = struct{}{}
	}
	closing, err := decoder.Token()
	if err != nil {
		writeRuntimeJSONError(response, err)
		return false
	}
	if delimiter, ok := closing.(json.Delim); !ok || delimiter != '}' || len(seen) != len(fields) {
		writeInvalidRuntimeRequest(response)
		return false
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		writeRuntimeJSONError(response, err)
		return false
	}
	return true
}

func writeRuntimeJSONError(response http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeAPIError(response, http.StatusRequestEntityTooLarge, "invalid_request", "The request body is too large.")
		return
	}
	writeInvalidRuntimeRequest(response)
}

func validRuntimePath(value string) bool {
	return value != "" &&
		len(value) <= maximumRuntimePathBytes &&
		utf8.ValidString(value) &&
		filepath.IsAbs(value) &&
		!strings.ContainsAny(value, "\x00\r\n")
}

func validManifestID(value string) bool {
	return value != "" &&
		len(value) <= maximumManifestIDBytes &&
		runtimeManifestPattern.MatchString(value)
}

func presentRuntimeEvidence(observation acmeruntime.Observation) runtimeEvidence {
	var version, commit *string
	switch observation.Version.Kind {
	case acmeruntime.VersionRelease:
		value := observation.Version.Value
		version = &value
	case acmeruntime.VersionRevision:
		value := observation.Version.Value
		commit = &value
	}
	return runtimeEvidence{
		CanonicalPath: observation.File.CanonicalPath,
		Version:       version,
		Commit:        commit,
		VersionOutput: observation.VersionOutput,
		Platform: runtimePlatform{
			OS:           observation.Platform.OS,
			Architecture: observation.Platform.Arch,
		},
		Metadata: runtimeMetadata{
			SizeBytes:    observation.File.Size,
			ModifiedAt:   observation.File.ModifiedAt.UTC().Format(time.RFC3339Nano),
			ChangedAt:    observation.File.ChangedAt.UTC().Format(time.RFC3339Nano),
			Mode:         fmt.Sprintf("%04o", observation.File.Mode&0o7777),
			Capabilities: presentCapabilities(observation.File.Capabilities),
			UID:          observation.File.UID,
			GID:          observation.File.GID,
			Device:       strconv.FormatUint(observation.File.Device, 10),
			Inode:        strconv.FormatUint(observation.File.Inode, 10),
		},
		Build: runtimeBuild{
			Available:             observation.Build.Available,
			ProvenanceComplete:    observation.Build.ProvenanceComplete,
			GoVersion:             observation.Build.GoVersion,
			CommandPath:           observation.Build.CommandPath,
			MainPath:              observation.Build.MainPath,
			MainVersion:           observation.Build.MainVersion,
			DependencyGraphSHA256: observation.Build.DependencyGraphSHA256,
			GOOS:                  observation.Build.GOOS,
			GOARCH:                observation.Build.GOARCH,
			VCSRevision:           observation.Build.VCSRevision,
			VCSModifiedKnown:      observation.Build.VCSModifiedKnown,
			VCSModifiedValid:      observation.Build.VCSModifiedValid,
			VCSModified:           observation.Build.VCSModified,
		},
		SHA256: observation.File.SHA256,
	}
}

func ptrRuntimeEvidence(evidence runtimeEvidence) *runtimeEvidence {
	return &evidence
}

func presentCapabilities(value string) string {
	if value == "" {
		return "none"
	}
	return value
}

func presentCompatibility(decision compatibility.Result) runtimeCompatibility {
	presentation := runtimeCompatibility{Code: string(decision.Code)}
	switch {
	case decision.Compatible() && decision.ManifestID != "":
		presentation.State = "supported"
		presentation.ManifestID = string(decision.ManifestID)
		presentation.Summary = "The executable matches an exact supported compatibility manifest."
	case decision.Code == compatibility.CodeUnknownIdentity:
		presentation.State = "unverified"
		presentation.Summary = "No exact AcmeMux compatibility manifest matches this lego identity."
	default:
		presentation.State = "incompatible"
		if decision.ManifestID != "" {
			presentation.ManifestID = string(decision.ManifestID)
		}
		presentation.Summary = compatibilityFailureSummary(decision.Code)
	}
	return presentation
}

func compatibilityFailureSummary(code compatibility.Code) string {
	switch code {
	case compatibility.CodeUnsupportedPlatform:
		return "This executable platform is outside the exact supported manifest."
	case compatibility.CodeExecutableDigestMismatch:
		return "These executable bytes are not the qualified artifact recorded by the manifest."
	case compatibility.CodeVersionOutputMismatch:
		return "The exact version output differs from the qualified artifact evidence."
	case compatibility.CodeBuildEvidenceMissing, compatibility.CodeBuildEvidenceIncomplete:
		return "The executable does not contain complete build provenance required by the manifest."
	case compatibility.CodeBuildModuleMismatch:
		return "The embedded command or module identity differs from the supported lego build."
	case compatibility.CodeBuildVersionMismatch:
		return "The embedded module version differs from the exact supported identity."
	case compatibility.CodeBuildToolchainMismatch:
		return "The embedded Go toolchain differs from the qualified artifact evidence."
	case compatibility.CodeBuildDependencyMismatch:
		return "The embedded dependency graph differs from the qualified artifact evidence."
	case compatibility.CodeBuildPlatformMismatch:
		return "The embedded build platform differs from the reported executable platform."
	case compatibility.CodeBuildRevisionMismatch:
		return "The embedded source revision differs from the exact supported identity."
	case compatibility.CodeBuildModified:
		return "The executable reports a modified or unverifiable source build."
	case compatibility.CodeObservationInvalid:
		return "The inspected runtime evidence is internally inconsistent."
	default:
		return "The executable does not satisfy the exact compatibility requirements."
	}
}

func directRuntimeDiagnostic(err error) (runtimeDiagnostic, bool) {
	code := acmeruntime.CodeOf(err)
	if code == "" {
		return runtimeDiagnostic{}, false
	}
	return diagnosticForCode(code), true
}

func selectedRuntimeDiagnostic(err error) (runtimeDiagnostic, bool) {
	var replacement *acmeruntime.ReplacementError
	if errors.As(err, &replacement) {
		if replacement.Cause == nil {
			return diagnosticForCode(acmeruntime.CodeReplacement), true
		}
		if code := acmeruntime.CodeOf(replacement.Cause); code != "" {
			return diagnosticForCode(code), true
		}
		return runtimeDiagnostic{}, false
	}
	return directRuntimeDiagnostic(err)
}

func isRuntimeInspectionBusy(err error) bool {
	if acmeruntime.CodeOf(err) == acmeruntime.CodeInspectionBusy {
		return true
	}
	var replacement *acmeruntime.ReplacementError
	return errors.As(err, &replacement) &&
		replacement.Cause != nil &&
		acmeruntime.CodeOf(replacement.Cause) == acmeruntime.CodeInspectionBusy
}

func diagnosticForCode(code acmeruntime.ErrorCode) runtimeDiagnostic {
	state := diagnosticState(code, true)
	message := "The executable failed the host runtime safety checks."
	switch state {
	case "missing":
		message = "The selected executable path is unavailable."
	case "changed":
		message = "The executable no longer matches the reviewed fingerprint."
	case "malformed_output":
		message = "The bounded identity probe did not return a trusted lego identity."
	case "timed_out":
		message = "The bounded identity probe exceeded its deadline and was stopped."
	}
	return runtimeDiagnostic{Code: code, Message: message}
}

func diagnosticState(code acmeruntime.ErrorCode, selected bool) string {
	switch code {
	case acmeruntime.CodePathUnavailable:
		return "missing"
	case acmeruntime.CodeProbeTimeout, acmeruntime.CodeInspectionTimeout:
		return "timed_out"
	case acmeruntime.CodeMalformedVersion,
		acmeruntime.CodeProbeOutputLimit,
		acmeruntime.CodeProbeFailed,
		acmeruntime.CodeProbeCanceled,
		acmeruntime.CodeInspectionCanceled,
		acmeruntime.CodeBuildIdentityMismatch:
		return "malformed_output"
	case acmeruntime.CodeReplacement:
		if selected {
			return "changed"
		}
	}
	return "unsafe"
}

func writeInvalidRuntimeRequest(response http.ResponseWriter) {
	writeAPIError(response, http.StatusBadRequest, "invalid_request", "The runtime request is invalid.")
}

func writeRuntimeChanged(response http.ResponseWriter) {
	writeAPIError(response, http.StatusConflict, "runtime_changed", "The executable no longer matches the reviewed evidence.")
}

func writeRuntimeUnavailable(response http.ResponseWriter) {
	writeAPIError(response, http.StatusServiceUnavailable, "service_unavailable", "Runtime status is unavailable.")
}

func writeRuntimeBusy(response http.ResponseWriter) {
	response.Header().Set("Retry-After", "1")
	writeAPIError(response, http.StatusServiceUnavailable, "service_unavailable", "Runtime inspection is already in progress.")
}
