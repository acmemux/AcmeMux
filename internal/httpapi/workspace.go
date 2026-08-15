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
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sgurden-certleap/AcmeMux/internal/identity"
	"github.com/sgurden-certleap/AcmeMux/internal/inventory"
	acmeruntime "github.com/sgurden-certleap/AcmeMux/internal/runtime"
	"github.com/sgurden-certleap/AcmeMux/internal/workspace"
)

const (
	maximumWorkspaceBodyBytes       = 24 * 1024
	maximumWorkspacePathBytes       = 4095
	maximumWorkspaceDiagnosticCount = 256
)

// WorkspaceInspector is the non-mutating native path inspection surface used
// by the browser API.
type WorkspaceInspector interface {
	Inspect(context.Context, workspace.Request) (workspace.Review, error)
	Verify(context.Context, workspace.Review) (workspace.Review, error)
}

// WorkspaceSelections persists only the complete bounded evidence reviewed by
// the administrator. Native configuration and certificate contents remain in
// the workspace.
type WorkspaceSelections interface {
	Load(context.Context) (workspace.Selection, error)
	Save(context.Context, workspace.Selection) error
}

// WorkspaceInventory is the trusted, bounded upstream inventory projection.
type WorkspaceInventory interface {
	Read(context.Context, inventory.PreparedExecutable, string) ([]inventory.Certificate, error)
}

// RuntimePreparer rechecks the persisted executable and exact compatibility
// manifest and returns the retained one-shot handle used for inventory.
type RuntimePreparer func(context.Context) (inventory.PreparedExecutable, error)

// WorkspaceDependencies are explicit so tests cannot accidentally inspect a
// host workspace or execute a host binary.
type WorkspaceDependencies struct {
	Inspector      WorkspaceInspector
	Selections     WorkspaceSelections
	Inventory      WorkspaceInventory
	PrepareRuntime RuntimePreparer
	Now            func() time.Time
}

func (dependencies WorkspaceDependencies) validate() (WorkspaceDependencies, error) {
	if dependencies.Inspector == nil {
		return WorkspaceDependencies{}, errors.New("workspace inspector is required")
	}
	if dependencies.Selections == nil {
		return WorkspaceDependencies{}, errors.New("workspace selection store is required")
	}
	if dependencies.Inventory == nil {
		return WorkspaceDependencies{}, errors.New("workspace inventory reader is required")
	}
	if dependencies.PrepareRuntime == nil {
		return WorkspaceDependencies{}, errors.New("workspace runtime preparer is required")
	}
	if dependencies.Now == nil {
		dependencies.Now = time.Now
	}
	return dependencies, nil
}

type workspaceEndpoints struct {
	identity       *identityEndpoints
	inspector      WorkspaceInspector
	selections     WorkspaceSelections
	inventory      WorkspaceInventory
	prepareRuntime RuntimePreparer
	now            func() time.Time
}

type workspaceRequest struct {
	WorkingDirectory  string
	ConfigurationPath string
	ReviewedEvidence  string
}

type workspaceAuthorization struct {
	sessionToken string
	csrfToken    string
}

type workspaceSnapshot struct {
	State       string                 `json:"state"`
	Workspace   *workspaceEvidence     `json:"workspace,omitempty"`
	Inventory   []workspaceCertificate `json:"inventory"`
	Diagnostics []workspaceDiagnostic  `json:"diagnostics"`
}

type workspaceCandidate struct {
	State                  string                `json:"state"`
	Candidate              workspaceEvidence     `json:"candidate"`
	ReviewedEvidenceSHA256 string                `json:"reviewedEvidenceSha256"`
	Adoptable              bool                  `json:"adoptable"`
	Diagnostics            []workspaceDiagnostic `json:"diagnostics"`
}

type workspaceEvidence struct {
	WorkingDirectory workspacePathEvidence   `json:"workingDirectory"`
	Configuration    workspaceConfiguration  `json:"configuration"`
	Storage          workspacePathEvidence   `json:"storage"`
	Dotenv           []workspacePathEvidence `json:"dotenv"`
	Webroots         []workspacePathEvidence `json:"webroots"`
}

type workspaceConfiguration struct {
	Source string                `json:"source"`
	Path   workspacePathEvidence `json:"path"`
}

type workspacePathEvidence struct {
	ConfiguredPath *string                      `json:"configuredPath"`
	CanonicalPath  *string                      `json:"canonicalPath"`
	Status         string                       `json:"status"`
	Access         workspaceAccessEvidence      `json:"access"`
	Type           string                       `json:"type"`
	Metadata       *workspacePathMetadata       `json:"metadata"`
	Components     []workspaceComponentEvidence `json:"components"`
	Safe           bool                         `json:"safe"`
}

type workspaceAccessEvidence struct {
	Readable   bool `json:"readable"`
	Writable   bool `json:"writable"`
	Searchable bool `json:"searchable"`
}

type workspacePathMetadata struct {
	UID        uint32 `json:"uid"`
	GID        uint32 `json:"gid"`
	Mode       string `json:"mode"`
	NLink      uint64 `json:"nlink"`
	Device     string `json:"device"`
	Inode      string `json:"inode"`
	SizeBytes  int64  `json:"sizeBytes"`
	ModifiedAt string `json:"modifiedAt"`
	ChangedAt  string `json:"changedAt"`
}

type workspaceComponentEvidence struct {
	Path   string                  `json:"path"`
	Type   string                  `json:"type"`
	Device string                  `json:"device"`
	Inode  string                  `json:"inode"`
	Mode   string                  `json:"mode"`
	UID    uint32                  `json:"uid"`
	GID    uint32                  `json:"gid"`
	Access workspaceAccessEvidence `json:"access"`
}

type workspaceDiagnostic struct {
	Code      string  `json:"code"`
	Severity  string  `json:"severity"`
	Role      string  `json:"role"`
	Message   string  `json:"message"`
	Path      *string `json:"path"`
	Component *string `json:"component"`
}

type workspaceCertificate struct {
	Name      string                       `json:"name"`
	DNSNames  []string                     `json:"dnsNames"`
	Issuer    string                       `json:"issuer"`
	ExpiresAt string                       `json:"expiresAt"`
	Artifact  workspaceCertificateArtifact `json:"artifact"`
}

type workspaceCertificateArtifact struct {
	NativePath string `json:"nativePath"`
	UID        uint32 `json:"uid"`
	GID        uint32 `json:"gid"`
	Mode       string `json:"mode"`
	NLink      uint64 `json:"nlink"`
	Device     string `json:"device"`
	Inode      string `json:"inode"`
	SizeBytes  int64  `json:"sizeBytes"`
	ModifiedAt string `json:"modifiedAt"`
	ChangedAt  string `json:"changedAt"`
}

func newWorkspaceEndpoints(identityAPI *identityEndpoints, dependencies WorkspaceDependencies) (*workspaceEndpoints, error) {
	if identityAPI == nil {
		return nil, errors.New("identity endpoints are required")
	}
	validated, err := dependencies.validate()
	if err != nil {
		return nil, err
	}
	return &workspaceEndpoints{
		identity:       identityAPI,
		inspector:      validated.Inspector,
		selections:     validated.Selections,
		inventory:      validated.Inventory,
		prepareRuntime: validated.PrepareRuntime,
		now:            validated.Now,
	}, nil
}

func (endpoints *workspaceEndpoints) register(multiplexer *http.ServeMux) {
	multiplexer.HandleFunc("GET /api/v1/workspace", endpoints.getWorkspace)
	multiplexer.HandleFunc("POST /api/v1/workspace/candidates", endpoints.inspectWorkspace)
	multiplexer.HandleFunc("PUT /api/v1/workspace", endpoints.adoptWorkspace)
}

func (endpoints *workspaceEndpoints) getWorkspace(response http.ResponseWriter, request *http.Request) {
	if _, ok := endpoints.authorize(response, request, false); !ok {
		return
	}
	selection, err := endpoints.selections.Load(request.Context())
	if errors.Is(err, workspace.ErrNoSelection) {
		writeJSON(response, http.StatusOK, map[string]string{"state": "unadopted"})
		return
	}
	if err != nil {
		writeWorkspaceUnavailable(response)
		return
	}

	prepared, err := endpoints.prepareRuntime(request.Context())
	if err != nil || prepared == nil {
		if workspaceRuntimeBusy(err) {
			writeWorkspaceRuntimeError(response, err)
			return
		}
		evidence := presentWorkspaceEvidence(selection.Review)
		diagnostics := presentWorkspaceDiagnostics(selection.Review.Diagnostics)
		diagnostics = append(diagnostics, runtimeWorkspaceDiagnostic(err))
		writeJSON(response, http.StatusOK, workspaceSnapshot{
			State:       "incompatible",
			Workspace:   &evidence,
			Inventory:   []workspaceCertificate{},
			Diagnostics: diagnostics,
		})
		return
	}

	current, verifyErr := endpoints.inspector.Verify(request.Context(), selection.Review)
	if verifyErr != nil {
		_ = prepared.Close()
		if !writeChangedWorkspaceSnapshot(response, current, verifyErr) {
			writeWorkspaceUnavailable(response)
		}
		return
	}

	certificates, err := endpoints.inventory.Read(request.Context(), prepared, current.Storage.Path)
	if err != nil {
		evidence := presentWorkspaceEvidence(current)
		diagnostics := presentWorkspaceDiagnostics(current.Diagnostics)
		diagnostics = append(diagnostics, inventoryWorkspaceDiagnostic(err))
		writeJSON(response, http.StatusOK, workspaceSnapshot{
			State:       "inventory_unavailable",
			Workspace:   &evidence,
			Inventory:   []workspaceCertificate{},
			Diagnostics: diagnostics,
		})
		return
	}
	confirmed, verifyErr := endpoints.inspector.Verify(request.Context(), current)
	if verifyErr != nil {
		if !writeChangedWorkspaceSnapshot(response, confirmed, verifyErr) {
			writeWorkspaceUnavailable(response)
		}
		return
	}
	current = confirmed
	evidence := presentWorkspaceEvidence(current)
	writeJSON(response, http.StatusOK, workspaceSnapshot{
		State:       "ready",
		Workspace:   &evidence,
		Inventory:   presentWorkspaceCertificates(certificates),
		Diagnostics: presentWorkspaceDiagnostics(current.Diagnostics),
	})
}

func writeChangedWorkspaceSnapshot(response http.ResponseWriter, current workspace.Review, verifyErr error) bool {
	var changed *workspace.VerificationError
	if !errors.As(verifyErr, &changed) {
		return false
	}
	evidence := presentWorkspaceEvidence(current)
	diagnostics := presentWorkspaceDiagnostics(current.Diagnostics)
	state := changedWorkspaceState(current)
	diagnostics = appendMandatoryWorkspaceDiagnostic(diagnostics, workspaceDiagnosticForCode(
		string(workspace.CodeReviewEvidenceChanged), "blocking", "workspace", "", "",
	), state)
	writeJSON(response, http.StatusOK, workspaceSnapshot{
		State:       state,
		Workspace:   &evidence,
		Inventory:   []workspaceCertificate{},
		Diagnostics: diagnostics,
	})
	return true
}

func appendMandatoryWorkspaceDiagnostic(diagnostics []workspaceDiagnostic, mandatory workspaceDiagnostic, state string) []workspaceDiagnostic {
	if len(diagnostics) < maximumWorkspaceDiagnosticCount {
		return append(diagnostics, mandatory)
	}
	required := make(map[int]struct{}, 2)
	if diagnostics[len(diagnostics)-1].Code == string(workspace.CodeReviewEvidenceLimit) {
		required[len(diagnostics)-1] = struct{}{}
	}
	for index, diagnostic := range diagnostics {
		if workspaceDiagnosticSupportsState(diagnostic, state) {
			required[index] = struct{}{}
			break
		}
	}
	keep := make([]bool, len(diagnostics))
	for index := range required {
		keep[index] = true
	}
	remaining := maximumWorkspaceDiagnosticCount - 1 - len(required)
	for index := range diagnostics {
		if keep[index] || remaining == 0 {
			continue
		}
		keep[index] = true
		remaining--
	}
	bounded := make([]workspaceDiagnostic, 0, maximumWorkspaceDiagnosticCount)
	for index, diagnostic := range diagnostics {
		if keep[index] {
			bounded = append(bounded, diagnostic)
		}
	}
	return append(bounded, mandatory)
}

func workspaceDiagnosticSupportsState(diagnostic workspaceDiagnostic, state string) bool {
	if diagnostic.Severity != "blocking" {
		return false
	}
	switch state {
	case "missing":
		return diagnostic.Code == string(workspace.CodePathMissing) || diagnostic.Code == string(workspace.CodeConfigurationMissing)
	case "read_only":
		return diagnostic.Code == string(workspace.CodePathReadOnly)
	case "unsafe":
		return diagnostic.Code != string(workspace.CodePathMissing) &&
			diagnostic.Code != string(workspace.CodeConfigurationMissing) &&
			diagnostic.Code != string(workspace.CodePathReadOnly)
	default:
		return false
	}
}

func (endpoints *workspaceEndpoints) inspectWorkspace(response http.ResponseWriter, request *http.Request) {
	if _, ok := endpoints.authorize(response, request, true); !ok {
		return
	}
	payload, ok := readWorkspaceRequest(response, request, false)
	if !ok {
		return
	}
	prepared, err := endpoints.prepareRuntime(request.Context())
	if err != nil || prepared == nil {
		writeWorkspaceRuntimeError(response, err)
		return
	}
	if err := prepared.Close(); err != nil {
		writeWorkspaceUnavailable(response)
		return
	}
	review, err := endpoints.inspector.Inspect(request.Context(), workspace.Request{
		WorkingDirectory:  payload.WorkingDirectory,
		ConfigurationPath: payload.ConfigurationPath,
	})
	if err != nil {
		if invalidWorkspaceRequestError(err) {
			writeInvalidWorkspaceRequest(response)
		} else {
			writeWorkspaceUnavailable(response)
		}
		return
	}
	writeJSON(response, http.StatusOK, workspaceCandidate{
		State:                  "review_required",
		Candidate:              presentWorkspaceEvidence(review),
		ReviewedEvidenceSHA256: review.ReviewedEvidenceSHA256,
		Adoptable:              review.Adoptable,
		Diagnostics:            presentWorkspaceDiagnostics(review.Diagnostics),
	})
}

func (endpoints *workspaceEndpoints) adoptWorkspace(response http.ResponseWriter, request *http.Request) {
	authorization, ok := endpoints.authorize(response, request, true)
	if !ok {
		return
	}
	payload, ok := readWorkspaceRequest(response, request, true)
	if !ok {
		return
	}
	prepared, err := endpoints.prepareRuntime(request.Context())
	if err != nil || prepared == nil {
		writeWorkspaceRuntimeError(response, err)
		return
	}
	review, err := endpoints.inspector.Inspect(request.Context(), workspace.Request{
		WorkingDirectory:  payload.WorkingDirectory,
		ConfigurationPath: payload.ConfigurationPath,
	})
	if err != nil {
		_ = prepared.Close()
		if invalidWorkspaceRequestError(err) {
			writeInvalidWorkspaceRequest(response)
		} else {
			writeWorkspaceUnavailable(response)
		}
		return
	}
	if !review.Adoptable ||
		review.ReviewedEvidenceSHA256 != payload.ReviewedEvidence ||
		workspace.ReviewFingerprint(review) != payload.ReviewedEvidence {
		_ = prepared.Close()
		writeWorkspaceChanged(response)
		return
	}
	certificates, err := endpoints.inventory.Read(request.Context(), prepared, review.Storage.Path)
	if err != nil {
		diagnostics := presentWorkspaceDiagnostics(review.Diagnostics)
		diagnostics = append(diagnostics, inventoryWorkspaceDiagnostic(err))
		writeJSON(response, http.StatusOK, workspaceCandidate{
			State:                  "review_required",
			Candidate:              presentWorkspaceEvidence(review),
			ReviewedEvidenceSHA256: review.ReviewedEvidenceSHA256,
			Adoptable:              false,
			Diagnostics:            diagnostics,
		})
		return
	}
	verified, err := endpoints.inspector.Verify(request.Context(), review)
	if err != nil || !verified.Adoptable || verified.ReviewedEvidenceSHA256 != payload.ReviewedEvidence ||
		workspace.ReviewFingerprint(verified) != payload.ReviewedEvidence {
		var changed *workspace.VerificationError
		if errors.As(err, &changed) || err == nil {
			writeWorkspaceChanged(response)
		} else {
			writeWorkspaceUnavailable(response)
		}
		return
	}
	review = verified
	if !endpoints.reauthorizeMutation(response, request, authorization) {
		return
	}
	if err := endpoints.selections.Save(request.Context(), workspace.Selection{
		Review:     review,
		ReviewedAt: endpoints.now().UTC(),
	}); err != nil {
		writeWorkspaceUnavailable(response)
		return
	}
	evidence := presentWorkspaceEvidence(review)
	writeJSON(response, http.StatusOK, workspaceSnapshot{
		State:       "ready",
		Workspace:   &evidence,
		Inventory:   presentWorkspaceCertificates(certificates),
		Diagnostics: presentWorkspaceDiagnostics(review.Diagnostics),
	})
}

func (endpoints *workspaceEndpoints) authorize(response http.ResponseWriter, request *http.Request, mutation bool) (workspaceAuthorization, bool) {
	rawSession, present := sessionToken(request)
	if !present {
		clearSessionCookies(response)
		writeAuthenticationRequired(response)
		return workspaceAuthorization{}, false
	}
	active, rawCSRF, err := endpoints.identity.validateBrowserSession(request, rawSession)
	if errors.Is(err, identity.ErrInvalidSession) || errors.Is(err, identity.ErrSessionExpired) {
		clearSessionCookies(response)
		writeAuthenticationRequired(response)
		return workspaceAuthorization{}, false
	}
	if err != nil {
		writeServiceUnavailable(response)
		return workspaceAuthorization{}, false
	}
	pairedCSRF := ""
	if mutation {
		var validPair bool
		pairedCSRF, validPair = csrfToken(request)
		if !validPair || !active.ValidCSRF(pairedCSRF) {
			writeAPIError(response, http.StatusForbidden, "request_not_allowed", "The request could not be verified.")
			return workspaceAuthorization{}, false
		}
	}
	if err := endpoints.identity.refreshCookies(response, rawCSRF, active); err != nil {
		_ = endpoints.identity.service.Logout(request.Context(), rawSession)
		clearSessionCookies(response)
		writeServiceUnavailable(response)
		return workspaceAuthorization{}, false
	}
	effectiveSession := rawSession
	if active.ReplacementToken != "" {
		effectiveSession = active.ReplacementToken
	}
	return workspaceAuthorization{sessionToken: effectiveSession, csrfToken: pairedCSRF}, true
}

func (endpoints *workspaceEndpoints) reauthorizeMutation(response http.ResponseWriter, request *http.Request, authorization workspaceAuthorization) bool {
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

func readWorkspaceRequest(response http.ResponseWriter, request *http.Request, adoption bool) (workspaceRequest, bool) {
	if !requireJSON(request) {
		writeAPIError(response, http.StatusUnsupportedMediaType, "invalid_request", "A JSON request body is required.")
		return workspaceRequest{}, false
	}
	request.Body = http.MaxBytesReader(response, request.Body, maximumWorkspaceBodyBytes)
	decoder := json.NewDecoder(request.Body)
	opening, err := decoder.Token()
	if err != nil {
		writeWorkspaceJSONError(response, err)
		return workspaceRequest{}, false
	}
	if delimiter, ok := opening.(json.Delim); !ok || delimiter != '{' {
		writeInvalidWorkspaceRequest(response)
		return workspaceRequest{}, false
	}
	required := 2
	if adoption {
		required = 3
	}
	seen := make(map[string]struct{}, required)
	var payload workspaceRequest
	for decoder.More() {
		rawKey, err := decoder.Token()
		if err != nil {
			writeWorkspaceJSONError(response, err)
			return workspaceRequest{}, false
		}
		key, ok := rawKey.(string)
		if !ok {
			writeInvalidWorkspaceRequest(response)
			return workspaceRequest{}, false
		}
		if _, duplicate := seen[key]; duplicate {
			writeInvalidWorkspaceRequest(response)
			return workspaceRequest{}, false
		}
		seen[key] = struct{}{}
		switch key {
		case "workingDirectory":
			if err := decoder.Decode(&payload.WorkingDirectory); err != nil {
				writeWorkspaceJSONError(response, err)
				return workspaceRequest{}, false
			}
		case "configurationPath":
			var raw json.RawMessage
			if err := decoder.Decode(&raw); err != nil {
				writeWorkspaceJSONError(response, err)
				return workspaceRequest{}, false
			}
			if string(raw) != "null" {
				if err := json.Unmarshal(raw, &payload.ConfigurationPath); err != nil || payload.ConfigurationPath == "" {
					writeInvalidWorkspaceRequest(response)
					return workspaceRequest{}, false
				}
			}
		case "reviewedEvidenceSha256":
			if !adoption {
				writeInvalidWorkspaceRequest(response)
				return workspaceRequest{}, false
			}
			if err := decoder.Decode(&payload.ReviewedEvidence); err != nil {
				writeWorkspaceJSONError(response, err)
				return workspaceRequest{}, false
			}
		default:
			writeInvalidWorkspaceRequest(response)
			return workspaceRequest{}, false
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		writeWorkspaceJSONError(response, err)
		return workspaceRequest{}, false
	}
	if delimiter, ok := closing.(json.Delim); !ok || delimiter != '}' || len(seen) != required {
		writeInvalidWorkspaceRequest(response)
		return workspaceRequest{}, false
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		writeWorkspaceJSONError(response, err)
		return workspaceRequest{}, false
	}
	if !validWorkspacePath(payload.WorkingDirectory) ||
		(payload.ConfigurationPath != "" && !validWorkspacePath(payload.ConfigurationPath)) ||
		(adoption && !runtimeDigestPattern.MatchString(payload.ReviewedEvidence)) {
		writeInvalidWorkspaceRequest(response)
		return workspaceRequest{}, false
	}
	return payload, true
}

func validWorkspacePath(value string) bool {
	return value != "" && len(value) <= maximumWorkspacePathBytes && utf8.ValidString(value) &&
		filepath.IsAbs(value) && filepath.Clean(value) == value && strings.IndexFunc(value, func(character rune) bool {
		return character < 0x20 || character == 0x7f
	}) < 0
}

func invalidWorkspaceRequestError(err error) bool {
	switch workspace.CodeOf(err) {
	case workspace.CodePathRequired, workspace.CodePathNotAbsolute, workspace.CodePathNotCanonical, workspace.CodePathTooLong:
		return true
	default:
		return false
	}
}

func presentWorkspaceEvidence(review workspace.Review) workspaceEvidence {
	return workspaceEvidence{
		WorkingDirectory: presentWorkspacePath(review.WorkingDirectory, review.Diagnostics),
		Configuration: workspaceConfiguration{
			Source: presentConfigurationSource(review.ConfigurationSource),
			Path:   presentWorkspacePath(review.Configuration, review.Diagnostics),
		},
		Storage:  presentWorkspacePath(review.Storage, review.Diagnostics),
		Dotenv:   presentWorkspacePaths(review.DotenvFiles, review.Diagnostics),
		Webroots: presentWorkspacePaths(review.Webroots, review.Diagnostics),
	}
}

func presentConfigurationSource(source workspace.ConfigurationSource) string {
	switch source {
	case workspace.ConfigurationConventionalYML:
		return "conventional_lego_yml"
	case workspace.ConfigurationConventionalYAML:
		return "conventional_lego_yaml"
	default:
		return "explicit"
	}
}

func presentWorkspacePaths(paths []workspace.PathEvidence, diagnostics []workspace.Diagnostic) []workspacePathEvidence {
	presented := make([]workspacePathEvidence, 0, len(paths))
	for _, path := range paths {
		presented = append(presented, presentWorkspacePath(path, diagnostics))
	}
	return presented
}

func presentWorkspacePath(evidence workspace.PathEvidence, diagnostics []workspace.Diagnostic) workspacePathEvidence {
	access := presentWorkspaceAccess(evidence.Access)
	if evidence.Path == "" {
		return workspacePathEvidence{
			Status:     "unresolved",
			Access:     access,
			Type:       "unresolved",
			Components: []workspaceComponentEvidence{},
			Safe:       false,
		}
	}
	configured := evidence.Path
	if evidence.Reference != "" {
		configured = evidence.Reference
	}
	path := evidence.Path
	presented := workspacePathEvidence{
		ConfiguredPath: &configured,
		CanonicalPath:  &path,
		Status:         workspacePathStatus(evidence, diagnostics),
		Access:         access,
		Type:           presentWorkspacePathType(evidence.Type),
		Components:     make([]workspaceComponentEvidence, 0, len(evidence.Components)),
		Safe:           evidence.Safe,
	}
	for _, component := range evidence.Components {
		presented.Components = append(presented.Components, workspaceComponentEvidence{
			Path:   component.Path,
			Type:   presentWorkspacePathType(component.Type),
			Device: strconv.FormatUint(component.Device, 10),
			Inode:  strconv.FormatUint(component.Inode, 10),
			Mode:   fmt.Sprintf("%04o", component.Mode&0o7777),
			UID:    component.UID,
			GID:    component.GID,
			Access: presentWorkspaceAccess(component.Access),
		})
	}
	reachedSelectedObject := len(evidence.Components) != 0 && evidence.Components[len(evidence.Components)-1].Path == evidence.Path
	if evidence.Exists && reachedSelectedObject {
		presented.Metadata = &workspacePathMetadata{
			UID:        evidence.UID,
			GID:        evidence.GID,
			Mode:       fmt.Sprintf("%04o", evidence.Mode&0o7777),
			NLink:      evidence.NLink,
			Device:     strconv.FormatUint(evidence.Device, 10),
			Inode:      strconv.FormatUint(evidence.Inode, 10),
			SizeBytes:  evidence.Size,
			ModifiedAt: evidence.ModifiedAt.UTC().Format(time.RFC3339Nano),
			ChangedAt:  evidence.ChangedAt.UTC().Format(time.RFC3339Nano),
		}
	}
	return presented
}

func presentWorkspaceAccess(access workspace.AccessEvidence) workspaceAccessEvidence {
	return workspaceAccessEvidence{Readable: access.Readable, Writable: access.Writable, Searchable: access.Searchable}
}

func presentWorkspacePathType(pathType workspace.PathType) string {
	switch pathType {
	case workspace.PathTypeDirectory:
		return "directory"
	case workspace.PathTypeRegular:
		return "regular_file"
	case workspace.PathTypeSymlink:
		return "symlink"
	case workspace.PathTypeOther:
		return "other"
	case workspace.PathTypeMissing:
		return "missing"
	default:
		return "unknown"
	}
}

func workspacePathStatus(evidence workspace.PathEvidence, diagnostics []workspace.Diagnostic) string {
	if evidence.Safe {
		return "available"
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.Path != evidence.Path {
			continue
		}
		switch diagnostic.Code {
		case workspace.CodePathUnavailable, workspace.CodePathNotReadable, workspace.CodePathNotSearchable:
			return "inaccessible"
		}
	}
	if !evidence.Exists && evidence.Type == workspace.PathTypeMissing {
		return "missing"
	}
	return "unsafe"
}

func presentWorkspaceDiagnostics(values []workspace.Diagnostic) []workspaceDiagnostic {
	presented := make([]workspaceDiagnostic, 0, len(values))
	for _, diagnostic := range values {
		presented = append(presented, workspaceDiagnosticForCode(
			string(diagnostic.Code), string(diagnostic.Severity), string(diagnostic.Role), diagnostic.Path, diagnostic.Component,
		))
	}
	return presented
}

func workspaceDiagnosticForCode(code, severity, role, path, component string) workspaceDiagnostic {
	return workspaceDiagnostic{
		Code:      code,
		Severity:  severity,
		Role:      role,
		Message:   workspaceDiagnosticMessage(code),
		Path:      optionalString(path),
		Component: optionalString(component),
	}
}

func workspaceDiagnosticMessage(code string) string {
	switch code {
	case "path_missing", "configuration_missing":
		return "A required native workspace path does not exist."
	case "path_too_deep":
		return "The native path exceeds the bounded traversal-evidence limit."
	case "path_unavailable", "path_not_readable", "path_not_searchable", "not_readable":
		return "The service identity cannot safely access this native path."
	case "symlink_not_allowed":
		return "Symbolic links are outside the native workspace safety boundary."
	case "component_not_directory", "path_type_unsafe", "not_directory", "not_regular":
		return "A native path has an unexpected filesystem type."
	case "path_owner_untrusted", "untrusted_owner":
		return "A native path is owned by an identity outside the accepted boundary."
	case "path_permissions_unsafe", "unsafe_permissions":
		return "A native path grants permissions outside the accepted boundary."
	case "path_hardlink_unsafe", "hard_link_not_allowed":
		return "A confidential native file has an unsafe link count."
	case "path_read_only":
		return "The service identity can read this path but cannot safely manage it."
	case "configuration_precedence":
		return "Both conventional configuration names exist; .lego.yml takes precedence."
	case "configuration_too_large", "configuration_too_complex":
		return "The native configuration exceeds a bounded inspection limit."
	case "configuration_malformed", "configuration_duplicate_key", "configuration_reference_invalid":
		return "The native configuration cannot be safely resolved for workspace adoption."
	case "changed_during_inspection", "review_evidence_changed", "inventory_artifacts_changed":
		return "Native workspace evidence changed and must be reviewed again."
	case "review_evidence_limit":
		return "The workspace produced more safety findings than the bounded review can display."
	case "inventory_timeout":
		return "The bounded native certificate inventory exceeded its deadline."
	case "inventory_busy":
		return "Another bounded native certificate inventory is already in progress."
	case "inventory_canceled":
		return "The native certificate inventory was canceled."
	case "inventory_output_limit", "tree_entry_limit", "tree_depth_limit", "certificate_limit":
		return "The native certificate inventory exceeded a configured safety limit."
	case "malformed_inventory_output", "duplicate_inventory_entry", "certificate_path_outside_storage":
		return "The upstream certificate inventory did not match the audited native artifacts."
	case "inventory_command_failed":
		return "The trusted lego certificate inventory command did not complete successfully."
	case "artifact_size_invalid":
		return "A native certificate artifact has an invalid bounded size."
	case "neutral_directory_not_private", "neutral_configuration_present":
		return "The private inventory execution directory failed its safety check."
	case "prepared_executable_close_failed":
		return "The retained executable handle could not be released safely."
	case "runtime_unavailable":
		return "The exact reviewed compatible lego runtime is unavailable."
	case "service_busy":
		return "Another bounded native inspection is already in progress."
	default:
		return "The native workspace failed a bounded safety check."
	}
}

func inventoryWorkspaceDiagnostic(err error) workspaceDiagnostic {
	code := inventory.CodeOf(err)
	path := ""
	var typed *inventory.Error
	if errors.As(err, &typed) {
		if validWorkspacePath(typed.Path) {
			path = typed.Path
		}
	}
	if code == "" {
		code = inventory.CodeExecutionFailed
	}
	return workspaceDiagnosticForCode(string(code), "blocking", "inventory", path, "")
}

func runtimeWorkspaceDiagnostic(err error) workspaceDiagnostic {
	code := "runtime_unavailable"
	if workspaceRuntimeBusy(err) {
		code = "service_busy"
	}
	return workspaceDiagnosticForCode(code, "blocking", "runtime", "", "")
}

func changedWorkspaceState(review workspace.Review) string {
	state := "changed"
	for _, diagnostic := range review.Diagnostics {
		if diagnostic.Severity != workspace.SeverityBlocking {
			continue
		}
		switch diagnostic.Code {
		case workspace.CodePathMissing, workspace.CodeConfigurationMissing:
			return "missing"
		case workspace.CodePathReadOnly:
			state = "read_only"
		default:
			if state != "read_only" {
				state = "unsafe"
			}
		}
	}
	return state
}

func presentWorkspaceCertificates(certificates []inventory.Certificate) []workspaceCertificate {
	presented := make([]workspaceCertificate, 0, len(certificates))
	for _, certificate := range certificates {
		presented = append(presented, workspaceCertificate{
			Name:      certificate.Name,
			DNSNames:  append([]string{}, certificate.DNSNames...),
			Issuer:    certificate.Issuer,
			ExpiresAt: certificate.ExpiresAt.UTC().Format(time.RFC3339Nano),
			Artifact: workspaceCertificateArtifact{
				NativePath: certificate.NativePath,
				UID:        certificate.Artifact.UID,
				GID:        certificate.Artifact.GID,
				Mode:       fmt.Sprintf("%04o", certificate.Artifact.Mode&0o7777),
				NLink:      certificate.Artifact.LinkCount,
				Device:     strconv.FormatUint(certificate.Artifact.Device, 10),
				Inode:      strconv.FormatUint(certificate.Artifact.Inode, 10),
				SizeBytes:  certificate.Artifact.Size,
				ModifiedAt: certificate.Artifact.ModifiedAt.UTC().Format(time.RFC3339Nano),
				ChangedAt:  certificate.Artifact.ChangedAt.UTC().Format(time.RFC3339Nano),
			},
		})
	}
	return presented
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func writeWorkspaceJSONError(response http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeAPIError(response, http.StatusRequestEntityTooLarge, "invalid_request", "The request body is too large.")
		return
	}
	writeInvalidWorkspaceRequest(response)
}

func writeInvalidWorkspaceRequest(response http.ResponseWriter) {
	writeAPIError(response, http.StatusBadRequest, "invalid_request", "The workspace request is invalid.")
}

func writeWorkspaceChanged(response http.ResponseWriter) {
	writeAPIError(response, http.StatusConflict, "workspace_changed", "The workspace no longer matches the reviewed evidence.")
}

func writeWorkspaceUnavailable(response http.ResponseWriter) {
	writeAPIError(response, http.StatusServiceUnavailable, "service_unavailable", "Workspace status is unavailable.")
}

func writeWorkspaceRuntimeError(response http.ResponseWriter, err error) {
	if workspaceRuntimeBusy(err) {
		response.Header().Set("Retry-After", "1")
		writeAPIError(response, http.StatusServiceUnavailable, "service_busy", "Native inspection is already in progress.")
		return
	}
	writeWorkspaceUnavailable(response)
}

func workspaceRuntimeBusy(err error) bool {
	if acmeruntime.CodeOf(err) == acmeruntime.CodeInspectionBusy {
		return true
	}
	var replacement *acmeruntime.ReplacementError
	return errors.As(err, &replacement) && replacement.Cause != nil &&
		acmeruntime.CodeOf(replacement.Cause) == acmeruntime.CodeInspectionBusy
}
