package configuration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"

	"github.com/sgurden-certleap/AcmeMux/internal/compatibility"
	"github.com/sgurden-certleap/AcmeMux/internal/integrations"
	"github.com/sgurden-certleap/AcmeMux/internal/nativeconfig"
	"github.com/sgurden-certleap/AcmeMux/internal/workspace"
)

const maximumExecutionCertificates = 64

// ExecutionCertificate is the complete non-secret certificate intent shown
// before a whole-workspace native operation. Native map identities remain
// authoritative and no filesystem artifact or credential value is included.
type ExecutionCertificate struct {
	Name          string
	Domains       []string
	Account       string
	CA            string
	ChallengeName string
	ChallengeKind string
	ChallengeMode string
}

// ExecutionIntent is safe to present and bind into an operation review token.
type ExecutionIntent struct {
	WorkingDirectory  string
	ConfigurationPath string
	StoragePath       string
	RuntimeIdentity   string
	RuntimeManifestID compatibility.ManifestID
	Certificates      []ExecutionCertificate
	CloudAccess       []ExecutionCloudAccess
}

// ExecutionCloudAccess explains the exact ambient capability selected for a
// cloud DNS challenge without exposing a credential value.
type ExecutionCloudAccess struct {
	ChallengeName string
	Provider      string
	AuthMode      string
	Files         []string
	Helper        string
	Metadata      string
}

type ExecutionEnvironment struct {
	Name      string
	Value     []byte
	Sensitive bool
}

// ExecutionPlan is an operation-scoped native execution snapshot. Revision is
// an opaque keyed token over runtime, workspace, source content, and metadata.
// ObservedSecrets are owned by the plan and exist only to seed redaction.
type ExecutionPlan struct {
	Intent                 ExecutionIntent
	Revision               string
	ReviewedEvidenceSHA256 string
	ObservedSecrets        [][]byte
	Environment            []ExecutionEnvironment
	cloudEvidence          []workspace.PathEvidence
	closed                 bool
}

// Close clears every confidential buffer retained for operation redaction.
func (plan *ExecutionPlan) Close() {
	if plan == nil || plan.closed {
		return
	}
	for index := range plan.ObservedSecrets {
		clear(plan.ObservedSecrets[index])
		plan.ObservedSecrets[index] = nil
	}
	plan.ObservedSecrets = nil
	for index := range plan.Environment {
		clear(plan.Environment[index].Value)
		plan.Environment[index].Value = nil
	}
	plan.Environment = nil
	plan.cloudEvidence = nil
	for index := range plan.Intent.Certificates {
		clear(plan.Intent.Certificates[index].Domains)
		plan.Intent.Certificates[index].Domains = nil
	}
	plan.closed = true
}

// PrepareExecution validates the exact runtime and complete native sources
// under an already-held shared workspace lease. It never acquires a second
// lease, writes native state, prepares an executable, or launches a process.
func (service *Service) PrepareExecution(ctx context.Context, lease *workspace.Lease) (*ExecutionPlan, error) {
	if service == nil || lease == nil {
		return nil, ErrInvalid
	}
	evaluated, err := service.evaluateLocked(ctx, lease)
	if err != nil {
		return nil, err
	}
	defer evaluated.close()
	if evaluated.view.State != StateReady || !evaluated.view.Execution {
		return nil, ErrInvalid
	}
	intent, err := executionIntent(evaluated)
	if err != nil {
		return nil, err
	}
	cloudAccess, environment, cloudSecrets, cloudEvidence, err := service.prepareCloudAccess(ctx, evaluated, intent)
	if err != nil {
		return nil, err
	}
	intent.CloudAccess = cloudAccess
	secrets, err := evaluated.runtime.engine.ObservedSecrets(evaluated.sources.Configuration.Content)
	if err != nil {
		return nil, fmt.Errorf("%w: inspect native operation secrets", ErrUnavailable)
	}
	complete := false
	defer func() {
		if complete {
			return
		}
		for index := range secrets {
			clear(secrets[index])
		}
	}()
	for _, managed := range evaluated.documents.byPath {
		if managed == nil || managed.document == nil {
			continue
		}
		for _, route := range managed.routes {
			if !route.Secret() {
				continue
			}
			value, present := managed.document.ValueCopy(route.EnvironmentKey())
			if !present || len(value) == 0 {
				clear(value)
				continue
			}
			duplicate := false
			for _, existing := range secrets {
				if bytes.Equal(existing, value) {
					duplicate = true
					break
				}
			}
			if duplicate {
				clear(value)
				continue
			}
			secrets = append(secrets, value)
		}
	}
	for _, value := range cloudSecrets {
		duplicate := false
		for _, existing := range secrets {
			if bytes.Equal(existing, value) {
				duplicate = true
				break
			}
		}
		if duplicate {
			clear(value)
		} else {
			secrets = append(secrets, value)
		}
	}
	plan := &ExecutionPlan{
		Intent: intent, Revision: evaluated.view.Source.BaseRevisionToken,
		ReviewedEvidenceSHA256: executionEvidenceDigest(evaluated, intent, cloudEvidence),
		ObservedSecrets:        secrets,
		Environment:            environment,
		cloudEvidence:          cloudEvidence,
	}
	complete = true
	return plan, nil
}

// executionEvidenceDigest is stable across service restarts and contains only
// non-confidential runtime, workspace, source-placement, and reviewed-intent
// evidence. Source content digests are intentionally excluded: Linux inode,
// size, mtime, and ctime evidence binds intervening content changes without
// persisting a credential-guessing oracle.
func executionEvidenceDigest(evaluated *evaluation, intent ExecutionIntent, cloudEvidence []workspace.PathEvidence) string {
	digest := sha256.New()
	writer := &tokenWriter{mac: digest}
	writer.text("acmemux-manual-operation-evidence-v2")
	writer.text(string(evaluated.runtime.manifestID))
	writer.text(evaluated.runtime.fingerprint)
	writer.text(workspace.ExecutionReviewFingerprint(evaluated.sources.Selection.Review))
	files := evaluated.sources.Files()
	writer.integer(uint64(len(files)))
	for _, file := range files {
		writer.text(string(file.Role))
		writer.text(file.Path)
		writer.text(file.Reference)
		identity := file.Fingerprint.Identity
		writer.boolean(identity.Exists)
		writer.integer(identity.Device)
		writer.integer(identity.Inode)
		writer.integer(uint64(identity.Mode))
		writer.integer(uint64(identity.UID))
		writer.integer(uint64(identity.GID))
		writer.integer(identity.NLink)
		writer.integer(uint64(identity.Size))
		writer.text(canonicalTime(identity.ModifiedAt))
		writer.text(canonicalTime(identity.ChangedAt))
	}
	writer.text(intent.WorkingDirectory)
	writer.text(intent.ConfigurationPath)
	writer.text(intent.StoragePath)
	writer.text(intent.RuntimeIdentity)
	writer.text(string(intent.RuntimeManifestID))
	writer.integer(uint64(len(intent.Certificates)))
	for _, certificate := range intent.Certificates {
		writer.text(certificate.Name)
		writer.integer(uint64(len(certificate.Domains)))
		for _, domain := range certificate.Domains {
			writer.text(domain)
		}
		writer.text(certificate.Account)
		writer.text(certificate.CA)
		writer.text(certificate.ChallengeName)
		writer.text(certificate.ChallengeKind)
		writer.text(certificate.ChallengeMode)
	}
	writer.integer(uint64(len(intent.CloudAccess)))
	for _, access := range intent.CloudAccess {
		writer.text(access.ChallengeName)
		writer.text(access.Provider)
		writer.text(access.AuthMode)
		writer.integer(uint64(len(access.Files)))
		for _, path := range access.Files {
			writer.text(path)
		}
		writer.text(access.Helper)
		writer.text(access.Metadata)
	}
	writer.integer(uint64(len(cloudEvidence)))
	for _, evidence := range cloudEvidence {
		writer.text(string(evidence.Role))
		writer.text(evidence.Path)
		writer.boolean(evidence.Exists)
		writer.integer(evidence.Device)
		writer.integer(evidence.Inode)
		writer.integer(uint64(evidence.Mode))
		writer.integer(uint64(evidence.UID))
		writer.integer(uint64(evidence.GID))
		writer.integer(evidence.NLink)
		writer.integer(uint64(evidence.Size))
		writer.text(canonicalTime(evidence.ModifiedAt))
		writer.text(canonicalTime(evidence.ChangedAt))
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func executionIntent(evaluated *evaluation) (ExecutionIntent, error) {
	if evaluated == nil || evaluated.sources == nil {
		return ExecutionIntent{}, ErrInvalid
	}
	values := make(map[string]integrations.Value)
	present := make(map[string]bool)
	for _, field := range evaluated.view.Inspection.Projection {
		key := executionProjectionKey(field.FieldID, field.Bindings)
		present[key] = field.Present && field.Configured
		if value, ok := field.Value(); ok {
			values[key] = value
		}
	}
	accounts := make(map[string]string)
	certificateNames := bindingValues(evaluated.view.Inspection.Projection, integrations.BindingCertificate)
	if len(certificateNames) == 0 || len(certificateNames) > maximumExecutionCertificates {
		return ExecutionIntent{}, fmt.Errorf("%w: native operation certificate scope", ErrInvalid)
	}
	for _, account := range bindingValues(evaluated.view.Inspection.Projection, integrations.BindingAccount) {
		server, ok := projectedString(values, integrations.FieldAccountServer, nativeconfig.Binding{
			ID: integrations.BindingAccount, Value: account,
		})
		if ok {
			accounts[account] = server
		}
	}
	certificates := make([]ExecutionCertificate, 0, len(certificateNames))
	for _, name := range certificateNames {
		binding := nativeconfig.Binding{ID: integrations.BindingCertificate, Value: name}
		domains, domainsOK := projectedStrings(values, integrations.FieldCertificateDomains, binding)
		account, accountOK := projectedString(values, integrations.FieldCertificateAccount, binding)
		challenge, challengeOK := projectedString(values, integrations.FieldCertificateChallenge, binding)
		server, serverOK := accounts[account]
		if !domainsOK || len(domains) == 0 || !accountOK || !challengeOK || !serverOK {
			return ExecutionIntent{}, fmt.Errorf("%w: incomplete native operation certificate scope", ErrInvalid)
		}
		challengeBinding := nativeconfig.Binding{ID: integrations.BindingChallenge, Value: challenge}
		kind := "http-01"
		mode := "listener"
		if provider, ok := projectedString(values, integrations.FieldChallengeDNSProvider, challengeBinding); ok {
			kind = "dns-01"
			mode = provider
		} else if present[executionProjectionKey(integrations.FieldChallengeHTTPWebroot, []nativeconfig.Binding{challengeBinding})] {
			mode = "webroot"
		}
		certificates = append(certificates, ExecutionCertificate{
			Name: name, Domains: domains, Account: account, CA: server,
			ChallengeName: challenge, ChallengeKind: kind, ChallengeMode: mode,
		})
	}
	return ExecutionIntent{
		WorkingDirectory:  evaluated.sources.Selection.Review.WorkingDirectory.Path,
		ConfigurationPath: evaluated.sources.Configuration.Path,
		StoragePath:       evaluated.sources.Selection.Review.Storage.Path,
		RuntimeIdentity:   evaluated.runtime.observation.Version.Value,
		RuntimeManifestID: evaluated.runtime.manifestID,
		Certificates:      certificates,
	}, nil
}

func bindingValues(fields []nativeconfig.ProjectedField, id integrations.BindingID) []string {
	seen := make(map[string]struct{})
	for _, field := range fields {
		for _, binding := range field.Bindings {
			if binding.ID == id && binding.Value != "" {
				seen[binding.Value] = struct{}{}
			}
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func projectedString(values map[string]integrations.Value, fieldID integrations.FieldID, bindings ...nativeconfig.Binding) (string, bool) {
	value, ok := values[executionProjectionKey(fieldID, bindings)]
	if !ok {
		return "", false
	}
	return value.String()
}

func projectedStrings(values map[string]integrations.Value, fieldID integrations.FieldID, bindings ...nativeconfig.Binding) ([]string, bool) {
	value, ok := values[executionProjectionKey(fieldID, bindings)]
	if !ok {
		return nil, false
	}
	return value.StringList()
}

func executionProjectionKey(fieldID integrations.FieldID, bindings []nativeconfig.Binding) string {
	ordered := slices.Clone(bindings)
	sort.Slice(ordered, func(left, right int) bool {
		if ordered[left].ID != ordered[right].ID {
			return ordered[left].ID < ordered[right].ID
		}
		return ordered[left].Value < ordered[right].Value
	})
	key := string(fieldID)
	for _, binding := range ordered {
		key += "\x00" + string(binding.ID) + "=" + binding.Value
	}
	return key
}
