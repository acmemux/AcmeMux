package workspace

import (
	"context"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Inspector discovers native path references and records Linux filesystem
// evidence without retaining confidential file contents.
type Inspector struct {
	policy Policy
}

// NewInspector validates and retains an explicit inspection policy.
func NewInspector(policy Policy) (*Inspector, error) {
	if policy.EffectiveUID == 0 {
		return nil, &Error{Code: CodeInvalidPolicy, Detail: "service identity must be non-root"}
	}
	if len(policy.EffectiveGIDs) == 0 {
		return nil, &Error{Code: CodeInvalidPolicy, Detail: "service groups are required"}
	}
	if policy.MaxConfigurationBytes <= 0 || policy.MaxConfigurationBytes > maximumConfigurationBytes {
		return nil, &Error{Code: CodeInvalidPolicy, Detail: "configuration size limit is invalid"}
	}
	if policy.MaxReferencedPaths <= 0 || policy.MaxReferencedPaths > maximumReferencedPaths {
		return nil, &Error{Code: CodeInvalidPolicy, Detail: "referenced path limit is invalid"}
	}
	policy.EffectiveGIDs = append([]uint32(nil), policy.EffectiveGIDs...)
	sort.Slice(policy.EffectiveGIDs, func(left, right int) bool { return policy.EffectiveGIDs[left] < policy.EffectiveGIDs[right] })
	policy.EffectiveGIDs = compactGIDs(policy.EffectiveGIDs)
	rootUID, err := filesystemRootUID()
	if err != nil {
		return nil, &Error{Code: CodeInvalidPolicy, Detail: "filesystem root identity could not be inspected", Cause: err}
	}
	if policy.EffectiveUID == rootUID {
		return nil, &Error{Code: CodeInvalidPolicy, Detail: "service identity must differ from the filesystem-root owner"}
	}
	policy.trustedRootUID = rootUID
	return &Inspector{policy: policy}, nil
}

// Inspect returns complete partial evidence for a syntactically valid
// request. Missing, read-only, and unsafe paths are diagnostics in the Review
// so an administrator can understand the candidate before adoption.
func (inspector *Inspector) Inspect(ctx context.Context, request Request) (Review, error) {
	if inspector == nil {
		return Review{}, &Error{Code: CodeInvalidPolicy, Detail: "inspector is not initialized"}
	}
	if ctx == nil {
		return Review{}, &Error{Code: CodeContextRequired}
	}
	if err := validateSelectedPath(request.WorkingDirectory); err != nil {
		return Review{}, err
	}
	if request.ConfigurationPath != "" {
		if err := validateSelectedPath(request.ConfigurationPath); err != nil {
			return Review{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return Review{}, &Error{Code: CodeInspectionCanceled, Cause: err}
	}

	review := Review{ObservedAt: time.Now().UTC()}
	workingRequirements := pathRequirements{
		expected: PathTypeDirectory, requireRead: true, requireSearch: true,
	}
	working := auditPath(ctx, request.WorkingDirectory, RoleWorkingDirectory, "", workingRequirements, inspector.policy)
	review.WorkingDirectory = inspector.confirmPath(ctx, working, workingRequirements, &review.Diagnostics)
	appendReviewDiagnostics(&review.Diagnostics, working.diagnostics...)

	configurationRequirements := pathRequirements{
		expected: PathTypeRegular, confidential: true, requireRead: true,
		requireParentSwap: true, readHandle: true,
	}
	configuration := auditedPath{}
	if request.ConfigurationPath != "" {
		review.ConfigurationSource = ConfigurationExplicit
		configuration = auditPath(ctx, request.ConfigurationPath, RoleConfiguration, "", configurationRequirements, inspector.policy)
	} else {
		configuration = inspector.discoverConventional(ctx, request.WorkingDirectory, configurationRequirements, &review)
	}
	if configuration.file != nil {
		defer configuration.file.Close()
	}
	review.Configuration = configuration.evidence
	appendReviewDiagnostics(&review.Diagnostics, configuration.diagnostics...)

	references, parseDiagnostics := readNativeReferences(ctx, configuration.file, configuration.evidence, request.WorkingDirectory, inspector.policy)
	appendReviewDiagnostics(&review.Diagnostics, parseDiagnostics...)
	if hasBlockingDiagnostics(parseDiagnostics) {
		review.Configuration.Safe = false
	}
	if configuration.evidence.Path != "" && configuration.evidence.Exists {
		confirmed := inspector.confirmPath(ctx, configuration, configurationRequirements, &review.Diagnostics)
		if !confirmed.Safe {
			review.Configuration.Safe = false
		}
	}

	if references.storage.resolved != "" {
		storageRequirements := pathRequirements{
			expected: PathTypeDirectory, requireRead: true, requireWrite: true, requireSearch: true,
		}
		storage := auditPath(ctx, references.storage.resolved, RoleStorage, references.storage.raw, storageRequirements, inspector.policy)
		review.Storage = inspector.confirmPath(ctx, storage, storageRequirements, &review.Diagnostics)
		appendReviewDiagnostics(&review.Diagnostics, storage.diagnostics...)
	}

	dotenvRequirements := pathRequirements{
		expected: PathTypeRegular, confidential: true, requireRead: true, requireParentSwap: true,
	}
	for _, reference := range references.dotenv {
		audited := auditPath(ctx, reference.resolved, RoleDotenv, reference.raw, dotenvRequirements, inspector.policy)
		review.DotenvFiles = append(review.DotenvFiles, inspector.confirmPath(ctx, audited, dotenvRequirements, &review.Diagnostics))
		appendReviewDiagnostics(&review.Diagnostics, audited.diagnostics...)
	}
	webrootRequirements := pathRequirements{
		expected: PathTypeDirectory, requireWrite: true, requireSearch: true,
	}
	for _, reference := range references.webroots {
		audited := auditPath(ctx, reference.resolved, RoleWebroot, reference.raw, webrootRequirements, inspector.policy)
		review.Webroots = append(review.Webroots, inspector.confirmPath(ctx, audited, webrootRequirements, &review.Diagnostics))
		appendReviewDiagnostics(&review.Diagnostics, audited.diagnostics...)
	}

	// Re-open the complete set once more after parsing and discovery. This
	// closes the otherwise material window where an earlier directory could be
	// replaced while later references were being audited.
	inspector.finalConfirmation(ctx, &review.WorkingDirectory, workingRequirements, &review.Diagnostics)
	inspector.finalConfirmation(ctx, &review.Configuration, configurationRequirements, &review.Diagnostics)
	if review.Storage.Path != "" {
		storageRequirements := pathRequirements{
			expected: PathTypeDirectory, requireRead: true, requireWrite: true, requireSearch: true,
		}
		inspector.finalConfirmation(ctx, &review.Storage, storageRequirements, &review.Diagnostics)
	}
	for index := range review.DotenvFiles {
		inspector.finalConfirmation(ctx, &review.DotenvFiles[index], dotenvRequirements, &review.Diagnostics)
	}
	for index := range review.Webroots {
		inspector.finalConfirmation(ctx, &review.Webroots[index], webrootRequirements, &review.Diagnostics)
	}

	review.Adoptable = review.WorkingDirectory.Safe && review.Configuration.Safe && review.Storage.Safe &&
		allSafe(review.DotenvFiles) && allSafe(review.Webroots) && !hasBlockingDiagnostics(review.Diagnostics)
	review.ReviewedEvidenceSHA256 = ReviewFingerprint(review)
	return review, nil
}

func (inspector *Inspector) finalConfirmation(ctx context.Context, evidence *PathEvidence, requirements pathRequirements, diagnostics *[]Diagnostic) {
	if evidence == nil || evidence.Path == "" || !evidence.Exists {
		return
	}
	confirmed := inspector.confirmPath(ctx, auditedPath{evidence: *evidence}, requirements, diagnostics)
	if !confirmed.Safe {
		evidence.Safe = false
	}
}

// Verify repeats inspection with the original discovery semantics and rejects
// any evidence change. Conventional reviews therefore notice a newly created
// higher-priority .lego.yml as well as replacement of an existing path.
func (inspector *Inspector) Verify(ctx context.Context, reviewed Review) (Review, error) {
	if reviewed.WorkingDirectory.Path == "" || reviewed.Configuration.Path == "" {
		return Review{}, &Error{Code: CodeReviewEvidenceChanged, Detail: "review evidence is incomplete"}
	}
	request := Request{WorkingDirectory: reviewed.WorkingDirectory.Path}
	switch reviewed.ConfigurationSource {
	case ConfigurationExplicit:
		request.ConfigurationPath = reviewed.Configuration.Path
	case ConfigurationConventionalYML, ConfigurationConventionalYAML:
		// Preserve upstream current-working-directory discovery.
	default:
		return Review{}, &Error{Code: CodeReviewEvidenceChanged, Detail: "configuration source is invalid"}
	}
	current, err := inspector.Inspect(ctx, request)
	if err != nil {
		return Review{}, err
	}
	if reviewed.ReviewedEvidenceSHA256 == ReviewFingerprint(reviewed) &&
		current.ReviewedEvidenceSHA256 == reviewed.ReviewedEvidenceSHA256 {
		return current, nil
	}
	return current, &VerificationError{Reviewed: reviewed, Current: current, Changes: reviewChanges(reviewed, current)}
}

func (inspector *Inspector) discoverConventional(ctx context.Context, workingDirectory string, requirements pathRequirements, review *Review) auditedPath {
	ymlPath := filepath.Join(workingDirectory, ".lego.yml")
	yamlPath := filepath.Join(workingDirectory, ".lego.yaml")
	yml := auditPath(ctx, ymlPath, RoleConfiguration, "", requirements, inspector.policy)
	if !conventionalPathAbsent(yml.evidence) {
		review.ConfigurationSource = ConfigurationConventionalYML
		probeRequirements := requirements
		probeRequirements.readHandle = false
		yaml := auditPath(ctx, yamlPath, RoleConfiguration, "", probeRequirements, inspector.policy)
		if yaml.evidence.Exists && yaml.evidence.Type != PathTypeDirectory {
			appendReviewDiagnostics(&review.Diagnostics, notice(CodeConfigurationPrecedence, RoleConfiguration, ymlPath, yamlPath,
				"both conventional names exist; .lego.yml takes precedence"))
		}
		return yml
	}
	if yml.file != nil {
		_ = yml.file.Close()
	}
	yaml := auditPath(ctx, yamlPath, RoleConfiguration, "", requirements, inspector.policy)
	if !conventionalPathAbsent(yaml.evidence) {
		review.ConfigurationSource = ConfigurationConventionalYAML
		return yaml
	}
	if yaml.file != nil {
		_ = yaml.file.Close()
	}
	review.ConfigurationSource = ConfigurationConventionalYML
	missing := yml
	if missing.evidence.Exists && missing.evidence.Type == PathTypeDirectory {
		missing.diagnostics = append(missing.diagnostics, diagnostic(CodeConfigurationMissing, RoleConfiguration, ymlPath, workingDirectory,
			"neither .lego.yml nor .lego.yaml is a configuration file"))
		return missing
	}
	missing.diagnostics = []Diagnostic{diagnostic(CodeConfigurationMissing, RoleConfiguration, ymlPath, workingDirectory,
		"neither .lego.yml nor .lego.yaml exists")}
	return missing
}

func conventionalPathAbsent(evidence PathEvidence) bool {
	return evidence.Type == PathTypeMissing || evidence.Exists && evidence.Type == PathTypeDirectory
}

func (inspector *Inspector) confirmPath(ctx context.Context, initial auditedPath, requirements pathRequirements, diagnostics *[]Diagnostic) PathEvidence {
	evidence := initial.evidence
	if evidence.Path == "" || !evidence.Exists {
		return evidence
	}
	confirmationRequirements := requirements
	confirmationRequirements.readHandle = false
	confirmation := auditPath(ctx, evidence.Path, evidence.Role, evidence.Reference, confirmationRequirements, inspector.policy)
	if confirmation.file != nil {
		_ = confirmation.file.Close()
	}
	if !samePathEvidence(evidence, confirmation.evidence) {
		evidence.Safe = false
		appendReviewDiagnostics(diagnostics, diagnostic(CodeChangedDuringInspection, evidence.Role, evidence.Path, evidence.Path,
			"path identity changed during inspection"))
	}
	return evidence
}

func samePathEvidence(left, right PathEvidence) bool {
	left.Safe = false
	right.Safe = false
	// Directory entry churn changes size, mtime, and ctime without changing
	// the selected directory's security identity. Operations create and remove
	// private staging files in reviewed directories, so these volatile fields
	// are live display evidence rather than stable review identity.
	if left.Type == PathTypeDirectory {
		left.Size = 0
		left.ModifiedAt = time.Time{}
		left.ChangedAt = time.Time{}
	}
	if right.Type == PathTypeDirectory {
		right.Size = 0
		right.ModifiedAt = time.Time{}
		right.ChangedAt = time.Time{}
	}
	// Directory link counts change when an unrelated sibling directory is
	// created or removed. They are audited live but are not stable identity
	// evidence. Final selected-object NLink remains compared and fingerprinted.
	left.Components = append([]ComponentEvidence(nil), left.Components...)
	right.Components = append([]ComponentEvidence(nil), right.Components...)
	for index := range left.Components {
		left.Components[index].NLink = 0
	}
	for index := range right.Components {
		right.Components[index].NLink = 0
	}
	return reflect.DeepEqual(left, right)
}

func allSafe(paths []PathEvidence) bool {
	for _, path := range paths {
		if !path.Safe {
			return false
		}
	}
	return true
}

func appendReviewDiagnostics(target *[]Diagnostic, values ...Diagnostic) {
	if len(values) == 0 || target == nil {
		return
	}
	if len(*target) != 0 && (*target)[len(*target)-1].Code == CodeReviewEvidenceLimit {
		return
	}
	remaining := maximumReviewDiagnostics - len(*target)
	if remaining <= 0 {
		(*target)[maximumReviewDiagnostics-1] = reviewEvidenceLimitDiagnostic()
		return
	}
	if len(values) <= remaining {
		*target = append(*target, values...)
		return
	}
	if remaining > 1 {
		*target = append(*target, values[:remaining-1]...)
	}
	*target = append(*target, reviewEvidenceLimitDiagnostic())
}

func reviewEvidenceLimitDiagnostic() Diagnostic {
	return diagnostic(CodeReviewEvidenceLimit, RoleWorkspace, "", "", "workspace diagnostics exceed the bounded review limit")
}

func validateSelectedPath(path string) error {
	if path == "" {
		return &Error{Code: CodePathRequired}
	}
	if len(path) > maximumPathBytes {
		return &Error{Code: CodePathTooLong, Path: path}
	}
	if !utf8.ValidString(path) || strings.IndexFunc(path, invalidPathRune) >= 0 {
		return &Error{Code: CodePathNotCanonical, Detail: "path contains invalid text"}
	}
	if !filepath.IsAbs(path) {
		return &Error{Code: CodePathNotAbsolute, Path: path}
	}
	if filepath.Clean(path) != path {
		return &Error{Code: CodePathNotCanonical, Path: path}
	}
	return nil
}

func invalidPathRune(character rune) bool {
	return character < 0x20 || character == 0x7f
}

func compactGIDs(values []uint32) []uint32 {
	if len(values) == 0 {
		return nil
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

func reviewChanges(reviewed, current Review) []string {
	var changes []string
	if reviewed.ReviewedEvidenceSHA256 != ReviewFingerprint(reviewed) {
		changes = append(changes, "review_fingerprint")
	}
	if reviewed.ConfigurationSource != current.ConfigurationSource {
		changes = append(changes, "configuration_source")
	}
	if !samePathEvidence(reviewed.WorkingDirectory, current.WorkingDirectory) {
		changes = append(changes, "working_directory")
	}
	if !samePathEvidence(reviewed.Configuration, current.Configuration) {
		changes = append(changes, "configuration")
	}
	if !samePathEvidence(reviewed.Storage, current.Storage) {
		changes = append(changes, "storage")
	}
	if !samePathEvidenceSlice(reviewed.DotenvFiles, current.DotenvFiles) {
		changes = append(changes, "dotenv_files")
	}
	if !samePathEvidenceSlice(reviewed.Webroots, current.Webroots) {
		changes = append(changes, "webroots")
	}
	if !reflect.DeepEqual(reviewed.Diagnostics, current.Diagnostics) {
		changes = append(changes, "diagnostics")
	}
	if reviewed.Adoptable != current.Adoptable {
		changes = append(changes, "adoptable")
	}
	if len(changes) == 0 {
		changes = append(changes, "review_fingerprint")
	}
	return changes
}

func samePathEvidenceSlice(left, right []PathEvidence) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !samePathEvidence(left[index], right[index]) {
			return false
		}
	}
	return true
}
