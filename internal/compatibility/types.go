package compatibility

import (
	"fmt"

	acmeruntime "github.com/acmemux/AcmeMux/internal/runtime"
)

// ManifestID is the stable identifier of an exact compatibility manifest.
type ManifestID string

const (
	// ManifestLegoV531 identifies upstream lego's official v5.3.1 source tag.
	ManifestLegoV531 ManifestID = "lego-v5.3.1"
	// ManifestLegoRevision2A58 identifies the reviewed post-v5.3.1 source revision.
	ManifestLegoRevision2A58 ManifestID = "lego-revision-2a58c3522708"
)

// AssetIdentity records immutable upstream provenance for a bundled asset.
type AssetIdentity struct {
	UpstreamPath string
	GitBlob      string
	SHA256       string
}

// SourceIdentity records the exact upstream source represented by a manifest.
type SourceIdentity struct {
	Repository string
	Tag        string
	TagObject  string
	Commit     string
}

// RuntimeIdentity is the exact executable identity admitted by a manifest.
// VersionTokens contains the explicitly reviewed tokens that may appear in
// `lego --version`; it never represents a range.
type RuntimeIdentity struct {
	Version               acmeruntime.VersionIdentity
	VersionTokens         []string
	CommandPath           string
	ModulePath            string
	ModuleVersion         string
	DependencyGraphSHA256 string
	VCSRevision           string
	RequireClean          bool
}

// CertificateAuthority identifies one upstream built-in or AcmeMux-curated
// fixed ACME directory. An empty UpstreamCode means lego has no built-in code.
type CertificateAuthority struct {
	ID           string
	UpstreamCode string
	DirectoryURL string
	Environment  string
	Origin       string
}

const (
	CAOriginBuiltIn     = "upstream_built_in"
	CAOriginFixedCustom = "acmemux_fixed_custom"
)

// ChallengeMode is a stable native configuration mode.
type ChallengeMode struct {
	ID       string
	Upstream string
}

// CatalogIdentity binds a deterministic newline-delimited catalog to a
// count and SHA-256 digest.
type CatalogIdentity struct {
	Count  int
	SHA256 string
}

// CompiledCatalog describes capabilities present in the exact upstream
// source. Presence here does not make a capability supported by AcmeMux.
type CompiledCatalog struct {
	CertificateAuthorities []CertificateAuthority
	ChallengeModes         []ChallengeMode
	DNSProviderCodes       []string
	DNSProviders           CatalogIdentity
}

// SupportedCatalog is the deliberately smaller AcmeMux product allowlist.
type SupportedCatalog struct {
	CertificateAuthorities []CertificateAuthority
	ChallengeModes         []ChallengeMode
	DNSProviderCodes       []string
}

// ProviderEvidence binds the complete reviewed upstream directory, generated
// provider documentation, and descriptor for one supported DNS provider.
type ProviderEvidence struct {
	Code             string
	DirectoryTree    string
	DirectorySHA256  string
	DescriptorSHA256 string
}

// ExecutableEvidence records an independently qualified exact artifact. Only
// entries with Executed true are admitted for runtime probing and selection;
// another build from the same source remains unsupported until qualified.
type ExecutableEvidence struct {
	Platform                 acmeruntime.Platform
	SHA256                   string
	VersionOutput            string
	GoVersion                string
	ModuleVersion            string
	VCSRevision              string
	VCSModified              bool
	OfficialBinary           bool
	Executed                 bool
	ArchiveName              string
	ArchiveSHA256            string
	PublishedChecksumsSHA256 string
}

// Evidence describes independent source structures reviewed for drift.
type Evidence struct {
	ProviderCatalogBundleSHA256 string
	CACatalogSHA256             string
	CASourceBundleSHA256        string
	ChallengeBundleSHA256       string
	SupportedProviders          []ProviderEvidence
	Executables                 []ExecutableEvidence
}

// Manifest is a complete exact-version compatibility decision.
type Manifest struct {
	ID        ManifestID
	Source    SourceIdentity
	Runtime   RuntimeIdentity
	Platforms []acmeruntime.Platform
	Schema    AssetIdentity
	License   AssetIdentity
	Compiled  CompiledCatalog
	Supported SupportedCatalog
	Evidence  Evidence
}

// Code is a stable, non-secret compatibility decision.
type Code string

const (
	CodeCompatible               Code = "compatible"
	CodeUnknownIdentity          Code = "unknown_identity"
	CodeUnsupportedPlatform      Code = "unsupported_platform"
	CodeExecutableDigestMismatch Code = "executable_digest_mismatch"
	CodeVersionOutputMismatch    Code = "version_output_mismatch"
	CodeBuildEvidenceMissing     Code = "build_evidence_missing"
	CodeBuildEvidenceIncomplete  Code = "build_evidence_incomplete"
	CodeBuildModuleMismatch      Code = "build_module_mismatch"
	CodeBuildVersionMismatch     Code = "build_version_mismatch"
	CodeBuildToolchainMismatch   Code = "build_toolchain_mismatch"
	CodeBuildDependencyMismatch  Code = "build_dependency_mismatch"
	CodeBuildPlatformMismatch    Code = "build_platform_mismatch"
	CodeBuildRevisionMismatch    Code = "build_revision_mismatch"
	CodeBuildModified            Code = "build_modified"
	CodeObservationInvalid       Code = "observation_invalid"
)

// Result is the fail-closed outcome of Classify.
type Result struct {
	Code       Code
	ManifestID ManifestID
	Detail     string
}

// Compatible reports whether the exact observation is admitted.
func (r Result) Compatible() bool { return r.Code == CodeCompatible }

// Error is returned when an embedded compatibility asset cannot be supplied.
type Error struct {
	ManifestID ManifestID
	Detail     string
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.ManifestID == "" {
		return "compatibility asset: " + e.Detail
	}
	return fmt.Sprintf("compatibility asset %s: %s", e.ManifestID, e.Detail)
}
