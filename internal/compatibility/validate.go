package compatibility

import (
	"crypto/sha1" // Git object IDs for reviewed upstream source use SHA-1.
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	acmeruntime "github.com/acmemux/AcmeMux/internal/runtime"
)

var (
	identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*$`)
	hex40Pattern      = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hex64Pattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func validateManifests(manifests []Manifest) error {
	if len(manifests) == 0 {
		return fmt.Errorf("no manifests")
	}
	ids := make(map[ManifestID]struct{}, len(manifests))
	identities := make(map[acmeruntime.VersionIdentity]struct{}, len(manifests))
	for index := range manifests {
		manifest := &manifests[index]
		if _, duplicate := ids[manifest.ID]; duplicate {
			return fmt.Errorf("duplicate manifest ID %q", manifest.ID)
		}
		ids[manifest.ID] = struct{}{}
		if _, duplicate := identities[manifest.Runtime.Version]; duplicate {
			return fmt.Errorf("duplicate runtime identity %#v", manifest.Runtime.Version)
		}
		identities[manifest.Runtime.Version] = struct{}{}
		if err := validateManifest(*manifest); err != nil {
			return fmt.Errorf("manifest %q: %w", manifest.ID, err)
		}
	}
	if err := validateBundledAssetProvenance(manifests); err != nil {
		return err
	}
	return nil
}

func validateBundledAssetProvenance(manifests []Manifest) error {
	for _, manifest := range manifests {
		for _, asset := range []struct {
			label    string
			identity AssetIdentity
			content  []byte
		}{
			{label: "schema", identity: manifest.Schema, content: bundledSchema},
			{label: "license", identity: manifest.License, content: bundledLicense},
		} {
			if digest(asset.content) != asset.identity.SHA256 {
				return fmt.Errorf("manifest %q: bundled %s SHA-256 mismatch", manifest.ID, asset.label)
			}
			if gitBlobObjectID(asset.content) != asset.identity.GitBlob {
				return fmt.Errorf("manifest %q: bundled %s Git blob mismatch", manifest.ID, asset.label)
			}
		}
	}
	return nil
}

func gitBlobObjectID(content []byte) string {
	hash := sha1.New()
	_, _ = hash.Write([]byte("blob " + strconv.Itoa(len(content))))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(content)
	return hex.EncodeToString(hash.Sum(nil))
}

func validateManifest(manifest Manifest) error {
	if !identifierPattern.MatchString(string(manifest.ID)) {
		return fmt.Errorf("invalid ID")
	}
	if manifest.Source.Repository != upstreamRepository || !hex40Pattern.MatchString(manifest.Source.Commit) {
		return fmt.Errorf("invalid source identity")
	}
	if manifest.Runtime.VCSRevision != manifest.Source.Commit || !manifest.Runtime.RequireClean {
		return fmt.Errorf("runtime must require the clean source commit")
	}
	if manifest.Runtime.CommandPath != upstreamModule || manifest.Runtime.ModulePath != upstreamModule ||
		manifest.Runtime.ModuleVersion == "" || !hex64Pattern.MatchString(manifest.Runtime.DependencyGraphSHA256) {
		return fmt.Errorf("invalid Go module identity")
	}
	if manifest.Runtime.Version.Kind != acmeruntime.VersionRelease && manifest.Runtime.Version.Kind != acmeruntime.VersionRevision {
		return fmt.Errorf("invalid version kind")
	}
	if manifest.Runtime.Version.Value == "" || len(manifest.Runtime.VersionTokens) == 0 {
		return fmt.Errorf("missing exact version identity")
	}
	if err := validateSortedUnique(manifest.Runtime.VersionTokens, false); err != nil {
		return fmt.Errorf("version tokens: %w", err)
	}
	if manifest.Runtime.Version.Kind == acmeruntime.VersionRevision && manifest.Runtime.Version.Value != manifest.Source.Commit {
		return fmt.Errorf("source revision does not equal source commit")
	}
	if manifest.Runtime.Version.Kind == acmeruntime.VersionRelease && manifest.Source.Tag == "" {
		return fmt.Errorf("release manifest has no tag")
	}
	if manifest.Source.TagObject != "" && !hex40Pattern.MatchString(manifest.Source.TagObject) {
		return fmt.Errorf("invalid tag object")
	}
	if err := validatePlatforms(manifest.Platforms); err != nil {
		return err
	}
	if err := validateAsset(manifest.Schema); err != nil {
		return fmt.Errorf("schema: %w", err)
	}
	if err := validateAsset(manifest.License); err != nil {
		return fmt.Errorf("license: %w", err)
	}
	if err := validateCompiledCatalog(manifest.Compiled, manifest.Evidence); err != nil {
		return err
	}
	if err := validateSupportedCatalog(manifest.Compiled, manifest.Supported); err != nil {
		return err
	}
	if err := validateEvidence(manifest); err != nil {
		return err
	}
	return nil
}

func validatePlatforms(platforms []acmeruntime.Platform) error {
	if len(platforms) == 0 {
		return fmt.Errorf("no platforms")
	}
	seen := make(map[acmeruntime.Platform]struct{}, len(platforms))
	previous := ""
	for _, platform := range platforms {
		key := platform.OS + "/" + platform.Arch
		if !platform.Supported() {
			return fmt.Errorf("unsupported manifest platform %q", key)
		}
		if _, exists := seen[platform]; exists || (previous != "" && strings.Compare(previous, key) >= 0) {
			return fmt.Errorf("platforms are duplicate or unsorted")
		}
		seen[platform] = struct{}{}
		previous = key
	}
	return nil
}

func validateAsset(asset AssetIdentity) error {
	if asset.UpstreamPath == "" || !hex40Pattern.MatchString(asset.GitBlob) || !hex64Pattern.MatchString(asset.SHA256) {
		return fmt.Errorf("incomplete provenance")
	}
	return nil
}

func validateCompiledCatalog(catalog CompiledCatalog, evidence Evidence) error {
	if err := validateCAs(catalog.CertificateAuthorities); err != nil {
		return fmt.Errorf("compiled CA catalog: %w", err)
	}
	if canonicalCADigest(catalog.CertificateAuthorities) != evidence.CACatalogSHA256 {
		return fmt.Errorf("compiled CA catalog digest mismatch")
	}
	if err := validateChallenges(catalog.ChallengeModes); err != nil {
		return fmt.Errorf("compiled challenge catalog: %w", err)
	}
	if err := validateSortedUnique(catalog.DNSProviderCodes, true); err != nil {
		return fmt.Errorf("compiled DNS provider catalog: %w", err)
	}
	if catalog.DNSProviders.Count != len(catalog.DNSProviderCodes) || !hex64Pattern.MatchString(catalog.DNSProviders.SHA256) {
		return fmt.Errorf("compiled DNS provider identity mismatch")
	}
	if digest([]byte(strings.Join(catalog.DNSProviderCodes, "\n")+"\n")) != catalog.DNSProviders.SHA256 {
		return fmt.Errorf("compiled DNS provider digest mismatch")
	}
	return nil
}

func validateSupportedCatalog(compiled CompiledCatalog, supported SupportedCatalog) error {
	if err := validateCAs(supported.CertificateAuthorities); err != nil {
		return fmt.Errorf("supported CA catalog: %w", err)
	}
	for _, authority := range supported.CertificateAuthorities {
		if authority.Origin == CAOriginFixedCustom {
			if authority.UpstreamCode != "" {
				return fmt.Errorf("fixed custom CA %q has an upstream code", authority.ID)
			}
			continue
		}
		if !slices.Contains(compiled.CertificateAuthorities, authority) {
			return fmt.Errorf("supported CA %q is not in compiled catalog", authority.ID)
		}
	}
	if err := validateChallenges(supported.ChallengeModes); err != nil {
		return fmt.Errorf("supported challenge catalog: %w", err)
	}
	for _, challenge := range supported.ChallengeModes {
		if !slices.Contains(compiled.ChallengeModes, challenge) {
			return fmt.Errorf("supported challenge %q is not compiled", challenge.ID)
		}
	}
	if err := validateSortedUnique(supported.DNSProviderCodes, true); err != nil {
		return fmt.Errorf("supported DNS provider catalog: %w", err)
	}
	for _, provider := range supported.DNSProviderCodes {
		if !slices.Contains(compiled.DNSProviderCodes, provider) {
			return fmt.Errorf("supported DNS provider %q is not compiled", provider)
		}
	}
	return nil
}

func validateEvidence(manifest Manifest) error {
	for label, value := range map[string]string{
		"provider catalog bundle": manifest.Evidence.ProviderCatalogBundleSHA256,
		"CA catalog":              manifest.Evidence.CACatalogSHA256,
		"CA source bundle":        manifest.Evidence.CASourceBundleSHA256,
		"challenge bundle":        manifest.Evidence.ChallengeBundleSHA256,
	} {
		if !hex64Pattern.MatchString(value) {
			return fmt.Errorf("invalid %s digest", label)
		}
	}
	if len(manifest.Evidence.SupportedProviders) != len(manifest.Supported.DNSProviderCodes) {
		return fmt.Errorf("supported provider evidence count mismatch")
	}
	for index, provider := range manifest.Evidence.SupportedProviders {
		if provider.Code != manifest.Supported.DNSProviderCodes[index] || !hex40Pattern.MatchString(provider.DirectoryTree) ||
			!hex64Pattern.MatchString(provider.DirectorySHA256) || !hex64Pattern.MatchString(provider.DescriptorSHA256) {
			return fmt.Errorf("invalid supported provider evidence for %q", provider.Code)
		}
	}
	if len(manifest.Evidence.Executables) == 0 {
		return fmt.Errorf("no executable evidence fixture")
	}
	seenExecutables := make(map[string]struct{}, len(manifest.Evidence.Executables))
	for _, executable := range manifest.Evidence.Executables {
		if !executable.Platform.Supported() || !hex64Pattern.MatchString(executable.SHA256) ||
			(executable.Executed && !slices.Contains(manifest.Platforms, executable.Platform)) {
			return fmt.Errorf("invalid executable evidence platform or digest")
		}
		key := executable.Platform.OS + "/" + executable.Platform.Arch + "/" + executable.SHA256
		if _, duplicate := seenExecutables[key]; duplicate {
			return fmt.Errorf("duplicate executable evidence")
		}
		seenExecutables[key] = struct{}{}
		version, platform, line, err := acmeruntime.ParseVersionOutput([]byte(executable.VersionOutput + "\n"))
		if err != nil || version != manifest.Runtime.Version || platform != executable.Platform || line != executable.VersionOutput {
			return fmt.Errorf("executable version fixture mismatch")
		}
		if executable.GoVersion == "" || executable.ModuleVersion != manifest.Runtime.ModuleVersion ||
			executable.VCSRevision != manifest.Runtime.VCSRevision || executable.VCSModified {
			return fmt.Errorf("executable build fixture mismatch")
		}
		if executable.OfficialBinary {
			if executable.ArchiveName == "" || !hex64Pattern.MatchString(executable.ArchiveSHA256) ||
				!hex64Pattern.MatchString(executable.PublishedChecksumsSHA256) {
				return fmt.Errorf("official executable provenance is incomplete")
			}
		} else if executable.ArchiveName != "" || executable.ArchiveSHA256 != "" || executable.PublishedChecksumsSHA256 != "" {
			return fmt.Errorf("local source fixture claims release archive provenance")
		}
	}
	return nil
}

func validateCAs(authorities []CertificateAuthority) error {
	if len(authorities) == 0 {
		return fmt.Errorf("empty catalog")
	}
	previous := ""
	for _, authority := range authorities {
		if !identifierPattern.MatchString(authority.ID) || (previous != "" && strings.Compare(previous, authority.ID) >= 0) {
			return fmt.Errorf("identifiers are invalid, duplicate, or unsorted")
		}
		parsed, err := url.Parse(authority.DirectoryURL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return fmt.Errorf("invalid directory URL for %q", authority.ID)
		}
		if authority.Environment != "production" && authority.Environment != "staging" {
			return fmt.Errorf("invalid environment for %q", authority.ID)
		}
		if authority.Origin != CAOriginBuiltIn && authority.Origin != CAOriginFixedCustom {
			return fmt.Errorf("invalid origin for %q", authority.ID)
		}
		if authority.Origin == CAOriginBuiltIn && authority.UpstreamCode != authority.ID {
			return fmt.Errorf("built-in code mismatch for %q", authority.ID)
		}
		previous = authority.ID
	}
	return nil
}

func validateChallenges(challenges []ChallengeMode) error {
	if len(challenges) == 0 {
		return fmt.Errorf("empty catalog")
	}
	previous := ""
	for _, challenge := range challenges {
		if !identifierPattern.MatchString(challenge.ID) || challenge.Upstream == "" ||
			(previous != "" && strings.Compare(previous, challenge.ID) >= 0) {
			return fmt.Errorf("entries are invalid, duplicate, or unsorted")
		}
		previous = challenge.ID
	}
	return nil
}

func validateSortedUnique(values []string, requireIdentifier bool) error {
	if len(values) == 0 {
		return fmt.Errorf("empty catalog")
	}
	previous := ""
	for _, value := range values {
		if value == "" || (requireIdentifier && !identifierPattern.MatchString(value)) ||
			(previous != "" && strings.Compare(previous, value) >= 0) {
			return fmt.Errorf("entries are invalid, duplicate, or unsorted")
		}
		previous = value
	}
	return nil
}

func canonicalCADigest(authorities []CertificateAuthority) string {
	var builder strings.Builder
	for _, authority := range authorities {
		builder.WriteString(authority.ID)
		builder.WriteByte('\t')
		builder.WriteString(authority.DirectoryURL)
		builder.WriteByte('\t')
		builder.WriteString(authority.Environment)
		builder.WriteByte('\n')
	}
	return digest([]byte(builder.String()))
}
