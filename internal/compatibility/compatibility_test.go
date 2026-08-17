package compatibility

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	acmeruntime "github.com/acmemux/AcmeMux/internal/runtime"
)

func TestExactManifestsValidateAndAreDefensiveCopies(t *testing.T) {
	manifests := List()
	if len(manifests) != 2 {
		t.Fatalf("List() count = %d, want 2", len(manifests))
	}
	if err := validateManifests(manifests); err != nil {
		t.Fatalf("validateManifests() error = %v", err)
	}
	for _, id := range []ManifestID{ManifestLegoV531, ManifestLegoRevision2A58} {
		manifest, ok := Lookup(id)
		if !ok || manifest.ID != id {
			t.Fatalf("Lookup(%q) = %#v, %v", id, manifest, ok)
		}
		if len(manifest.Platforms) != 1 || manifest.Platforms[0] != (acmeruntime.Platform{OS: "linux", Arch: "amd64"}) {
			t.Fatalf("%s platforms = %#v", id, manifest.Platforms)
		}
	}
	if _, ok := Lookup("unknown"); ok {
		t.Fatal("unknown manifest found")
	}

	manifests[0].Platforms[0].OS = "mutated"
	manifests[0].Runtime.VersionTokens[0] = "mutated"
	manifests[0].Supported.DNSProviderCodes[0] = "mutated"
	manifests[0].Compiled.CertificateAuthorities[0].DirectoryURL = "https://mutated.invalid"
	fresh, _ := Lookup(manifests[0].ID)
	if fresh.Platforms[0].OS == "mutated" || fresh.Runtime.VersionTokens[0] == "mutated" ||
		fresh.Supported.DNSProviderCodes[0] == "mutated" || fresh.Compiled.CertificateAuthorities[0].DirectoryURL == "https://mutated.invalid" {
		t.Fatal("manifest API leaked mutable package state")
	}
}

func TestBundledSchemaAndLicenseHaveExactProvenance(t *testing.T) {
	for _, id := range []ManifestID{ManifestLegoV531, ManifestLegoRevision2A58} {
		manifest, _ := Lookup(id)
		schema, err := Schema(id)
		if err != nil {
			t.Fatalf("Schema(%q) error = %v", id, err)
		}
		if digest(schema) != schemaSHA256 || digest(schema) != manifest.Schema.SHA256 {
			t.Fatalf("Schema(%q) digest = %s", id, digest(schema))
		}
		if got := gitBlobObjectID(schema); got != manifest.Schema.GitBlob {
			t.Fatalf("Schema(%q) Git blob = %s, want %s", id, got, manifest.Schema.GitBlob)
		}
		if !json.Valid(schema) {
			t.Fatalf("Schema(%q) is not valid JSON", id)
		}
		schema[0] ^= 0xff
		fresh, err := Schema(id)
		if err != nil || fresh[0] == schema[0] {
			t.Fatalf("Schema(%q) did not return a defensive copy", id)
		}
	}
	if _, err := Schema("unknown"); err == nil {
		t.Fatal("Schema(unknown) succeeded")
	}

	license := License()
	if digest(license) != licenseSHA256 || !strings.Contains(string(license), "MIT License") ||
		!strings.Contains(string(license), "Copyright (c) 2017-2024 Ludovic Fernandez") {
		t.Fatalf("bundled license provenance/content is invalid: digest %s", digest(license))
	}
	for _, manifest := range List() {
		if got := gitBlobObjectID(license); got != manifest.License.GitBlob {
			t.Fatalf("%s license Git blob = %s, want %s", manifest.ID, got, manifest.License.GitBlob)
		}
	}
	license[0] ^= 0xff
	if fresh := License(); fresh[0] == license[0] {
		t.Fatal("License() did not return a defensive copy")
	}

	original := bundledSchema[0]
	bundledSchema[0] ^= 0xff
	if _, err := Schema(ManifestLegoV531); err == nil {
		t.Fatal("Schema() accepted an asset whose digest drifted")
	}
	bundledSchema[0] = original
}

func TestCompiledAndSupportedCatalogsRemainDistinctAndExact(t *testing.T) {
	wantProviders := []string{"azuredns", "cloudflare", "digitalocean", "duckdns", "route53"}
	wantChallenges := []ChallengeMode{
		{ID: "dns-01", Upstream: "challenge.dns"},
		{ID: "http-01-listener", Upstream: "challenge.http.address"},
		{ID: "http-01-webroot", Upstream: "challenge.http.webroot"},
	}
	wantCAs := map[string]string{
		"godaddy-ca":          "https://acme.godaddy.com/v1/acme/directory",
		"googletrust":         "https://dv.acme-v02.api.pki.goog/directory",
		"googletrust-staging": "https://dv.acme-v02.test-api.pki.goog/directory",
		"letsencrypt":         "https://acme-v02.api.letsencrypt.org/directory",
		"letsencrypt-staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
		"sslcomecc":           "https://acme.ssl.com/sslcom-dv-ecc",
		"sslcomrsa":           "https://acme.ssl.com/sslcom-dv-rsa",
		"zerossl":             "https://acme.zerossl.com/v2/DV90",
	}

	for _, manifest := range List() {
		if !slices.Equal(manifest.Supported.DNSProviderCodes, wantProviders) {
			t.Fatalf("%s supported providers = %v", manifest.ID, manifest.Supported.DNSProviderCodes)
		}
		if !slices.Equal(manifest.Supported.ChallengeModes, wantChallenges) {
			t.Fatalf("%s supported challenges = %#v", manifest.ID, manifest.Supported.ChallengeModes)
		}
		if len(manifest.Supported.CertificateAuthorities) != len(wantCAs) {
			t.Fatalf("%s supported CA count = %d", manifest.ID, len(manifest.Supported.CertificateAuthorities))
		}
		for _, authority := range manifest.Supported.CertificateAuthorities {
			if wantCAs[authority.ID] != authority.DirectoryURL {
				t.Fatalf("%s supported CA %#v is outside PRD scope", manifest.ID, authority)
			}
			if authority.ID == "godaddy-ca" && (authority.Origin != CAOriginFixedCustom || authority.UpstreamCode != "") {
				t.Fatalf("GoDaddy CA must remain a fixed custom endpoint: %#v", authority)
			}
		}
		if len(manifest.Compiled.CertificateAuthorities) != 16 || len(manifest.Compiled.ChallengeModes) != 7 {
			t.Fatalf("%s compiled catalog counts are CA=%d challenge=%d", manifest.ID,
				len(manifest.Compiled.CertificateAuthorities), len(manifest.Compiled.ChallengeModes))
		}
		if !slices.Contains(manifest.Compiled.DNSProviderCodes, "godaddy") || slices.Contains(manifest.Supported.DNSProviderCodes, "godaddy") {
			t.Fatalf("%s confused compiled GoDaddy DNS with supported GoDaddy CA", manifest.ID)
		}
		if slices.Equal(manifest.Compiled.DNSProviderCodes, manifest.Supported.DNSProviderCodes) {
			t.Fatalf("%s compiled and supported catalogs collapsed", manifest.ID)
		}
	}

	release, _ := Lookup(ManifestLegoV531)
	revision, _ := Lookup(ManifestLegoRevision2A58)
	wantRevisionProviders := slices.Clone(release.Compiled.DNSProviderCodes)
	wantRevisionProviders = append(wantRevisionProviders, "nexdns")
	slices.Sort(wantRevisionProviders)
	if !slices.Equal(revision.Compiled.DNSProviderCodes, wantRevisionProviders) {
		t.Fatal("source revision provider drift is not exactly the addition of nexdns")
	}
	if release.Compiled.DNSProviders != (CatalogIdentity{Count: 218, SHA256: "3493fa79904f5e38d8a17ffe6c82f7790a9de2039a631571c7cc7b770d16769f"}) ||
		revision.Compiled.DNSProviders != (CatalogIdentity{Count: 219, SHA256: "c4e2b0f480508d2e6c16df14417672e410dd3d88ce84b466b2d1d60c0cf09edd"}) {
		t.Fatal("compiled provider evidence drifted")
	}
}

func TestClassifyAcceptsOnlyExactCleanBuildEvidence(t *testing.T) {
	for _, manifest := range List() {
		for _, executable := range manifest.Evidence.Executables {
			if !executable.Executed {
				continue
			}
			observation := validObservation(manifest, executable)
			result := Classify(observation)
			if !result.Compatible() || result.ManifestID != manifest.ID || result.Code != CodeCompatible {
				t.Fatalf("Classify(%s, %s/%s, %s) = %#v", manifest.ID, executable.Platform.OS, executable.Platform.Arch, executable.SHA256, result)
			}
		}
	}
}

func TestClassifyRejectsUnknownSparseModifiedAndMismatchedEvidence(t *testing.T) {
	manifest, _ := Lookup(ManifestLegoV531)
	base := validObservation(manifest, manifest.Evidence.Executables[0])
	tests := []struct {
		name string
		code Code
		edit func(*acmeruntime.Observation)
	}{
		{name: "unknown identity", code: CodeUnknownIdentity, edit: func(value *acmeruntime.Observation) {
			value.Version = acmeruntime.VersionIdentity{Kind: acmeruntime.VersionRelease, Value: "v5.3.2"}
		}},
		{name: "invalid fingerprint", code: CodeObservationInvalid, edit: func(value *acmeruntime.Observation) { value.File.SHA256 = "" }},
		{name: "unqualified digest", code: CodeExecutableDigestMismatch, edit: func(value *acmeruntime.Observation) {
			value.File.SHA256 = strings.Repeat("a", 64)
		}},
		{name: "unsupported platform", code: CodeUnsupportedPlatform, edit: func(value *acmeruntime.Observation) {
			value.Platform = acmeruntime.Platform{OS: "linux", Arch: "386"}
		}},
		{name: "decorated output", code: CodeVersionOutputMismatch, edit: func(value *acmeruntime.Observation) {
			value.VersionOutput = "lego version 5.3.1+local linux/amd64"
		}},
		{name: "missing build evidence", code: CodeBuildEvidenceMissing, edit: func(value *acmeruntime.Observation) {
			value.Build = acmeruntime.BuildEvidence{}
		}},
		{name: "sparse build evidence", code: CodeBuildEvidenceIncomplete, edit: func(value *acmeruntime.Observation) {
			value.Build.VCSRevision = ""
		}},
		{name: "incomplete provenance", code: CodeBuildEvidenceIncomplete, edit: func(value *acmeruntime.Observation) {
			value.Build.ProvenanceComplete = false
		}},
		{name: "unparseable modified state", code: CodeBuildEvidenceIncomplete, edit: func(value *acmeruntime.Observation) {
			value.Build.VCSModifiedValid = false
		}},
		{name: "wrong module", code: CodeBuildModuleMismatch, edit: func(value *acmeruntime.Observation) {
			value.Build.MainPath = "example.invalid/lego"
		}},
		{name: "wrong command", code: CodeBuildModuleMismatch, edit: func(value *acmeruntime.Observation) {
			value.Build.CommandPath = "example.invalid/lego"
		}},
		{name: "wrong toolchain", code: CodeBuildToolchainMismatch, edit: func(value *acmeruntime.Observation) {
			value.Build.GoVersion = "go1.99.0"
		}},
		{name: "wrong module version", code: CodeBuildVersionMismatch, edit: func(value *acmeruntime.Observation) {
			value.Build.MainVersion = "v5.3.2"
		}},
		{name: "wrong dependency graph", code: CodeBuildDependencyMismatch, edit: func(value *acmeruntime.Observation) {
			value.Build.DependencyGraphSHA256 = strings.Repeat("0", 64)
		}},
		{name: "wrong build platform", code: CodeBuildPlatformMismatch, edit: func(value *acmeruntime.Observation) {
			value.Build.GOARCH = "arm64"
		}},
		{name: "wrong revision", code: CodeBuildRevisionMismatch, edit: func(value *acmeruntime.Observation) {
			value.Build.VCSRevision = strings.Repeat("0", 40)
		}},
		{name: "modified source", code: CodeBuildModified, edit: func(value *acmeruntime.Observation) {
			value.Build.VCSModified = true
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation := base
			test.edit(&observation)
			result := Classify(observation)
			if result.Code != test.code || result.Compatible() {
				t.Fatalf("Classify() = %#v, want code %q", result, test.code)
			}
			if test.code != CodeUnknownIdentity && result.ManifestID != manifest.ID {
				t.Fatalf("matched failure lost manifest ID: %#v", result)
			}
		})
	}
}

func TestRuntimeEvidenceFixturesMatchManifests(t *testing.T) {
	entries, err := fs.ReadDir(runtimeEvidenceFS, "assets/evidence")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "runtime-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		count++
		data, err := runtimeEvidenceFS.ReadFile("assets/evidence/" + entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		var fixture runtimeEvidenceFixture
		if err := json.Unmarshal(data, &fixture); err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		manifest, ok := Lookup(fixture.ManifestID)
		if !ok {
			t.Fatalf("%s names unknown manifest %q", entry.Name(), fixture.ManifestID)
		}
		version, platform, line, err := acmeruntime.ParseVersionOutput([]byte(fixture.VersionOutput))
		if err != nil || version != manifest.Runtime.Version || line != strings.TrimSuffix(fixture.VersionOutput, "\n") {
			t.Fatalf("%s version fixture mismatch: version=%#v platform=%#v line=%q err=%v", entry.Name(), version, platform, line, err)
		}
		if fixture.CommandPath != manifest.Runtime.CommandPath || fixture.ModulePath != manifest.Runtime.ModulePath ||
			fixture.ModuleVersion != manifest.Runtime.ModuleVersion || fixture.DependencyGraphSHA256 != manifest.Runtime.DependencyGraphSHA256 ||
			fixture.VCSRevision != manifest.Runtime.VCSRevision || fixture.VCSModified || fixture.GOOS != platform.OS || fixture.GOARCH != platform.Arch {
			t.Fatalf("%s build fixture mismatch: %#v", entry.Name(), fixture)
		}
		index := slices.IndexFunc(manifest.Evidence.Executables, func(evidence ExecutableEvidence) bool {
			return evidence.SHA256 == fixture.ExecutableSHA256
		})
		if index < 0 {
			t.Fatalf("%s executable digest is absent from manifest", entry.Name())
		}
		evidence := manifest.Evidence.Executables[index]
		if evidence.Platform != platform || evidence.OfficialBinary != fixture.OfficialBinary || evidence.Executed != fixture.Executed ||
			evidence.ArchiveName != fixture.ArchiveName || evidence.ArchiveSHA256 != fixture.ArchiveSHA256 ||
			evidence.PublishedChecksumsSHA256 != fixture.PublishedChecksumsSHA256 {
			t.Fatalf("%s provenance differs from manifest: fixture=%#v evidence=%#v", entry.Name(), fixture, evidence)
		}
	}
	if count != 4 {
		t.Fatalf("runtime evidence fixture count = %d, want 4", count)
	}
}

func TestConfiguredExecutableFixturesClassify(t *testing.T) {
	tests := []struct {
		name        string
		environment string
		manifest    ManifestID
	}{
		{name: "official release", environment: "ACMEMUX_TEST_OFFICIAL_LEGO", manifest: ManifestLegoV531},
		{name: "source revision", environment: "ACMEMUX_TEST_SOURCE_LEGO", manifest: ManifestLegoRevision2A58},
	}
	configured := false
	for _, test := range tests {
		source := os.Getenv(test.environment)
		if source == "" {
			continue
		}
		configured = true
		t.Run(test.name, func(t *testing.T) {
			path := copyConfiguredExecutable(t, source)
			policy := acmeruntime.DefaultProbePolicy()
			policy.TrustedSHA256 = QualifiedExecutableSHA256s()
			inspector, err := acmeruntime.NewInspector(policy)
			if err != nil {
				t.Fatal(err)
			}
			observation, err := inspector.Inspect(context.Background(), path)
			if err != nil {
				t.Fatalf("Inspect() error = %v", err)
			}
			result := Classify(observation)
			if !result.Compatible() || result.ManifestID != test.manifest {
				t.Fatalf("Classify() = %#v, observation = %#v", result, observation)
			}
		})
	}
	if !configured {
		t.Skip("configured lego fixture paths are not set")
	}
}

func copyConfiguredExecutable(t *testing.T, source string) string {
	t.Helper()
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	path := filepath.Join(t.TempDir(), "lego")
	output, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestManifestValidationFailsOnDuplicateAndEvidenceDrift(t *testing.T) {
	tests := []struct {
		name string
		edit func([]Manifest) []Manifest
	}{
		{name: "duplicate ID", edit: func(values []Manifest) []Manifest { return append(values, cloneManifest(values[0])) }},
		{name: "duplicate runtime identity", edit: func(values []Manifest) []Manifest {
			values[1].Runtime.Version = values[0].Runtime.Version
			return values
		}},
		{name: "schema digest", edit: func(values []Manifest) []Manifest { values[0].Schema.SHA256 = "bad"; return values }},
		{name: "schema Git blob", edit: func(values []Manifest) []Manifest {
			values[0].Schema.GitBlob = strings.Repeat("0", 40)
			return values
		}},
		{name: "license Git blob", edit: func(values []Manifest) []Manifest {
			values[0].License.GitBlob = strings.Repeat("0", 40)
			return values
		}},
		{name: "provider duplicate", edit: func(values []Manifest) []Manifest {
			values[0].Compiled.DNSProviderCodes[1] = values[0].Compiled.DNSProviderCodes[0]
			return values
		}},
		{name: "provider digest", edit: func(values []Manifest) []Manifest {
			values[0].Compiled.DNSProviders.SHA256 = strings.Repeat("0", 64)
			return values
		}},
		{name: "unsupported provider", edit: func(values []Manifest) []Manifest {
			values[0].Supported.DNSProviderCodes = append(values[0].Supported.DNSProviderCodes, "zz-not-compiled")
			return values
		}},
		{name: "CA drift", edit: func(values []Manifest) []Manifest {
			values[0].Compiled.CertificateAuthorities[0].DirectoryURL = "https://changed.invalid/directory"
			return values
		}},
		{name: "challenge drift", edit: func(values []Manifest) []Manifest {
			values[0].Supported.ChallengeModes[0].Upstream = "challenge.changed"
			return values
		}},
		{name: "version fixture", edit: func(values []Manifest) []Manifest {
			values[0].Evidence.Executables[0].VersionOutput = "lego version 5.3.2 linux/amd64"
			return values
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := test.edit(List())
			if err := validateManifests(values); err == nil {
				t.Fatal("validateManifests() accepted drift")
			}
		})
	}
}

type runtimeEvidenceFixture struct {
	ManifestID               ManifestID `json:"manifest_id"`
	FixtureKind              string     `json:"fixture_kind"`
	OfficialBinary           bool       `json:"official_binary"`
	Executed                 bool       `json:"executed"`
	ArchiveName              string     `json:"archive_name"`
	ArchiveSHA256            string     `json:"archive_sha256"`
	PublishedChecksumsSHA256 string     `json:"published_checksums_sha256"`
	ExecutableSHA256         string     `json:"executable_sha256"`
	VersionOutput            string     `json:"version_output"`
	GoVersion                string     `json:"go_version"`
	CommandPath              string     `json:"command_path"`
	ModulePath               string     `json:"module_path"`
	ModuleVersion            string     `json:"module_version"`
	DependencyGraphSHA256    string     `json:"dependency_graph_sha256"`
	GOOS                     string     `json:"goos"`
	GOARCH                   string     `json:"goarch"`
	VCSRevision              string     `json:"vcs_revision"`
	VCSModified              bool       `json:"vcs_modified"`
}

func validObservation(manifest Manifest, executable ExecutableEvidence) acmeruntime.Observation {
	return acmeruntime.Observation{
		File:     acmeruntime.FileIdentity{SHA256: executable.SHA256},
		Version:  manifest.Runtime.Version,
		Platform: executable.Platform,
		Build: acmeruntime.BuildEvidence{
			Available:             true,
			ProvenanceComplete:    true,
			GoVersion:             executable.GoVersion,
			CommandPath:           manifest.Runtime.CommandPath,
			MainPath:              manifest.Runtime.ModulePath,
			MainVersion:           manifest.Runtime.ModuleVersion,
			DependencyGraphSHA256: manifest.Runtime.DependencyGraphSHA256,
			GOOS:                  executable.Platform.OS,
			GOARCH:                executable.Platform.Arch,
			VCSRevision:           manifest.Runtime.VCSRevision,
			VCSModifiedKnown:      true,
			VCSModifiedValid:      true,
			VCSModified:           false,
		},
		VersionOutput: executable.VersionOutput,
	}
}
