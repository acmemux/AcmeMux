package compatibility

import (
	"io/fs"
	"slices"
	"sort"
	"strings"
	"testing"

	acmeruntime "github.com/acmemux/AcmeMux/internal/runtime"
)

type qualifiedExecutableFixture struct {
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

func TestQualifiedExecutableListIsExactlyBackedByEmbeddedFixtures(t *testing.T) {
	entries, err := fs.ReadDir(runtimeEvidenceFS, "assets/evidence")
	if err != nil {
		t.Fatal(err)
	}
	wantFixtureCount := 0
	for _, manifest := range List() {
		wantFixtureCount += len(manifest.Evidence.Executables)
	}
	if len(entries) != wantFixtureCount {
		t.Fatalf("runtime evidence files = %d, want %d", len(entries), wantFixtureCount)
	}

	seen := make(map[string]string, len(entries))
	qualified := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "runtime-") || !strings.HasSuffix(entry.Name(), ".json") {
			t.Fatalf("unexpected embedded runtime evidence entry %q", entry.Name())
		}
		fixture := readStrictJSON[qualifiedExecutableFixture](t, runtimeEvidenceFS, "assets/evidence/"+entry.Name())
		manifest, ok := Lookup(fixture.ManifestID)
		if !ok {
			t.Fatalf("%s names unknown manifest %q", entry.Name(), fixture.ManifestID)
		}
		if fixture.OfficialBinary != (fixture.FixtureKind == "official_github_release") ||
			(!fixture.OfficialBinary && fixture.FixtureKind != "local_source_build") {
			t.Fatalf("%s has inconsistent fixture kind %q", entry.Name(), fixture.FixtureKind)
		}
		if !strings.HasSuffix(fixture.VersionOutput, "\n") || strings.Count(fixture.VersionOutput, "\n") != 1 {
			t.Fatalf("%s version output is not one canonical line", entry.Name())
		}
		version, platform, line, err := acmeruntime.ParseVersionOutput([]byte(fixture.VersionOutput))
		if err != nil || version != manifest.Runtime.Version || platform != (acmeruntime.Platform{OS: fixture.GOOS, Arch: fixture.GOARCH}) {
			t.Fatalf("%s runtime identity mismatch: version=%#v platform=%#v err=%v", entry.Name(), version, platform, err)
		}
		if fixture.CommandPath != manifest.Runtime.CommandPath || fixture.ModulePath != manifest.Runtime.ModulePath ||
			fixture.ModuleVersion != manifest.Runtime.ModuleVersion || fixture.DependencyGraphSHA256 != manifest.Runtime.DependencyGraphSHA256 ||
			fixture.VCSRevision != manifest.Runtime.VCSRevision || fixture.VCSModified {
			t.Fatalf("%s Go build identity differs from manifest", entry.Name())
		}

		key := string(fixture.ManifestID) + "/" + fixture.ExecutableSHA256
		if previous, duplicate := seen[key]; duplicate {
			t.Fatalf("%s duplicates executable fixture %s from %s", entry.Name(), key, previous)
		}
		seen[key] = entry.Name()
		index := slices.IndexFunc(manifest.Evidence.Executables, func(evidence ExecutableEvidence) bool {
			return evidence.SHA256 == fixture.ExecutableSHA256
		})
		if index < 0 {
			t.Fatalf("%s executable digest is absent from manifest", entry.Name())
		}
		want := ExecutableEvidence{
			Platform:                 platform,
			SHA256:                   fixture.ExecutableSHA256,
			VersionOutput:            line,
			GoVersion:                fixture.GoVersion,
			ModuleVersion:            fixture.ModuleVersion,
			VCSRevision:              fixture.VCSRevision,
			VCSModified:              fixture.VCSModified,
			OfficialBinary:           fixture.OfficialBinary,
			Executed:                 fixture.Executed,
			ArchiveName:              fixture.ArchiveName,
			ArchiveSHA256:            fixture.ArchiveSHA256,
			PublishedChecksumsSHA256: fixture.PublishedChecksumsSHA256,
		}
		if manifest.Evidence.Executables[index] != want {
			t.Fatalf("%s fixture differs from manifest: fixture=%#v manifest=%#v", entry.Name(), want, manifest.Evidence.Executables[index])
		}
		if fixture.Executed {
			qualified = append(qualified, fixture.ExecutableSHA256)
		}
	}

	for _, manifest := range List() {
		for _, executable := range manifest.Evidence.Executables {
			key := string(manifest.ID) + "/" + executable.SHA256
			if _, ok := seen[key]; !ok {
				t.Fatalf("manifest executable %s has no embedded evidence fixture", key)
			}
		}
	}
	sort.Strings(qualified)
	qualified = slices.Compact(qualified)
	if got := QualifiedExecutableSHA256s(); !slices.Equal(got, qualified) {
		t.Fatalf("QualifiedExecutableSHA256s() = %v, want fixture-backed %v", got, qualified)
	}
}
