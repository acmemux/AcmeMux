//go:build linux

package runtime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/acmemux/AcmeMux/internal/state"
)

const sourceRevision = "2a58c3522708e4c7393a67be691bd0c3a16d8441"

var (
	probeFixtureV531 string
	probeFixtureV532 string
)

func TestMain(m *testing.M) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		fmt.Fprintln(os.Stderr, "locate runtime probe test source")
		os.Exit(1)
	}
	directory, err := os.MkdirTemp("", "acmemux-runtime-probe-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	probeFixtureV531 = filepath.Join(directory, "probe-v5.3.1")
	probeFixtureV532 = filepath.Join(directory, "probe-v5.3.2")
	for version, output := range map[string]string{"5.3.1": probeFixtureV531, "5.3.2": probeFixtureV532} {
		command := exec.Command("go", "build", "-buildvcs=false", "-trimpath", "-ldflags", "-X main.forcedVersion="+version, "-o", output, ".")
		command.Dir = filepath.Join(filepath.Dir(sourceFile), "testdata", "probe")
		command.Env = append(os.Environ(), "GOWORK=off")
		if result, buildErr := command.CombinedOutput(); buildErr != nil {
			fmt.Fprintf(os.Stderr, "build runtime probe fixture: %v\n%s", buildErr, result)
			os.Exit(1)
		}
	}
	result := m.Run()
	_ = os.RemoveAll(directory)
	os.Exit(result)
}

func TestInspectRunsOnlyBoundedVersionProbeWithControlledEnvironment(t *testing.T) {
	t.Setenv("ACMEMUX_RUNTIME_PROBE_LEAK", "must-not-be-inherited")
	path := copyProbeFixture(t, "release", probeFixtureV531)

	inspector := newTestInspector(t, 2*time.Second, 4096, "linux", runtime.GOARCH)
	observation, err := inspector.Inspect(context.Background(), path)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if observation.Version != (VersionIdentity{Kind: VersionRelease, Value: "v5.3.1"}) {
		t.Fatalf("version = %#v", observation.Version)
	}
	if observation.Platform != (Platform{OS: "linux", Arch: runtime.GOARCH}) {
		t.Fatalf("platform = %#v", observation.Platform)
	}
	if !observation.Build.Available || observation.Build.MainPath != "github.com/go-acme/lego/v5" {
		t.Fatalf("Go fixture build evidence = %#v", observation.Build)
	}
	if observation.VersionOutput != "lego version 5.3.1 linux/"+runtime.GOARCH || observation.ObservedAt.IsZero() {
		t.Fatalf("observation = %#v", observation)
	}
}

func TestInspectRejectsUntrustedBuildBeforeRunningCandidate(t *testing.T) {
	directory := t.TempDir()
	path := copyProbeFixtureIn(t, directory, "slow-release", probeFixtureV531)
	policy := DefaultProbePolicy()
	policy.Audit = CurrentAuditPolicy()
	policy.TrustedSHA256 = []string{strings.Repeat("0", 64)}
	inspector, err := NewInspector(policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inspector.Inspect(context.Background(), path); CodeOf(err) != CodeExecutableNotQualified {
		t.Fatalf("CodeOf(error) = %q, error = %v", CodeOf(err), err)
	}
	if _, err := os.Stat(filepath.Join(directory, "started")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("candidate executed before build provenance rejection: %v", err)
	}
}

func TestInspectorWaitForCapacityIsBounded(t *testing.T) {
	policy := DefaultProbePolicy()
	policy.RequireTrustedBuild = false
	policy.InspectionTimeout = 20 * time.Millisecond
	inspector, err := NewInspector(policy)
	if err != nil {
		t.Fatal(err)
	}
	inspector.gate <- struct{}{}
	defer func() { <-inspector.gate }()
	_, err = inspector.Inspect(context.Background(), copyProbeFixture(t, "release", probeFixtureV531))
	if CodeOf(err) != CodeInspectionBusy {
		t.Fatalf("CodeOf(error) = %q, error = %v", CodeOf(err), err)
	}
}

func TestInspectAcceptsExactSourceRevision(t *testing.T) {
	t.Parallel()
	path := copyProbeFixture(t, "revision", probeFixtureV531)
	inspector := newTestInspector(t, 2*time.Second, 4096, "linux", runtime.GOARCH)
	observation, err := inspector.Inspect(context.Background(), path)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if observation.Version != (VersionIdentity{Kind: VersionRevision, Value: sourceRevision}) {
		t.Fatalf("version = %#v", observation.Version)
	}
}

func TestInspectRejectsProbeFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		mode        string
		timeout     time.Duration
		outputLimit int
		code        ErrorCode
	}{
		{name: "stderr", mode: "stderr", timeout: time.Second, outputLimit: 4096, code: CodeProbeFailed},
		{name: "nonzero", mode: "nonzero", timeout: time.Second, outputLimit: 4096, code: CodeProbeFailed},
		{name: "malformed", mode: "malformed", timeout: time.Second, outputLimit: 4096, code: CodeMalformedVersion},
		{name: "stdout oversized", mode: "stdout-oversized", timeout: time.Second, outputLimit: 64, code: CodeProbeOutputLimit},
		{name: "stderr oversized", mode: "stderr-oversized", timeout: time.Second, outputLimit: 64, code: CodeProbeOutputLimit},
		{name: "timeout", mode: "timeout", timeout: 250 * time.Millisecond, outputLimit: 4096, code: CodeProbeTimeout},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := copyProbeFixture(t, test.mode, probeFixtureV531)
			inspector := newTestInspector(t, test.timeout, test.outputLimit, "linux", runtime.GOARCH)
			_, err := inspector.Inspect(context.Background(), path)
			if CodeOf(err) != test.code {
				t.Fatalf("CodeOf(error) = %q, want %q; error = %v", CodeOf(err), test.code, err)
			}
		})
	}
}

func TestInspectHonorsCallerCancellation(t *testing.T) {
	t.Parallel()
	path := copyProbeFixture(t, "timeout", probeFixtureV531)
	inspector := newTestInspector(t, time.Second, 4096, "linux", runtime.GOARCH)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := inspector.Inspect(ctx, path)
	if CodeOf(err) != CodeInspectionCanceled {
		t.Fatalf("CodeOf(error) = %q, error = %v", CodeOf(err), err)
	}
}

func TestInspectReportsOverallInspectionDeadlineBeforeProbeDeadline(t *testing.T) {
	t.Parallel()
	path := copyProbeFixture(t, "timeout", probeFixtureV531)
	inspector, err := NewInspector(ProbePolicy{
		Audit:               CurrentAuditPolicy(),
		Timeout:             time.Second,
		InspectionTimeout:   30 * time.Millisecond,
		OutputLimit:         4096,
		HostOS:              "linux",
		HostArch:            runtime.GOARCH,
		RequireTrustedBuild: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inspector.Inspect(context.Background(), path); CodeOf(err) != CodeInspectionTimeout {
		t.Fatalf("CodeOf(error) = %q, error = %v", CodeOf(err), err)
	}
}

func TestInspectEnforcesNativePlatformPolicy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		mode string
		code ErrorCode
	}{
		{name: "unsupported", mode: "darwin", code: CodeUnsupportedPlatform},
		{name: "host mismatch", mode: "other-arch", code: CodePlatformMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := copyProbeFixture(t, test.mode, probeFixtureV531)
			inspector := newTestInspector(t, time.Second, 4096, "linux", runtime.GOARCH)
			_, err := inspector.Inspect(context.Background(), path)
			if CodeOf(err) != test.code {
				t.Fatalf("CodeOf(error) = %q, want %q; error = %v", CodeOf(err), test.code, err)
			}
		})
	}
}

func TestInspectDetectsPathReplacementDuringProbe(t *testing.T) {
	directory := t.TempDir()
	marker := filepath.Join(directory, "started")
	path := copyProbeFixtureIn(t, directory, "slow-release", probeFixtureV531)
	inspector := newTestInspector(t, time.Second, 4096, "linux", runtime.GOARCH)

	result := make(chan error, 1)
	go func() {
		_, err := inspector.Inspect(context.Background(), path)
		result <- err
	}()
	waitForFile(t, marker)
	replacement := copyProbeFixtureIn(t, directory, "replacement", probeFixtureV531)
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if err := <-result; CodeOf(err) != CodeChangedDuringInspection {
		t.Fatalf("CodeOf(error) = %q, error = %v", CodeOf(err), err)
	}
}

func TestVerifyDetectsContentAndInodeReplacement(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := copyProbeFixtureIn(t, directory, "release", probeFixtureV531)
	inspector := newTestInspector(t, time.Second, 4096, "linux", runtime.GOARCH)
	reviewed, err := inspector.Inspect(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inspector.Verify(context.Background(), reviewed); err != nil {
		t.Fatalf("unchanged Verify() error = %v", err)
	}

	if err := replaceProbeFixture(path, probeFixtureV532); err != nil {
		t.Fatal(err)
	}
	current, err := inspector.Verify(context.Background(), reviewed)
	var replacement *ReplacementError
	if !errors.As(err, &replacement) || CodeOf(err) != CodeReplacement {
		t.Fatalf("Verify() error = %v", err)
	}
	if !slices.Contains(replacement.Changes, "sha256") || !slices.Contains(replacement.Changes, "version") {
		t.Fatalf("changes = %v", replacement.Changes)
	}

	reviewed = current
	replacementPath := copyProbeFixtureIn(t, directory, "new-release", probeFixtureV532)
	if err := os.Rename(replacementPath, path); err != nil {
		t.Fatal(err)
	}
	_, err = inspector.Verify(context.Background(), reviewed)
	if !errors.As(err, &replacement) || !slices.Contains(replacement.Changes, "inode") {
		t.Fatalf("inode replacement error = %v; changes = %v", err, replacement.Changes)
	}
}

func TestVerifyClassifiesAnUninspectableReplacement(t *testing.T) {
	t.Parallel()
	path := copyProbeFixture(t, "release", probeFixtureV531)
	inspector := newTestInspector(t, time.Second, 4096, "linux", runtime.GOARCH)
	reviewed, err := inspector.Inspect(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o722); err != nil {
		t.Fatal(err)
	}
	_, err = inspector.Verify(context.Background(), reviewed)
	var replacement *ReplacementError
	if CodeOf(err) != CodeReplacement || !errors.As(err, &replacement) {
		t.Fatalf("Verify() error = %v", err)
	}
	var runtimeError *Error
	if !errors.As(err, &runtimeError) || runtimeError.Code != CodeUnsafePermissions {
		t.Fatalf("underlying error = %v", err)
	}
}

func TestPreparedExecutableRunsRetainedFileAfterPathRename(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := copyProbeFixtureIn(t, directory, "retained", probeFixtureV531)
	inspector := newTestInspector(t, time.Second, 4096, "linux", runtime.GOARCH)
	reviewed, err := inspector.Inspect(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := inspector.prepareSelection(context.Background(), Selection{
		Observation: reviewed,
		ManifestID:  "test-manifest",
	}, func(Observation) (string, bool) { return "test-manifest", true })
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()

	replacement := copyProbeFixtureIn(t, directory, "replacement-lego", probeFixtureV532)
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	command, err := prepared.StartContext(context.Background(), func(command *exec.Cmd) error {
		command.Path = "/bin/false"
		command.Args = []string{"/bin/false"}
		command.ExtraFiles = nil
		command.Dir = "/"
		command.Env = slices.Clone(controlledProbeEnvironment)
		command.Stdout = &stdout
		return nil
	}, "managed-operation")
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("retained command error = %v", err)
	}
	if stdout.String() != "retained:managed-operation\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := prepared.StartContext(context.Background(), func(*exec.Cmd) error { return nil }, "managed-operation"); CodeOf(err) != CodePreparedClosed {
		t.Fatalf("closed command error = %v", err)
	}
}

func TestPrepareSelectionBlocksWithdrawnOrDifferentManifest(t *testing.T) {
	t.Parallel()
	path := copyProbeFixture(t, "release", probeFixtureV531)
	inspector := newTestInspector(t, time.Second, 4096, "linux", runtime.GOARCH)
	reviewed, err := inspector.Inspect(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	selection := Selection{Observation: reviewed, ManifestID: "reviewed-manifest"}
	for _, classify := range []SelectionClassifier{
		func(Observation) (string, bool) { return "reviewed-manifest", false },
		func(Observation) (string, bool) { return "different-manifest", true },
	} {
		if _, err := inspector.prepareSelection(context.Background(), selection, classify); CodeOf(err) != CodeCompatibilityChanged {
			t.Fatalf("PrepareSelection() error = %v", err)
		}
	}
	if _, err := inspector.PrepareCurrent(context.Background(), nil, func(Observation) (string, bool) { return "", false }); CodeOf(err) != CodeInvalidPolicy {
		t.Fatalf("nil selection store error = %v", err)
	}
}

func TestPrepareCurrentLoadsOnlyThePersistedSelection(t *testing.T) {
	t.Parallel()
	database, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := NewSelectionStore(database)
	if err != nil {
		t.Fatal(err)
	}
	selection := selectionFixture()
	selection.Observation.File.CanonicalPath = filepath.Join(t.TempDir(), "missing-lego")
	if err := store.Save(context.Background(), selection); err != nil {
		t.Fatal(err)
	}
	inspector := newTestInspector(t, time.Second, 4096, "linux", runtime.GOARCH)
	_, err = inspector.PrepareCurrent(context.Background(), store, func(Observation) (string, bool) {
		return selection.ManifestID, true
	})
	var replacement *ReplacementError
	if !errors.As(err, &replacement) || replacement.Path != selection.Observation.File.CanonicalPath {
		t.Fatalf("PrepareCurrent() error = %v", err)
	}
}

func TestBuildEvidenceValidation(t *testing.T) {
	t.Parallel()
	revision := VersionIdentity{Kind: VersionRevision, Value: sourceRevision}
	platform := Platform{OS: "linux", Arch: "amd64"}
	valid := BuildEvidence{
		Available:             true,
		ProvenanceComplete:    true,
		GoVersion:             "go1.26.6",
		CommandPath:           "github.com/go-acme/lego/v5",
		MainPath:              "github.com/go-acme/lego/v5",
		MainVersion:           "v5.3.2-0.20260803101616-2a58c3522708",
		DependencyGraphSHA256: strings.Repeat("a", 64),
		GOOS:                  "linux",
		GOARCH:                "amd64",
		VCSRevision:           sourceRevision,
		VCSModifiedKnown:      true,
		VCSModifiedValid:      true,
	}
	if err := validateBuildEvidence(valid, revision, platform, "/lego"); err != nil {
		t.Fatalf("valid evidence error = %v", err)
	}
	if err := validateBuildEvidence(BuildEvidence{}, revision, platform, "/lego"); CodeOf(err) != CodeBuildIdentityMismatch {
		t.Fatalf("unavailable evidence error = %v", err)
	}

	tests := []BuildEvidence{
		func() BuildEvidence { value := valid; value.MainPath = "example.invalid/not-lego"; return value }(),
		func() BuildEvidence { value := valid; value.GOOS = "darwin"; return value }(),
		func() BuildEvidence { value := valid; value.GOARCH = "arm64"; return value }(),
		func() BuildEvidence { value := valid; value.VCSRevision = strings.Repeat("0", 40); return value }(),
		func() BuildEvidence { value := valid; value.VCSRevision = "not-a-revision"; return value }(),
		func() BuildEvidence { value := valid; value.VCSModifiedValid = false; return value }(),
		func() BuildEvidence { value := valid; value.MainVersion = "bad\nversion"; return value }(),
	}
	for _, evidence := range tests {
		if err := validateBuildEvidence(evidence, revision, platform, "/lego"); CodeOf(err) != CodeBuildIdentityMismatch {
			t.Fatalf("evidence %#v error = %v", evidence, err)
		}
	}
}

func TestReadBuildEvidenceFromGoTestBinary(t *testing.T) {
	t.Parallel()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	evidence, err := readBuildEvidence(context.Background(), file, path)
	if err != nil {
		t.Fatal(err)
	}
	if !evidence.Available || evidence.GoVersion == "" || evidence.MainPath == "" {
		t.Fatalf("build evidence = %#v", evidence)
	}
	if err := validateBuildEvidence(evidence, VersionIdentity{Kind: VersionRelease, Value: "v5.3.1"}, Platform{OS: runtime.GOOS, Arch: runtime.GOARCH}, path); CodeOf(err) != CodeBuildIdentityMismatch {
		t.Fatalf("non-lego test binary must be rejected, error = %v", err)
	}
}

func TestInspectConfiguredSourceBackedLego(t *testing.T) {
	source := os.Getenv("ACMEMUX_TEST_SOURCE_LEGO")
	if source == "" {
		t.Skip("ACMEMUX_TEST_SOURCE_LEGO is not set")
	}
	path := copyProbeFixture(t, "lego", source)
	inspector := newProductionInspector(t)
	observation, err := inspector.Inspect(context.Background(), path)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if observation.Version != (VersionIdentity{Kind: VersionRevision, Value: sourceRevision}) {
		t.Fatalf("version = %#v", observation.Version)
	}
	if !observation.Build.Available || observation.Build.MainPath != "github.com/go-acme/lego/v5" || observation.Build.VCSRevision != sourceRevision || !observation.Build.VCSModifiedKnown || !observation.Build.VCSModifiedValid || observation.Build.VCSModified {
		t.Fatalf("build evidence = %#v", observation.Build)
	}
	t.Logf("source revision dependency graph sha256 = %s", observation.Build.DependencyGraphSHA256)
}

func TestInspectConfiguredOfficialLego(t *testing.T) {
	source := os.Getenv("ACMEMUX_TEST_OFFICIAL_LEGO")
	if source == "" {
		t.Skip("ACMEMUX_TEST_OFFICIAL_LEGO is not set")
	}
	path := copyProbeFixture(t, "official-lego", source)
	inspector := newProductionInspector(t)
	observation, err := inspector.Inspect(context.Background(), path)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if observation.Version != (VersionIdentity{Kind: VersionRelease, Value: "v5.3.1"}) ||
		observation.VersionOutput != "lego version 5.3.1 linux/"+runtime.GOARCH {
		t.Fatalf("version evidence = %#v, output = %q", observation.Version, observation.VersionOutput)
	}
	if !observation.Build.Available || observation.Build.MainPath != "github.com/go-acme/lego/v5" ||
		observation.Build.MainVersion != "v5.3.1" ||
		observation.Build.VCSRevision != "589c84af4f26629fbdaa7fbca712f806632ccb7e" ||
		!observation.Build.VCSModifiedKnown || !observation.Build.VCSModifiedValid || observation.Build.VCSModified {
		t.Fatalf("build evidence = %#v", observation.Build)
	}
	t.Logf("official v5.3.1 dependency graph sha256 = %s", observation.Build.DependencyGraphSHA256)
}

func TestInspectConfiguredV531SourceLego(t *testing.T) {
	source := os.Getenv("ACMEMUX_TEST_V531_SOURCE_LEGO")
	if source == "" {
		t.Skip("ACMEMUX_TEST_V531_SOURCE_LEGO is not set")
	}
	path := copyProbeFixture(t, "source-lego", source)
	observation, err := newProductionInspector(t).Inspect(context.Background(), path)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if observation.Version != (VersionIdentity{Kind: VersionRelease, Value: "v5.3.1"}) ||
		observation.VersionOutput != "lego version v5.3.1 linux/"+runtime.GOARCH ||
		observation.Build.MainVersion != "v5.3.1" ||
		observation.Build.VCSRevision != "589c84af4f26629fbdaa7fbca712f806632ccb7e" {
		t.Fatalf("observation = %#v", observation)
	}
	t.Logf("source v5.3.1 dependency graph sha256 = %s", observation.Build.DependencyGraphSHA256)
}

func TestNewInspectorRejectsUnsafePolicyBounds(t *testing.T) {
	t.Parallel()
	base := DefaultProbePolicy()
	base.TrustedSHA256 = []string{strings.Repeat("0", 64)}
	tests := []ProbePolicy{
		func() ProbePolicy { value := base; value.Timeout = 0; return value }(),
		func() ProbePolicy { value := base; value.Timeout = maximumProbeTimeout + time.Nanosecond; return value }(),
		func() ProbePolicy { value := base; value.InspectionTimeout = 0; return value }(),
		func() ProbePolicy {
			value := base
			value.InspectionTimeout = maximumInspectionTimeout + time.Nanosecond
			return value
		}(),
		func() ProbePolicy { value := base; value.OutputLimit = 0; return value }(),
		func() ProbePolicy { value := base; value.OutputLimit = 64<<10 + 1; return value }(),
		func() ProbePolicy { value := base; value.HostOS = ""; return value }(),
		func() ProbePolicy { value := base; value.HostArch = ""; return value }(),
		func() ProbePolicy { value := base; value.TrustedSHA256 = nil; return value }(),
		func() ProbePolicy { value := base; value.TrustedSHA256 = []string{"not-a-digest"}; return value }(),
		func() ProbePolicy {
			value := base
			value.TrustedSHA256 = []string{strings.Repeat("A", 64)}
			return value
		}(),
		func() ProbePolicy {
			value := base
			value.TrustedSHA256 = []string{strings.Repeat("0", 64), strings.Repeat("0", 64)}
			return value
		}(),
	}
	for _, policy := range tests {
		if _, err := NewInspector(policy); CodeOf(err) != CodeInvalidPolicy {
			t.Fatalf("policy %#v error = %v", policy, err)
		}
	}
}

func newTestInspector(t *testing.T, timeout time.Duration, outputLimit int, hostOS, hostArch string) *Inspector {
	t.Helper()
	inspector, err := NewInspector(ProbePolicy{
		Audit:               CurrentAuditPolicy(),
		Timeout:             timeout,
		InspectionTimeout:   3 * time.Second,
		OutputLimit:         outputLimit,
		HostOS:              hostOS,
		HostArch:            hostArch,
		RequireTrustedBuild: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	return inspector
}

func newProductionInspector(t *testing.T) *Inspector {
	t.Helper()
	policy := DefaultProbePolicy()
	policy.Timeout = 10 * time.Second
	policy.TrustedSHA256 = []string{
		"36c97b1ed369c2c46d7a4dde0d635d8e742b080c27c36d58933a8029f7811624",
		"e55089f626ffe1725de10b71bac366a6f6ee8d88cddc7fbff8fdb1cd3ad4897f",
		"ef3819a069a79e8b79306665cac076b9ce53e31f63c60b953d62740f8f4b59b4",
	}
	inspector, err := NewInspector(policy)
	if err != nil {
		t.Fatal(err)
	}
	return inspector
}

func copyProbeFixture(t *testing.T, name, source string) string {
	t.Helper()
	return copyProbeFixtureIn(t, t.TempDir(), name, source)
}

func copyProbeFixtureIn(t *testing.T, directory, name, source string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		t.Fatal(err)
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func replaceProbeFixture(path, source string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	var output *os.File
	deadline := time.Now().Add(time.Second)
	for {
		output, err = os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
		if err == nil || !errors.Is(err, syscall.ETXTBSY) || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		return err
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		return err
	}
	return output.Close()
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}

func TestDefaultPolicyMatchesRuntime(t *testing.T) {
	t.Parallel()
	policy := DefaultProbePolicy()
	if policy.HostOS != runtime.GOOS || policy.HostArch != runtime.GOARCH {
		t.Fatalf("policy host = %s/%s", policy.HostOS, policy.HostArch)
	}
}
