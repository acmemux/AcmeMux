//go:build linux

package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

var controlledProbeEnvironment = []string{
	"LANG=C",
	"LC_ALL=C",
	"PATH=/usr/bin:/bin",
	"TZ=UTC",
}

const (
	maximumBuildInfoReadBytes = 8 << 20
	maximumBuildDependencies  = 2048
	maximumBuildSettings      = 64
	maximumBuildFieldBytes    = 4096
	maximumBuildEvidenceBytes = 1 << 20
)

// Inspector performs bounded audits and identity probes.
type Inspector struct {
	policy ProbePolicy
	gate   chan struct{}
}

// PreparedExecutable retains the exact persisted and re-reviewed file
// descriptor so a later broker operation cannot be redirected by a path rename
// after verification. It is a one-shot handle: StartContext owns the descriptor
// until the child starts, and Close safely abandons an unused handle.
type PreparedExecutable struct {
	observation Observation
	file        *os.File
	mu          sync.Mutex
}

// NewInspector validates and retains an explicit probe policy.
func NewInspector(policy ProbePolicy) (*Inspector, error) {
	if policy.Timeout <= 0 || policy.Timeout > maximumProbeTimeout {
		return nil, &Error{Code: CodeInvalidPolicy, Detail: "probe timeout must be positive and no more than 30 seconds"}
	}
	if policy.InspectionTimeout <= 0 || policy.InspectionTimeout > maximumInspectionTimeout {
		return nil, &Error{Code: CodeInvalidPolicy, Detail: "inspection timeout must be positive and no more than two minutes"}
	}
	if policy.OutputLimit <= 0 || policy.OutputLimit > 64<<10 {
		return nil, &Error{Code: CodeInvalidPolicy, Detail: "probe output limit must be between 1 and 65536 bytes per stream"}
	}
	if policy.HostOS == "" || policy.HostArch == "" {
		return nil, &Error{Code: CodeInvalidPolicy, Detail: "host operating system and architecture are required"}
	}
	if len(policy.TrustedSHA256) > 64 {
		return nil, &Error{Code: CodeInvalidPolicy, Detail: "trusted executable digest allowlist is too large"}
	}
	seenDigests := make(map[string]struct{}, len(policy.TrustedSHA256))
	for _, digest := range policy.TrustedSHA256 {
		if len(digest) != sha256.Size*2 {
			return nil, &Error{Code: CodeInvalidPolicy, Detail: "trusted executable digest is malformed"}
		}
		if _, err := hex.DecodeString(digest); err != nil || strings.ToLower(digest) != digest {
			return nil, &Error{Code: CodeInvalidPolicy, Detail: "trusted executable digest is malformed"}
		}
		if _, duplicate := seenDigests[digest]; duplicate {
			return nil, &Error{Code: CodeInvalidPolicy, Detail: "trusted executable digest is duplicated"}
		}
		seenDigests[digest] = struct{}{}
	}
	if policy.RequireTrustedBuild && len(policy.TrustedSHA256) == 0 {
		return nil, &Error{Code: CodeInvalidPolicy, Detail: "trusted builds require an executable digest allowlist"}
	}
	policy.Audit.EffectiveGIDs = slices.Clone(policy.Audit.EffectiveGIDs)
	policy.TrustedSHA256 = slices.Clone(policy.TrustedSHA256)
	return &Inspector{policy: policy, gate: make(chan struct{}, 1)}, nil
}

// Inspect audits the selected path, probes the already-open file directly with
// exactly --version, then re-hashes both the open file and the current path.
// This prevents a rename replacement from being silently adopted during the
// inspection window.
func (i *Inspector) Inspect(ctx context.Context, path string) (Observation, error) {
	inspectionContext, release, err := i.beginInspection(ctx)
	if err != nil {
		return Observation{}, err
	}
	defer release()
	observation, file, err := i.inspectOpen(inspectionContext, path)
	if file != nil {
		_ = file.Close()
	}
	return observation, err
}

func (i *Inspector) beginInspection(ctx context.Context) (context.Context, func(), error) {
	if i == nil || i.gate == nil {
		return nil, nil, &Error{Code: CodeInvalidPolicy, Detail: "inspector is nil"}
	}
	if ctx == nil {
		return nil, nil, &Error{Code: CodeInvalidPolicy, Detail: "inspection context is nil"}
	}
	bounded, cancel := context.WithTimeout(ctx, i.policy.InspectionTimeout)
	select {
	case i.gate <- struct{}{}:
		return bounded, func() {
			<-i.gate
			cancel()
		}, nil
	default:
		cancel()
		return nil, nil, &Error{Code: CodeInspectionBusy, Detail: "another runtime inspection is already in progress"}
	}
}

func (i *Inspector) inspectOpen(ctx context.Context, path string) (observation Observation, retained *os.File, resultErr error) {
	if i == nil {
		return Observation{}, nil, &Error{Code: CodeInvalidPolicy, Detail: "inspector is nil"}
	}
	opened, err := openExecutableContext(ctx, path, i.policy.Audit)
	if err != nil {
		return Observation{}, nil, err
	}
	defer func() {
		if resultErr != nil {
			_ = opened.file.Close()
		}
	}()
	if i.policy.RequireTrustedBuild && !slices.Contains(i.policy.TrustedSHA256, opened.identity.SHA256) {
		return Observation{File: opened.identity}, nil, &Error{Code: CodeExecutableNotQualified, Path: path, Detail: "executable bytes are not in an independently qualified manifest"}
	}

	build, err := readBuildEvidence(ctx, opened.file, path)
	if err != nil {
		return Observation{File: opened.identity}, nil, err
	}
	if i.policy.RequireTrustedBuild {
		if err := validateBuildProvenance(build, i.policy.HostOS, i.policy.HostArch, path); err != nil {
			return Observation{File: opened.identity, Build: build}, nil, err
		}
	}
	version, platform, output, err := i.probe(ctx, opened.file, path)
	if err != nil {
		return Observation{File: opened.identity}, nil, err
	}
	if !platform.Supported() {
		return Observation{File: opened.identity, Version: version, Platform: platform, Build: build, VersionOutput: output}, nil, &Error{
			Code:   CodeUnsupportedPlatform,
			Path:   path,
			Detail: fmt.Sprintf("reported platform %s/%s is outside the Linux amd64/arm64 policy", platform.OS, platform.Arch),
		}
	}
	if platform.OS != i.policy.HostOS || platform.Arch != i.policy.HostArch {
		return Observation{File: opened.identity, Version: version, Platform: platform, Build: build, VersionOutput: output}, nil, &Error{
			Code:   CodePlatformMismatch,
			Path:   path,
			Detail: fmt.Sprintf("reported platform %s/%s does not match host %s/%s", platform.OS, platform.Arch, i.policy.HostOS, i.policy.HostArch),
		}
	}
	if i.policy.RequireTrustedBuild {
		if err := validateBuildEvidence(build, version, platform, path); err != nil {
			return Observation{File: opened.identity, Version: version, Platform: platform, Build: build, VersionOutput: output}, nil, err
		}
	} else if err := validateReportedBuildEvidence(build, version, platform, path); err != nil {
		return Observation{File: opened.identity, Version: version, Platform: platform, Build: build, VersionOutput: output}, nil, err
	}

	afterProbe, err := fingerprintOpenedFileContext(ctx, opened.file, path, i.policy.Audit)
	if err != nil {
		return Observation{File: opened.identity, Version: version, Platform: platform, Build: build, VersionOutput: output}, nil, err
	}
	if !sameFileIdentity(opened.identity, afterProbe) {
		return Observation{File: afterProbe, Version: version, Platform: platform, Build: build, VersionOutput: output}, nil, &Error{Code: CodeChangedDuringInspection, Path: path, Detail: "opened executable changed while probing"}
	}

	currentOpened, err := openExecutableContext(ctx, path, i.policy.Audit)
	if err != nil {
		return Observation{File: afterProbe, Version: version, Platform: platform, Build: build, VersionOutput: output}, nil, &Error{Code: CodeChangedDuringInspection, Path: path, Detail: "selected path changed while probing", Cause: err}
	}
	current := currentOpened.identity
	_ = currentOpened.file.Close()
	if !sameFileIdentity(opened.identity, current) {
		return Observation{File: current, Version: version, Platform: platform, Build: build, VersionOutput: output}, nil, &Error{Code: CodeChangedDuringInspection, Path: path, Detail: "selected path now resolves to different executable evidence"}
	}

	observation = Observation{
		File:          opened.identity,
		Version:       version,
		Platform:      platform,
		Build:         build,
		VersionOutput: output,
		ObservedAt:    time.Now().UTC(),
	}
	return observation, opened.file, nil
}

// Verify re-inspects the reviewed path immediately before a managed operation
// and rejects every metadata, digest, version-output, or platform difference.
func (i *Inspector) Verify(ctx context.Context, reviewed Observation) (Observation, error) {
	prepared, err := i.prepareReviewed(ctx, reviewed)
	if err != nil {
		var replacement *ReplacementError
		if errors.As(err, &replacement) {
			return replacementCurrent(err), err
		}
		return Observation{}, err
	}
	defer prepared.Close()
	return prepared.Observation(), nil
}

// SelectionClassifier returns the current exact compatibility manifest for an
// observation. A false compatible result blocks preparation.
type SelectionClassifier func(Observation) (manifestID string, compatible bool)

// PrepareCurrent loads the persisted administrator-reviewed singleton,
// re-inspects and reclassifies the exact retained executable, and permits
// execution only while the current compatible manifest is identical to the
// reviewed manifest. Accepting the concrete store prevents operation callers
// from substituting an unpersisted Selection.
func (i *Inspector) PrepareCurrent(
	ctx context.Context,
	selections *SelectionStore,
	classify SelectionClassifier,
) (*PreparedExecutable, error) {
	if selections == nil || classify == nil {
		return nil, &Error{Code: CodeInvalidPolicy, Detail: "runtime selection store and classifier are required"}
	}
	selection, err := selections.Load(ctx)
	if err != nil {
		return nil, err
	}
	return i.prepareSelection(ctx, selection, classify)
}

func (i *Inspector) prepareSelection(
	ctx context.Context,
	selection Selection,
	classify SelectionClassifier,
) (*PreparedExecutable, error) {
	prepared, err := i.prepareReviewed(ctx, selection.Observation)
	if err != nil {
		return nil, err
	}
	manifestID, compatible := classify(prepared.Observation())
	if !compatible || manifestID != selection.ManifestID {
		_ = prepared.Close()
		return nil, &Error{Code: CodeCompatibilityChanged, Path: selection.Observation.File.CanonicalPath, Detail: "the reviewed compatibility manifest is no longer current"}
	}
	return prepared, nil
}

func (i *Inspector) prepareReviewed(ctx context.Context, reviewed Observation) (*PreparedExecutable, error) {
	if reviewed.File.CanonicalPath == "" {
		return nil, &Error{Code: CodePathRequired, Detail: "reviewed observation has no canonical path"}
	}
	inspectionContext, release, err := i.beginInspection(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	current, file, err := i.inspectOpen(inspectionContext, reviewed.File.CanonicalPath)
	if err != nil {
		return nil, &ReplacementError{Path: reviewed.File.CanonicalPath, Current: current, Changes: []string{"inspection_failed"}, Cause: err}
	}
	changes := Differences(reviewed, current)
	if len(changes) != 0 {
		_ = file.Close()
		return nil, &ReplacementError{Path: reviewed.File.CanonicalPath, Current: current, Changes: changes}
	}
	return &PreparedExecutable{observation: current, file: file}, nil
}

func replacementCurrent(err error) Observation {
	var replacement *ReplacementError
	if errors.As(err, &replacement) {
		return replacement.Current
	}
	return Observation{}
}

// Observation returns the re-inspected evidence retained by this handle.
func (p *PreparedExecutable) Observation() Observation {
	if p == nil {
		return Observation{}
	}
	return p.observation
}

// StartContext constructs and starts one direct, no-shell command while owning
// the retained descriptor under a lock. configure must set the explicit
// working directory, allowlisted environment, process controls, and bounded
// output before Start; ExtraFiles is assigned afterward and cannot be replaced.
// The descriptor is closed in the parent only after Start has duplicated it
// into the child, preventing Close/reuse races from redirecting fd 3.
func (p *PreparedExecutable) StartContext(
	ctx context.Context,
	configure func(*exec.Cmd) error,
	arguments ...string,
) (*exec.Cmd, error) {
	if p == nil {
		return nil, &Error{Code: CodePreparedClosed}
	}
	if ctx == nil || configure == nil {
		return nil, &Error{Code: CodeInvalidPolicy, Detail: "command context and configuration are required"}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.file == nil {
		return nil, &Error{Code: CodePreparedClosed}
	}
	arguments = slices.Clone(arguments)
	command := exec.CommandContext(ctx, "/proc/self/fd/3", arguments...)
	if err := configure(command); err != nil {
		return nil, fmt.Errorf("configure prepared executable: %w", err)
	}
	command.Path = "/proc/self/fd/3"
	command.Args = append([]string{p.observation.File.CanonicalPath}, arguments...)
	command.ExtraFiles = []*os.File{p.file}
	startErr := command.Start()
	closeErr := p.file.Close()
	p.file = nil
	if startErr != nil {
		return nil, startErr
	}
	if closeErr != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return nil, fmt.Errorf("release prepared executable after start: %w", closeErr)
	}
	return command, nil
}

// Close releases the retained executable descriptor. It is idempotent.
func (p *PreparedExecutable) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.file == nil {
		return nil
	}
	err := p.file.Close()
	p.file = nil
	return err
}

// Differences reports material replacement dimensions in deterministic order.
// Observation timestamps are not identity evidence and are not compared.
func Differences(reviewed, current Observation) []string {
	var changes []string
	if reviewed.File.CanonicalPath != current.File.CanonicalPath {
		changes = append(changes, "canonical_path")
	}
	if reviewed.File.Device != current.File.Device {
		changes = append(changes, "device")
	}
	if reviewed.File.Inode != current.File.Inode {
		changes = append(changes, "inode")
	}
	if reviewed.File.Mode != current.File.Mode {
		changes = append(changes, "mode")
	}
	if reviewed.File.Capabilities != current.File.Capabilities {
		changes = append(changes, "capabilities")
	}
	if reviewed.File.UID != current.File.UID {
		changes = append(changes, "uid")
	}
	if reviewed.File.GID != current.File.GID {
		changes = append(changes, "gid")
	}
	if reviewed.File.Size != current.File.Size {
		changes = append(changes, "size")
	}
	if !reviewed.File.ModifiedAt.Equal(current.File.ModifiedAt) {
		changes = append(changes, "modified_at")
	}
	if !reviewed.File.ChangedAt.Equal(current.File.ChangedAt) {
		changes = append(changes, "changed_at")
	}
	if reviewed.File.SHA256 != current.File.SHA256 {
		changes = append(changes, "sha256")
	}
	if reviewed.Version != current.Version {
		changes = append(changes, "version")
	}
	if reviewed.Platform != current.Platform {
		changes = append(changes, "platform")
	}
	if reviewed.Build != current.Build {
		changes = append(changes, "build_evidence")
	}
	if reviewed.VersionOutput != current.VersionOutput {
		changes = append(changes, "version_output")
	}
	return changes
}

func readBuildEvidence(ctx context.Context, file *os.File, path string) (BuildEvidence, error) {
	reader := &boundedBuildInfoReader{ctx: ctx, reader: file, remaining: maximumBuildInfoReadBytes}
	info, err := buildinfo.Read(reader)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			code := CodeInspectionCanceled
			if errors.Is(ctxErr, context.DeadlineExceeded) {
				code = CodeInspectionTimeout
			}
			return BuildEvidence{}, &Error{Code: code, Path: path, Cause: ctxErr}
		}
		if reader.exceeded {
			return BuildEvidence{}, &Error{Code: CodeBuildIdentityMismatch, Path: path, Detail: "embedded Go build information exceeds its read bound"}
		}
		return BuildEvidence{}, nil
	}
	if len(info.Deps) > maximumBuildDependencies || len(info.Settings) > maximumBuildSettings {
		return BuildEvidence{}, &Error{Code: CodeBuildIdentityMismatch, Path: path, Detail: "embedded Go build information exceeds its entry bound"}
	}
	evidence := BuildEvidence{
		Available:   true,
		GoVersion:   info.GoVersion,
		CommandPath: info.Path,
		MainPath:    info.Main.Path,
		MainVersion: info.Main.Version,
	}
	evidence.DependencyGraphSHA256, evidence.ProvenanceComplete = dependencyGraphIdentity(ctx, info.Deps)
	settingsComplete := validBuildSettings(info.Settings)
	evidence.ProvenanceComplete = evidence.ProvenanceComplete && settingsComplete
	for _, setting := range info.Settings {
		switch setting.Key {
		case "GOOS":
			evidence.GOOS = setting.Value
		case "GOARCH":
			evidence.GOARCH = setting.Value
		case "vcs.revision":
			evidence.VCSRevision = setting.Value
		case "vcs.modified":
			evidence.VCSModifiedKnown = true
			evidence.VCSModifiedValid = setting.Value == "true" || setting.Value == "false"
			evidence.VCSModified = setting.Value == "true"
		}
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		code := CodeInspectionCanceled
		if errors.Is(ctxErr, context.DeadlineExceeded) {
			code = CodeInspectionTimeout
		}
		return BuildEvidence{}, &Error{Code: code, Path: path, Cause: ctxErr}
	}
	return evidence, nil
}

type boundedBuildInfoReader struct {
	ctx       context.Context
	reader    io.ReaderAt
	remaining int64
	exceeded  bool
}

func (r *boundedBuildInfoReader) ReadAt(value []byte, offset int64) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if int64(len(value)) > r.remaining {
		r.exceeded = true
		return 0, io.ErrUnexpectedEOF
	}
	count, err := r.reader.ReadAt(value, offset)
	r.remaining -= int64(count)
	return count, err
}

type dependencyRecord struct {
	path    string
	version string
	sum     string
}

func dependencyGraphIdentity(ctx context.Context, dependencies []*debug.Module) (string, bool) {
	if len(dependencies) > maximumBuildDependencies {
		return "", false
	}
	records := make([]dependencyRecord, 0, len(dependencies))
	complete := true
	aggregate := 0
	seen := make(map[string]struct{}, len(dependencies))
	for _, dependency := range dependencies {
		if ctx.Err() != nil || dependency == nil || dependency.Replace != nil ||
			!validDependencyField(dependency.Path, maximumBuildFieldBytes) ||
			!validDependencyField(dependency.Version, 256) ||
			!validDependencyField(dependency.Sum, 256) {
			complete = false
			continue
		}
		aggregate += len(dependency.Path) + len(dependency.Version) + len(dependency.Sum)
		key := dependency.Path + "\x00" + dependency.Version + "\x00" + dependency.Sum
		if aggregate > maximumBuildEvidenceBytes {
			complete = false
			continue
		}
		if _, duplicate := seen[key]; duplicate {
			complete = false
			continue
		}
		seen[key] = struct{}{}
		records = append(records, dependencyRecord{path: dependency.Path, version: dependency.Version, sum: dependency.Sum})
	}
	sort.Slice(records, func(left, right int) bool {
		if records[left].path != records[right].path {
			return records[left].path < records[right].path
		}
		if records[left].version != records[right].version {
			return records[left].version < records[right].version
		}
		return records[left].sum < records[right].sum
	})
	hash := sha256.New()
	for _, record := range records {
		writeBuildField(hash, record.path)
		writeBuildField(hash, record.version)
		writeBuildField(hash, record.sum)
	}
	return hex.EncodeToString(hash.Sum(nil)), complete
}

func validDependencyField(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range []byte(value) {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func writeBuildField(writer io.Writer, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = io.WriteString(writer, value)
}

func validBuildSettings(settings []debug.BuildSetting) bool {
	if len(settings) > maximumBuildSettings {
		return false
	}
	allowed := map[string]func(string) bool{
		"-buildmode":     func(value string) bool { return value == "exe" },
		"-compiler":      func(value string) bool { return value == "gc" },
		"-trimpath":      func(value string) bool { return value == "true" },
		"CGO_ENABLED":    func(value string) bool { return value == "0" },
		"DefaultGODEBUG": func(value string) bool { return boundedPrintableBuildField(value, 1024) },
		"GOARCH":         func(value string) bool { return platformPattern.MatchString(value) },
		"GOOS":           func(value string) bool { return platformPattern.MatchString(value) },
		"GOAMD64":        func(value string) bool { return value == "v1" || value == "v2" || value == "v3" || value == "v4" },
		"GOARM64":        func(value string) bool { return strings.HasPrefix(value, "v8.") || strings.HasPrefix(value, "v9.") },
		"vcs":            func(value string) bool { return value == "git" },
		"vcs.modified":   func(value string) bool { return value == "true" || value == "false" },
		"vcs.revision":   func(value string) bool { return revisionPattern.MatchString(value) },
		"vcs.time": func(value string) bool {
			_, err := time.Parse(time.RFC3339, value)
			return err == nil
		},
	}
	seen := make(map[string]struct{}, len(settings))
	aggregate := 0
	for _, setting := range settings {
		aggregate += len(setting.Key) + len(setting.Value)
		if aggregate > maximumBuildEvidenceBytes || !validDependencyField(setting.Key, 128) || len(setting.Value) > maximumBuildFieldBytes {
			return false
		}
		validator, ok := allowed[setting.Key]
		if !ok || !validator(setting.Value) {
			return false
		}
		if _, duplicate := seen[setting.Key]; duplicate {
			return false
		}
		seen[setting.Key] = struct{}{}
	}
	for _, required := range []string{"-buildmode", "-compiler", "-trimpath", "CGO_ENABLED", "GOOS", "GOARCH"} {
		if _, ok := seen[required]; !ok {
			return false
		}
	}
	return true
}

func validateBuildProvenance(build BuildEvidence, hostOS, hostArch, path string) error {
	if !build.Available || !build.ProvenanceComplete || build.DependencyGraphSHA256 == "" {
		return &Error{Code: CodeBuildIdentityMismatch, Path: path, Detail: "complete Go build provenance is required before execution"}
	}
	if build.CommandPath != "github.com/go-acme/lego/v5" || build.MainPath != "github.com/go-acme/lego/v5" {
		return &Error{Code: CodeBuildIdentityMismatch, Path: path, Detail: "embedded command and main module are not github.com/go-acme/lego/v5"}
	}
	if build.GOOS != hostOS || build.GOARCH != hostArch {
		return &Error{Code: CodeBuildIdentityMismatch, Path: path, Detail: "embedded build platform does not match this host"}
	}
	if !revisionPattern.MatchString(build.VCSRevision) || !build.VCSModifiedKnown || !build.VCSModifiedValid || build.VCSModified {
		return &Error{Code: CodeBuildIdentityMismatch, Path: path, Detail: "a clean exact Git source revision is required before execution"}
	}
	return nil
}

func validateBuildEvidence(build BuildEvidence, version VersionIdentity, platform Platform, path string) error {
	if err := validateBuildProvenance(build, platform.OS, platform.Arch, path); err != nil {
		return err
	}
	return validateReportedBuildEvidence(build, version, platform, path)
}

func validateReportedBuildEvidence(build BuildEvidence, version VersionIdentity, platform Platform, path string) error {
	if !build.Available {
		return nil
	}
	if build.MainPath != "" && build.MainPath != "github.com/go-acme/lego/v5" {
		return &Error{Code: CodeBuildIdentityMismatch, Path: path, Detail: "embedded main module is not github.com/go-acme/lego/v5"}
	}
	if !boundedPrintableBuildField(build.GoVersion, 128) || !boundedPrintableBuildField(build.MainVersion, 256) {
		return &Error{Code: CodeBuildIdentityMismatch, Path: path, Detail: "embedded Go build version data is malformed"}
	}
	if build.VCSRevision != "" && !revisionPattern.MatchString(build.VCSRevision) {
		return &Error{Code: CodeBuildIdentityMismatch, Path: path, Detail: "embedded VCS revision is not an exact lowercase object name"}
	}
	if build.VCSModifiedKnown && !build.VCSModifiedValid {
		return &Error{Code: CodeBuildIdentityMismatch, Path: path, Detail: "embedded VCS modified state is malformed"}
	}
	if build.GOOS != "" && (len(build.GOOS) > 32 || !platformPattern.MatchString(build.GOOS)) {
		return &Error{Code: CodeBuildIdentityMismatch, Path: path, Detail: "embedded operating system is malformed"}
	}
	if build.GOARCH != "" && (len(build.GOARCH) > 32 || !platformPattern.MatchString(build.GOARCH)) {
		return &Error{Code: CodeBuildIdentityMismatch, Path: path, Detail: "embedded architecture is malformed"}
	}
	if build.GOOS != "" && build.GOOS != platform.OS {
		return &Error{Code: CodeBuildIdentityMismatch, Path: path, Detail: "reported operating system disagrees with embedded Go build information"}
	}
	if build.GOARCH != "" && build.GOARCH != platform.Arch {
		return &Error{Code: CodeBuildIdentityMismatch, Path: path, Detail: "reported architecture disagrees with embedded Go build information"}
	}
	if version.Kind == VersionRevision && build.VCSRevision != "" && build.VCSRevision != version.Value {
		return &Error{Code: CodeBuildIdentityMismatch, Path: path, Detail: "reported source revision disagrees with embedded Go build information"}
	}
	return nil
}

func boundedPrintableBuildField(value string, maximum int) bool {
	if len(value) > maximum {
		return false
	}
	for _, character := range []byte(value) {
		if character < 0x20 || character > 0x7e {
			return false
		}
	}
	return true
}

func (i *Inspector) probe(ctx context.Context, file *os.File, path string) (VersionIdentity, Platform, string, error) {
	probeContext, cancel := context.WithTimeout(ctx, i.policy.Timeout)
	defer cancel()

	stdout := newLimitedBuffer(i.policy.OutputLimit)
	stderr := newLimitedBuffer(i.policy.OutputLimit)
	command := exec.CommandContext(probeContext, "/proc/self/fd/3", "--version")
	command.Args[0] = path
	command.Dir = "/"
	command.Env = slices.Clone(controlledProbeEnvironment)
	command.ExtraFiles = []*os.File{file}
	command.Stdout = stdout
	command.Stderr = stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process == nil {
			return nil
		}
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = 250 * time.Millisecond

	err := command.Run()
	if stdout.exceeded || stderr.exceeded {
		return VersionIdentity{}, Platform{}, "", &Error{Code: CodeProbeOutputLimit, Path: path, Detail: "version probe exceeded its stdout or stderr limit"}
	}
	if ctx.Err() != nil {
		code := CodeInspectionCanceled
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			code = CodeInspectionTimeout
		}
		return VersionIdentity{}, Platform{}, "", &Error{Code: code, Path: path, Cause: ctx.Err()}
	}
	if errors.Is(probeContext.Err(), context.DeadlineExceeded) {
		return VersionIdentity{}, Platform{}, "", &Error{Code: CodeProbeTimeout, Path: path, Cause: probeContext.Err()}
	}
	if err != nil {
		return VersionIdentity{}, Platform{}, "", &Error{Code: CodeProbeFailed, Path: path, Detail: "version probe did not exit successfully", Cause: err}
	}
	if stderr.buffer.Len() != 0 {
		return VersionIdentity{}, Platform{}, "", &Error{Code: CodeProbeFailed, Path: path, Detail: "version probe wrote unexpected stderr output"}
	}
	return ParseVersionOutput(stdout.buffer.Bytes())
}

type limitedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func newLimitedBuffer(limit int) *limitedBuffer {
	return &limitedBuffer{limit: limit}
}

func (b *limitedBuffer) Write(value []byte) (int, error) {
	remaining := b.limit - b.buffer.Len()
	if remaining > 0 {
		write := len(value)
		if write > remaining {
			write = remaining
		}
		_, _ = b.buffer.Write(value[:write])
	}
	if len(value) > remaining {
		b.exceeded = true
	}
	return len(value), nil
}
