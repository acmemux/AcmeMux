//go:build linux

package inventory

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	maximumTimeout             = 2 * time.Minute
	maximumStandardOutputLimit = 16 << 20
	maximumErrorOutputLimit    = 1 << 20
	maximumCertificateCount    = 10000
	maximumTreeEntryCount      = 100000
	maximumTreeDepth           = 64
	maximumServiceGroups       = 128
	processWaitDelay           = time.Second
)

func controlledEnvironment(neutralDirectory string) []string {
	return []string{
		"HOME=" + neutralDirectory,
		"LANG=C",
		"LC_ALL=C",
		"TZ=UTC",
		"XDG_CONFIG_HOME=" + neutralDirectory,
	}
}

// Reader runs one bounded, non-mutating upstream certificate inventory and
// reconciles its JSON with native filesystem evidence.
type Reader struct {
	policy Policy
	gate   chan struct{}
}

// NewReader validates and retains an explicit inventory policy.
func NewReader(policy Policy) (*Reader, error) {
	if err := validateCanonicalPath(policy.NeutralDirectory); err != nil {
		return nil, &Error{Code: CodeInvalidPolicy, Path: policy.NeutralDirectory, Detail: "neutral directory must be a canonical absolute path", Cause: err}
	}
	if policy.Timeout <= 0 || policy.Timeout > maximumTimeout {
		return nil, &Error{Code: CodeInvalidPolicy, Detail: "timeout must be positive and no more than two minutes"}
	}
	if policy.StdoutLimit <= 0 || policy.StdoutLimit > maximumStandardOutputLimit {
		return nil, &Error{Code: CodeInvalidPolicy, Detail: "stdout limit must be between 1 byte and 16 MiB"}
	}
	if policy.StderrLimit <= 0 || policy.StderrLimit > maximumErrorOutputLimit {
		return nil, &Error{Code: CodeInvalidPolicy, Detail: "stderr limit must be between 1 byte and 1 MiB"}
	}
	if policy.MaximumCertificates <= 0 || policy.MaximumCertificates > maximumCertificateCount {
		return nil, &Error{Code: CodeInvalidPolicy, Detail: "certificate limit must be between 1 and 10000"}
	}
	if policy.MaximumTreeEntries <= 0 || policy.MaximumTreeEntries > maximumTreeEntryCount {
		return nil, &Error{Code: CodeInvalidPolicy, Detail: "tree entry limit must be between 1 and 100000"}
	}
	if policy.MaximumTreeDepth <= 0 || policy.MaximumTreeDepth > maximumTreeDepth {
		return nil, &Error{Code: CodeInvalidPolicy, Detail: "tree depth limit must be between 1 and 64"}
	}
	if len(policy.EffectiveGIDs) == 0 || len(policy.EffectiveGIDs) > maximumServiceGroups {
		return nil, &Error{Code: CodeInvalidPolicy, Detail: "service group list must contain between 1 and 128 groups"}
	}
	seenGIDs := make(map[uint32]struct{}, len(policy.EffectiveGIDs))
	for _, gid := range policy.EffectiveGIDs {
		if _, duplicate := seenGIDs[gid]; duplicate {
			return nil, &Error{Code: CodeInvalidPolicy, Detail: "service group list contains a duplicate"}
		}
		seenGIDs[gid] = struct{}{}
	}
	policy.EffectiveGIDs = slices.Clone(policy.EffectiveGIDs)
	return &Reader{policy: policy, gate: make(chan struct{}, 1)}, nil
}

// Read closes prepared exactly once on every path, runs exact argv
// `certificates list --path <storage> --json`, and returns metadata only.
func (reader *Reader) Read(
	ctx context.Context,
	prepared PreparedExecutable,
	storagePath string,
) (certificates []Certificate, resultErr error) {
	if prepared == nil {
		return nil, &Error{Code: CodeInvalidPolicy, Detail: "prepared executable is required"}
	}
	defer func() {
		if err := prepared.Close(); err != nil && resultErr == nil {
			certificates = nil
			resultErr = &Error{Code: CodePreparedCloseFailed, Detail: "could not close prepared executable", Cause: err}
		}
	}()
	if reader == nil {
		return nil, &Error{Code: CodeInvalidPolicy, Detail: "inventory reader is nil"}
	}
	if ctx == nil {
		return nil, &Error{Code: CodeInvalidPolicy, Detail: "inventory context is nil"}
	}
	if err := validateCanonicalPath(storagePath); err != nil {
		return nil, err
	}
	select {
	case reader.gate <- struct{}{}:
		defer func() { <-reader.gate }()
	default:
		return nil, &Error{Code: CodeExecutionBusy, Detail: "another bounded certificate inventory is already running"}
	}

	boundedContext, cancelBounded := context.WithTimeout(ctx, reader.policy.Timeout)
	defer cancelBounded()
	neutralBefore, err := reader.auditNeutralDirectory(boundedContext)
	if err != nil {
		return nil, err
	}
	before, err := reader.auditStorage(boundedContext, storagePath)
	if err != nil {
		return nil, err
	}

	runContext, cancelRun := context.WithCancel(boundedContext)
	defer cancelRun()
	standardOutput := newBoundedOutput(reader.policy.StdoutLimit, cancelRun)
	errorOutput := newBoundedSink(reader.policy.StderrLimit, cancelRun)
	// Pdeathsig is tied to the creating Linux thread, not merely the parent
	// process. Keep that thread alive until Wait completes so Go runtime thread
	// retirement cannot kill a healthy inventory child.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	command, err := prepared.StartContext(
		runContext,
		func(command *exec.Cmd) error {
			command.Dir = reader.policy.NeutralDirectory
			command.Env = controlledEnvironment(reader.policy.NeutralDirectory)
			command.Stdin = nil
			command.Stdout = standardOutput
			command.Stderr = errorOutput
			command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
			command.WaitDelay = processWaitDelay
			command.Cancel = func() error { return killProcessGroup(command) }
			return nil
		},
		"certificates", "list", "--path", storagePath, "--json",
	)
	if err != nil {
		if contextErr := contextDiagnostic(boundedContext); contextErr != nil {
			return nil, contextErr
		}
		return nil, &Error{Code: CodeExecutionFailed, Detail: "could not start certificate inventory command", Cause: err}
	}
	waitErr := command.Wait()
	_ = killProcessGroup(command)
	if standardOutput.Overflowed() || errorOutput.Overflowed() {
		return nil, &Error{Code: CodeOutputLimit, Detail: "certificate inventory command exceeded an output limit"}
	}
	if contextErr := contextDiagnostic(boundedContext); contextErr != nil {
		return nil, contextErr
	}

	neutralAfter, err := reader.auditNeutralDirectory(boundedContext)
	if err != nil || neutralAfter != neutralBefore {
		return nil, &Error{Code: CodeArtifactsChanged, Path: reader.policy.NeutralDirectory, Detail: "neutral command directory changed during inventory", Cause: err}
	}
	after, err := reader.auditStorage(boundedContext, storagePath)
	if err != nil {
		return nil, &Error{Code: CodeArtifactsChanged, Path: storagePath, Detail: "certificate artifacts changed during inventory", Cause: err}
	}
	if !sameTree(before, after) {
		return nil, &Error{Code: CodeArtifactsChanged, Path: storagePath, Detail: "certificate artifacts changed during inventory"}
	}
	if waitErr != nil {
		// Upstream lego reports a non-zero stat error when a valid, empty native
		// storage has no certificates directory yet. The upstream logger writes
		// that stat error to stdout, so normalize only the exact pre/post-audited
		// absence; every other child failure stays fail closed. AcmeMux does not
		// create or repair the native directory.
		if before.certificates == nil && after.certificates == nil &&
			stableMissingCertificateDirectoryFailure(waitErr, standardOutput.Bytes(), errorOutput.Written(), storagePath) {
			return []Certificate{}, nil
		}
		return nil, &Error{Code: CodeExecutionFailed, Detail: "certificate inventory command did not complete successfully", Cause: waitErr}
	}
	return decodeInventory(standardOutput.Bytes(), after, storagePath, reader.policy.MaximumCertificates)
}

func stableMissingCertificateDirectoryFailure(waitErr error, stdout []byte, stderrBytes int, storagePath string) bool {
	var exitError *exec.ExitError
	if !errors.As(waitErr, &exitError) || exitError.ExitCode() != 1 || stderrBytes != 0 ||
		len(stdout) == 0 || stdout[len(stdout)-1] != '\n' || bytes.Count(stdout, []byte{'\n'}) != 1 {
		return false
	}

	line := strings.TrimSuffix(string(stdout), "\n")
	separator := strings.IndexByte(line, ' ')
	if separator <= 0 {
		return false
	}
	if _, err := time.Parse(time.RFC3339Nano, line[:separator]); err != nil {
		return false
	}
	const prefix = "ERROR Error error="
	encoded := strings.TrimPrefix(line[separator+1:], prefix)
	if encoded == line[separator+1:] {
		return false
	}
	message, err := strconv.Unquote(encoded)
	if err != nil {
		return false
	}
	want := "stat " + certificateRoot(storagePath) + ": " + syscall.ENOENT.Error()
	return message == want
}

func checkContext(ctx context.Context) error {
	if err := contextDiagnostic(ctx); err != nil {
		return err
	}
	return nil
}

func contextDiagnostic(ctx context.Context) error {
	if ctx == nil || ctx.Err() == nil {
		return nil
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return &Error{Code: CodeExecutionTimeout, Detail: "certificate inventory exceeded its deadline", Cause: ctx.Err()}
	}
	return &Error{Code: CodeExecutionCanceled, Detail: "certificate inventory was canceled", Cause: ctx.Err()}
}

func killProcessGroup(command *exec.Cmd) error {
	if command == nil || command.Process == nil {
		return os.ErrProcessDone
	}
	err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}

type boundedOutput struct {
	mu         sync.Mutex
	limit      int
	buffer     bytes.Buffer
	overflowed bool
	onOverflow func()
}

func newBoundedOutput(limit int, onOverflow func()) *boundedOutput {
	return &boundedOutput{limit: limit, onOverflow: onOverflow}
}

func (output *boundedOutput) Write(value []byte) (int, error) {
	output.mu.Lock()
	remaining := output.limit - output.buffer.Len()
	if remaining > len(value) {
		remaining = len(value)
	}
	if remaining > 0 {
		_, _ = output.buffer.Write(value[:remaining])
	}
	newOverflow := len(value) > remaining && !output.overflowed
	if len(value) > remaining {
		output.overflowed = true
	}
	output.mu.Unlock()
	if newOverflow && output.onOverflow != nil {
		output.onOverflow()
	}
	return len(value), nil
}

func (output *boundedOutput) Bytes() []byte {
	output.mu.Lock()
	defer output.mu.Unlock()
	return bytes.Clone(output.buffer.Bytes())
}

func (output *boundedOutput) Overflowed() bool {
	output.mu.Lock()
	defer output.mu.Unlock()
	return output.overflowed
}

// boundedSink counts and discards child stderr so diagnostics cannot linger in
// application memory or reach logs while overflow still cancels the process.
type boundedSink struct {
	mu         sync.Mutex
	limit      int
	written    int
	overflowed bool
	onOverflow func()
}

func newBoundedSink(limit int, onOverflow func()) *boundedSink {
	return &boundedSink{limit: limit, onOverflow: onOverflow}
}

func (sink *boundedSink) Write(value []byte) (int, error) {
	sink.mu.Lock()
	remaining := sink.limit - sink.written
	accepted := min(len(value), remaining)
	sink.written += accepted
	newOverflow := len(value) > accepted && !sink.overflowed
	if len(value) > accepted {
		sink.overflowed = true
	}
	sink.mu.Unlock()
	if newOverflow && sink.onOverflow != nil {
		sink.onOverflow()
	}
	return len(value), nil
}

func (sink *boundedSink) Written() int {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.written
}

func (sink *boundedSink) Overflowed() bool {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.overflowed
}

func certificateRoot(storagePath string) string {
	return filepath.Join(storagePath, "certificates")
}
