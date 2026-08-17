//go:build linux

package broker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/acmemux/AcmeMux/internal/redaction"
)

const (
	maximumPathBytes        = 4095
	processPipeWait         = time.Second
	forcedCleanupWait       = time.Second
	processScanInterval     = 25 * time.Millisecond
	maximumTrackedProcesses = 4096
)

var (
	environmentNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
	fixedEnvironment       = []string{"LANG=C", "LC_ALL=C", "TZ=UTC"}
	errHardTimeout         = errors.New("broker hard timeout")
	errOutputLimit         = errors.New("broker output limit")
	lockCreatorOSThread    = runtime.LockOSThread
	unlockCreatorOSThread  = runtime.UnlockOSThread
)

// Runner executes one file-mode operation at a time per prepared handle.
type Runner struct {
	policy Policy
}

// NewRunner validates and retains an explicit process policy.
func NewRunner(policy Policy) (*Runner, error) {
	if policy.Timeout <= 0 || policy.Timeout > maximumTimeout {
		return nil, &Error{Code: CodeInvalidPolicy, Detail: "timeout must be positive and no more than one hour"}
	}
	if policy.TerminationGrace <= 0 || policy.TerminationGrace > maximumTerminationGrace {
		return nil, &Error{Code: CodeInvalidPolicy, Detail: "termination grace must be positive and no more than 30 seconds"}
	}
	if policy.StdoutLimit <= 0 || policy.StdoutLimit > maximumStreamOutputLimit ||
		policy.StderrLimit <= 0 || policy.StderrLimit > maximumStreamOutputLimit ||
		policy.AggregateLimit <= 0 || policy.AggregateLimit > maximumAggregateOutputLimit ||
		policy.AggregateLimit < policy.StdoutLimit || policy.AggregateLimit < policy.StderrLimit ||
		policy.AggregateLimit > policy.StdoutLimit+policy.StderrLimit {
		return nil, &Error{Code: CodeInvalidPolicy, Detail: "output limits are invalid"}
	}
	if policy.MaximumEnvironment <= 0 || policy.MaximumEnvironment > maximumEnvironment ||
		policy.MaximumEnvironmentBytes <= 0 || policy.MaximumEnvironmentBytes > maximumEnvironmentByte ||
		policy.MaximumEnvironmentTotal <= 0 || policy.MaximumEnvironmentTotal > maximumEnvironmentSum {
		return nil, &Error{Code: CodeInvalidPolicy, Detail: "environment limits are invalid"}
	}
	if policy.MaximumSecrets <= 0 || policy.MaximumSecrets > maximumSecrets ||
		policy.MaximumSecretBytes <= 0 || policy.MaximumSecretBytes > maximumSecretByte ||
		policy.MaximumSecretTotal <= 0 || policy.MaximumSecretTotal > maximumSecretSum {
		return nil, &Error{Code: CodeInvalidPolicy, Detail: "secret limits are invalid"}
	}
	if err := ensureChildSubreaper(); err != nil {
		return nil, &Error{Code: CodeProcessBoundary, Detail: "could not enable the Linux child-subreaper boundary", Cause: err}
	}
	return &Runner{policy: policy}, nil
}

// Run consumes prepared exactly once on every path and invokes the upstream
// root file-mode action with exact argv `--config <absolute path>`.
func (runner *Runner) Run(ctx context.Context, request Request) (result Result, resultErr error) {
	prepared := request.Prepared
	if prepared == nil {
		return Result{}, &Error{Code: CodeInvalidRequest, Detail: "prepared executable is required"}
	}
	defer func() {
		if err := prepared.Close(); err != nil && resultErr == nil {
			resultErr = &Error{Code: CodePreparedCloseFailed, Detail: "could not close prepared executable", Cause: err}
		}
	}()
	if runner == nil {
		return Result{}, &Error{Code: CodeInvalidPolicy, Detail: "broker runner is nil"}
	}
	if ctx == nil {
		return Result{}, &Error{Code: CodeInvalidRequest, Detail: "operation context is required"}
	}
	if err := validateCanonicalPath(request.WorkingDirectory, true); err != nil {
		return Result{}, err
	}
	if err := validateCanonicalPath(request.ConfigurationPath, false); err != nil {
		return Result{}, err
	}

	environment, secretValues, err := runner.prepareEnvironmentAndSecrets(request)
	if err != nil {
		return Result{}, err
	}
	defer clearOwnedEnvironment(environment, secretValues)
	processGuard, err := newProcessGuard()
	if err != nil {
		return Result{}, &Error{Code: CodeProcessBoundary, Detail: "could not create the operation process guard", Cause: err}
	}
	environment = append(environment, processGuard)
	filterPolicy := redaction.Policy{
		MaximumValues:         runner.policy.MaximumSecrets,
		MaximumValueBytes:     runner.policy.MaximumSecretBytes,
		MaximumAggregateBytes: runner.policy.MaximumSecretTotal,
	}
	filter, err := redaction.New(secretValues, filterPolicy)
	if err != nil {
		return Result{}, &Error{Code: CodeRedactionFailed, Detail: "could not construct bounded output redaction", Cause: err}
	}
	defer filter.Clear()

	if err := ctx.Err(); err != nil {
		return Result{}, &Error{Code: CodeStartFailed, Detail: "operation was canceled before process start", Cause: err}
	}
	// Linux PR_SET_PDEATHSIG is tied to the OS thread that creates the child,
	// not merely to the AcmeMux process. Keep that thread alive and pinned until
	// Wait and process-tree cleanup complete so ordinary Go thread retirement
	// cannot kill a healthy lego operation.
	lockCreatorOSThread()
	defer unlockCreatorOSThread()
	timeoutContext, cancelTimeout := context.WithTimeoutCause(ctx, runner.policy.Timeout, errHardTimeout)
	defer cancelTimeout()
	runContext, cancelRun := context.WithCancelCause(timeoutContext)
	defer cancelRun(nil)

	collector := newOutputCollector(runner.policy.StdoutLimit, runner.policy.StderrLimit, runner.policy.AggregateLimit, func() {
		cancelRun(errOutputLimit)
	})
	controller, err := newProcessController(runner.policy.TerminationGrace, processGuard)
	if err != nil {
		return Result{}, &Error{Code: CodeProcessBoundary, Detail: "could not initialize guarded descendant tracking", Cause: err}
	}
	startAttemptedAt := time.Now().UTC()
	command, err := prepared.StartContext(runContext, func(command *exec.Cmd) error {
		command.Dir = request.WorkingDirectory
		command.Env = slices.Clone(environment)
		command.Stdin = nil
		command.Stdout = collector.stdoutWriter()
		command.Stderr = collector.stderrWriter()
		command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
		command.WaitDelay = runner.policy.TerminationGrace + forcedCleanupWait + processPipeWait
		command.Cancel = func() error {
			if command.Process == nil {
				return os.ErrProcessDone
			}
			return controller.cancel(command.Process.Pid)
		}
		return nil
	}, "--config", request.ConfigurationPath)
	if err != nil {
		// A retained runtime handle can report an error after Start succeeds.
		// Runtime kills and waits the leader before returning that error, but a
		// child created in the Start-to-close window may already have escaped its
		// process group. The guarded subreaper boundary remains available without
		// a command handle, so always perform operation-marker cleanup here too.
		_ = controller.finish()
		stdout, stderr, _ := collector.take()
		clear(stdout)
		clear(stderr)
		// runtime.PreparedExecutable can report an error after command.Start
		// succeeds (for example, if releasing the retained parent descriptor
		// fails). Without a command handle the broker cannot prove that no native
		// or external change occurred, so every StartContext error is conservative.
		return Result{
			Outcome: OutcomeAmbiguous, Started: true, StartedAt: startAttemptedAt,
			FinishedAt: time.Now().UTC(), Termination: controller.terminationState(),
			OutputDiscarded: true, MayHaveChanged: true,
		}, &Error{Code: CodeStartFailed, Detail: "constrained lego start has uncertain completion", Cause: err}
	}
	result.Started = true
	result.MayHaveChanged = true
	result.StartedAt = startAttemptedAt
	controller.start(command.Process.Pid)

	waitErr := command.Wait()
	cause := context.Cause(runContext)
	cleanupUncertain := controller.finish()
	result.FinishedAt = time.Now().UTC()
	result.Termination = controller.terminationState()
	result.ExitCode, result.ExitCodeKnown, result.TermSignal = processExit(command.ProcessState)
	clear(command.Env)
	command.Env = nil
	command.Stdout = nil
	command.Stderr = nil

	stdout, stderr, overflowed := collector.take()
	if overflowed {
		clear(stdout)
		clear(stderr)
		result.OutputDiscarded = true
	} else {
		redactedStdout := filter.Bytes(stdout)
		redactedStderr := filter.Bytes(stderr)
		clear(stdout)
		clear(stderr)
		sanitizedStdout := sanitizeOutput(redactedStdout)
		sanitizedStderr := sanitizeOutput(redactedStderr)
		clear(redactedStdout)
		clear(redactedStderr)
		// Sanitization can turn a control byte into '?' and thereby recreate an
		// observed secret that did not exist in the raw stream. Redact the safe
		// bytes a second time before converting them to immutable result text.
		finalStdout := filter.Bytes(sanitizedStdout)
		finalStderr := filter.Bytes(sanitizedStderr)
		clear(sanitizedStdout)
		clear(sanitizedStderr)
		result.Stdout = string(finalStdout)
		result.Stderr = string(finalStderr)
		clear(finalStdout)
		clear(finalStderr)
	}

	switch {
	case cleanupUncertain:
		result.Outcome = OutcomeAmbiguous
	case errors.Is(waitErr, exec.ErrWaitDelay):
		result.Outcome = OutcomeAmbiguous
	case overflowed || errors.Is(cause, errOutputLimit):
		result.Outcome = OutcomeOutputLimit
	case controller.cancelRequested() && errors.Is(cause, errHardTimeout):
		result.Outcome = OutcomeTimedOut
	case controller.cancelRequested() && cause != nil:
		result.Outcome = OutcomeInterrupted
	case waitErr == nil && command.ProcessState != nil && command.ProcessState.Success():
		result.Outcome = OutcomeSucceeded
	default:
		result.Outcome = OutcomeFailed
	}
	return result, nil
}

func validateCanonicalPath(value string, directory bool) error {
	if value == "" || len(value) > maximumPathBytes || !utf8.ValidString(value) {
		return &Error{Code: CodeInvalidPath, Detail: "native path has an invalid length or encoding"}
	}
	if strings.IndexFunc(value, func(character rune) bool { return character < 0x20 || character == 0x7f }) >= 0 {
		return &Error{Code: CodeInvalidPath, Detail: "native path contains control text"}
	}
	if !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return &Error{Code: CodeInvalidPath, Detail: "native path must be canonical and absolute"}
	}
	if !directory && filepath.Base(value) == string(filepath.Separator) {
		return &Error{Code: CodeInvalidPath, Detail: "configuration path must name a file"}
	}
	return nil
}

func (runner *Runner) prepareEnvironmentAndSecrets(request Request) ([]string, [][]byte, error) {
	if len(request.Environment) > runner.policy.MaximumEnvironment {
		return nil, nil, &Error{Code: CodeInvalidEnvironment, Detail: "too many environment entries"}
	}
	if len(request.ObservedSecrets) > runner.policy.MaximumSecrets {
		return nil, nil, &Error{Code: CodeRedactionFailed, Detail: "too many observed secret values"}
	}

	ownedValues := make(map[string][]byte, len(request.Environment))
	sensitiveNames := make(map[string]bool, len(request.Environment))
	environmentTotal := 0
	for _, variable := range request.Environment {
		if !environmentNamePattern.MatchString(variable.Name) || variable.Name == "LANG" || variable.Name == "LC_ALL" || variable.Name == "TZ" {
			clearByteMap(ownedValues)
			return nil, nil, &Error{Code: CodeInvalidEnvironment, Detail: "environment name is invalid, duplicate, or reserved"}
		}
		if _, duplicate := ownedValues[variable.Name]; duplicate {
			clearByteMap(ownedValues)
			return nil, nil, &Error{Code: CodeInvalidEnvironment, Detail: "environment name is invalid, duplicate, or reserved"}
		}
		if len(variable.Value) > runner.policy.MaximumEnvironmentBytes || bytesContainNUL(variable.Value) || !utf8.Valid(variable.Value) {
			clearByteMap(ownedValues)
			return nil, nil, &Error{Code: CodeInvalidEnvironment, Detail: "environment value is outside the process contract"}
		}
		environmentTotal += len(variable.Name) + 1 + len(variable.Value)
		if environmentTotal > runner.policy.MaximumEnvironmentTotal {
			clearByteMap(ownedValues)
			return nil, nil, &Error{Code: CodeInvalidEnvironment, Detail: "environment entries exceed the aggregate bound"}
		}
		ownedValues[variable.Name] = slices.Clone(variable.Value)
		sensitiveNames[variable.Name] = variable.Sensitive
	}

	names := make([]string, 0, len(ownedValues))
	for name := range ownedValues {
		names = append(names, name)
	}
	sort.Strings(names)
	environment := slices.Clone(fixedEnvironment)
	secrets := make([][]byte, 0, len(request.ObservedSecrets)+len(names))
	secretTotal := 0
	for _, value := range request.ObservedSecrets {
		if len(value) == 0 {
			continue
		}
		if len(value) > runner.policy.MaximumSecretBytes {
			clearByteMap(ownedValues)
			clearByteSlices(secrets)
			return nil, nil, &Error{Code: CodeRedactionFailed, Detail: "observed secret value exceeds the per-value bound"}
		}
		secretTotal += len(value)
		if secretTotal > runner.policy.MaximumSecretTotal {
			clearByteMap(ownedValues)
			clearByteSlices(secrets)
			return nil, nil, &Error{Code: CodeRedactionFailed, Detail: "observed secret values exceed the aggregate bound"}
		}
		secrets = append(secrets, slices.Clone(value))
	}
	for _, name := range names {
		value := ownedValues[name]
		environment = append(environment, name+"="+string(value))
		if sensitiveNames[name] && len(value) != 0 {
			if len(secrets) >= runner.policy.MaximumSecrets || len(value) > runner.policy.MaximumSecretBytes || secretTotal+len(value) > runner.policy.MaximumSecretTotal {
				clearByteMap(ownedValues)
				clearByteSlices(secrets)
				clear(environment)
				return nil, nil, &Error{Code: CodeRedactionFailed, Detail: "sensitive environment values exceed the redaction bound"}
			}
			secretTotal += len(value)
			secrets = append(secrets, slices.Clone(value))
		}
	}
	clearByteMap(ownedValues)
	return environment, secrets, nil
}

func clearOwnedEnvironment(environment []string, secrets [][]byte) {
	clear(environment)
	clearByteSlices(secrets)
}

func clearByteMap(values map[string][]byte) {
	for key, value := range values {
		clear(value)
		delete(values, key)
	}
}

func clearByteSlices(values [][]byte) {
	for index := range values {
		clear(values[index])
		values[index] = nil
	}
	clear(values)
}

func bytesContainNUL(value []byte) bool {
	for _, item := range value {
		if item == 0 {
			return true
		}
	}
	return false
}

func processExit(state *os.ProcessState) (exitCode int, known bool, signal string) {
	if state == nil {
		return 0, false, ""
	}
	status, ok := state.Sys().(syscall.WaitStatus)
	if !ok {
		if code := state.ExitCode(); code >= 0 {
			return code, true, ""
		}
		return 0, false, ""
	}
	if status.Exited() {
		return status.ExitStatus(), true, ""
	}
	if status.Signaled() {
		return 0, false, signalName(status.Signal())
	}
	return 0, false, ""
}

func signalName(signal syscall.Signal) string {
	switch signal {
	case syscall.SIGTERM:
		return "SIGTERM"
	case syscall.SIGKILL:
		return "SIGKILL"
	case syscall.SIGINT:
		return "SIGINT"
	case syscall.SIGHUP:
		return "SIGHUP"
	case syscall.SIGQUIT:
		return "SIGQUIT"
	default:
		return fmt.Sprintf("SIG%d", signal)
	}
}
