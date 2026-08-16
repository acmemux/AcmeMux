//go:build linux

package broker

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	helperSecret          = "broker-secret-canary"
	helperSanitizedSecret = "recreated?secret"
)

var (
	helperBehavior = flag.String("broker-helper", "", "internal broker test helper")
	helperPIDFile  = flag.String("broker-helper-pid-file", "", "internal broker test PID file")
)

func TestRunnerUsesExactFileModeContractAndRedactsBeforeSanitizing(t *testing.T) {
	fixture := newRunnerFixture(t, "contract")
	request := fixture.request()
	request.Environment = []Variable{
		{Name: "PATH", Value: []byte("/test/bin")},
		{Name: "API_TOKEN", Value: []byte(helperSecret), Sensitive: true},
	}
	request.ObservedSecrets = [][]byte{[]byte(helperSecret), []byte(helperSanitizedSecret)}

	result, err := fixture.runner.Run(context.Background(), request)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Outcome != OutcomeSucceeded || !result.Started || !result.ExitCodeKnown || result.ExitCode != 0 {
		t.Fatalf("Run() result = %#v", result)
	}
	if !result.MayHaveChanged || result.OutputDiscarded || result.Termination != TerminationNone || result.TermSignal != "" {
		t.Fatalf("Run() process evidence = %#v", result)
	}
	if result.StartedAt.IsZero() || result.FinishedAt.Before(result.StartedAt) || result.StartedAt.Location() != time.UTC || result.FinishedAt.Location() != time.UTC {
		t.Fatalf("Run() timestamps = %v -> %v", result.StartedAt, result.FinishedAt)
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(helperSecret))
	if strings.Contains(result.Stdout, helperSecret) || strings.Contains(result.Stderr, encoded) {
		t.Fatalf("Run() leaked observed secret: stdout %q stderr %q", result.Stdout, result.Stderr)
	}
	if strings.Contains(result.Stdout, helperSanitizedSecret) {
		t.Fatalf("Run() recreated a secret while sanitizing: %q", result.Stdout)
	}
	if strings.ContainsRune(result.Stdout, '\x1b') || !strings.Contains(result.Stdout, "?") {
		t.Fatalf("Run() did not sanitize child controls and invalid UTF-8: %q", result.Stdout)
	}

	fixture.prepared.mu.Lock()
	defer fixture.prepared.mu.Unlock()
	if !slices.Equal(fixture.prepared.arguments, []string{"--config", fixture.configuration}) {
		t.Fatalf("StartContext arguments = %q", fixture.prepared.arguments)
	}
	if fixture.prepared.directory != fixture.workingDirectory {
		t.Fatalf("command directory = %q", fixture.prepared.directory)
	}
	wantEnvironment := []string{"LANG=C", "LC_ALL=C", "TZ=UTC", "API_TOKEN=" + helperSecret, "PATH=/test/bin"}
	if len(fixture.prepared.environment) != len(wantEnvironment)+1 ||
		!slices.Equal(fixture.prepared.environment[:len(wantEnvironment)], wantEnvironment) ||
		!strings.HasPrefix(fixture.prepared.environment[len(wantEnvironment)], processGuardPrefix+"_") ||
		!strings.HasSuffix(fixture.prepared.environment[len(wantEnvironment)], "=1") {
		t.Fatalf("command environment = %q, want %q plus one guarded lineage marker", fixture.prepared.environment, wantEnvironment)
	}
	if fixture.prepared.sysProcAttr == nil || !fixture.prepared.sysProcAttr.Setpgid || fixture.prepared.sysProcAttr.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("command process controls = %#v", fixture.prepared.sysProcAttr)
	}
	if !fixture.prepared.cancelSet || fixture.prepared.waitDelay <= fixture.runner.policy.TerminationGrace {
		t.Fatalf("command cancellation controls = cancel %t delay %v", fixture.prepared.cancelSet, fixture.prepared.waitDelay)
	}
	if fixture.prepared.startCount != 1 || fixture.prepared.closeCount != 1 {
		t.Fatalf("prepared lifecycle = start %d close %d", fixture.prepared.startCount, fixture.prepared.closeCount)
	}
}

func TestRunnerDoesNotInterpretConfigurationPathAsShell(t *testing.T) {
	fixture := newRunnerFixture(t, "success")
	marker := filepath.Join(fixture.workingDirectory, "shell-marker")
	fixture.configuration = filepath.Join(fixture.workingDirectory, "$(touch shell-marker); configuration.yml")
	result, err := fixture.runner.Run(context.Background(), fixture.request())
	if err != nil || result.Outcome != OutcomeSucceeded {
		t.Fatalf("Run() = %#v, %v", result, err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("shell-looking path created marker: %v", err)
	}
	if !slices.Equal(fixture.prepared.arguments, []string{"--config", fixture.configuration}) {
		t.Fatalf("StartContext arguments = %q", fixture.prepared.arguments)
	}
}

func TestRunnerRejectsInvalidInputsBeforeStartAndClosesPrepared(t *testing.T) {
	tests := map[string]func(*runnerFixture, *Request){
		"relative working directory": func(_ *runnerFixture, request *Request) {
			request.WorkingDirectory = "relative"
		},
		"unclean configuration": func(_ *runnerFixture, request *Request) {
			request.ConfigurationPath += "/../config.yml"
		},
		"reserved environment": func(_ *runnerFixture, request *Request) {
			request.Environment = []Variable{{Name: "LANG", Value: []byte("en_US.UTF-8")}}
		},
		"duplicate environment": func(_ *runnerFixture, request *Request) {
			request.Environment = []Variable{{Name: "TOKEN", Value: []byte("one")}, {Name: "TOKEN", Value: []byte("two")}}
		},
		"invalid environment name": func(_ *runnerFixture, request *Request) {
			request.Environment = []Variable{{Name: "lowercase", Value: []byte("value")}}
		},
		"NUL environment value": func(_ *runnerFixture, request *Request) {
			request.Environment = []Variable{{Name: "TOKEN", Value: []byte{'a', 0, 'b'}}}
		},
		"invalid UTF-8 environment value": func(_ *runnerFixture, request *Request) {
			request.Environment = []Variable{{Name: "TOKEN", Value: []byte{0xff}}}
		},
		"oversized secret": func(fixture *runnerFixture, request *Request) {
			fixture.runner.policy.MaximumSecretBytes = 4
			request.ObservedSecrets = [][]byte{[]byte("12345")}
		},
	}

	for name, arrange := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newRunnerFixture(t, "success")
			request := fixture.request()
			arrange(&fixture, &request)
			_, err := fixture.runner.Run(context.Background(), request)
			if err == nil {
				t.Fatal("Run() error = nil")
			}
			fixture.prepared.mu.Lock()
			defer fixture.prepared.mu.Unlock()
			if fixture.prepared.startCount != 0 || fixture.prepared.closeCount != 1 {
				t.Fatalf("prepared lifecycle = start %d close %d", fixture.prepared.startCount, fixture.prepared.closeCount)
			}
		})
	}
}

func TestRunnerClassifiesNonzeroExitWithoutReturningAnError(t *testing.T) {
	fixture := newRunnerFixture(t, "exit-seven")
	request := fixture.request()
	request.ObservedSecrets = [][]byte{[]byte(helperSecret)}
	result, err := fixture.runner.Run(context.Background(), request)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Outcome != OutcomeFailed || !result.ExitCodeKnown || result.ExitCode != 7 || result.Termination != TerminationNone {
		t.Fatalf("Run() result = %#v", result)
	}
	if strings.Contains(result.Stderr, helperSecret) {
		t.Fatalf("Run() leaked failed child output: %q", result.Stderr)
	}
}

func TestRunnerDiscardsAllOutputAndKillsOnAnyLimit(t *testing.T) {
	fixture := newRunnerFixture(t, "flood")
	policy := fixture.runner.policy
	policy.StdoutLimit = 64
	policy.StderrLimit = 64
	policy.AggregateLimit = 128
	policy.TerminationGrace = 50 * time.Millisecond
	fixture.runner = mustRunner(t, policy)

	result, err := fixture.runner.Run(context.Background(), fixture.request())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Outcome != OutcomeOutputLimit || !result.OutputDiscarded || result.Stdout != "" || result.Stderr != "" {
		t.Fatalf("Run() result = %#v", result)
	}
	if result.Termination != TerminationForced || result.TermSignal != "SIGKILL" {
		t.Fatalf("Run() termination = %#v", result)
	}
}

func TestRunnerTimesOutAndTerminatesOrdinaryProcessTree(t *testing.T) {
	fixture := newRunnerFixture(t, "tree-root")
	fixture.prepared.pidFile = filepath.Join(fixture.workingDirectory, "tree-pids")
	policy := fixture.runner.policy
	policy.Timeout = 350 * time.Millisecond
	policy.TerminationGrace = 75 * time.Millisecond
	fixture.runner = mustRunner(t, policy)

	result, err := fixture.runner.Run(context.Background(), fixture.request())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Outcome != OutcomeTimedOut || result.Termination != TerminationForced || !result.MayHaveChanged {
		t.Fatalf("Run() result = %#v", result)
	}
	assertRecordedProcessesGone(t, fixture.prepared.pidFile)
}

func TestRunnerTracksAndTerminatesChildThatEscapesProcessGroup(t *testing.T) {
	fixture := newRunnerFixture(t, "escaped-timeout-root")
	fixture.prepared.pidFile = filepath.Join(fixture.workingDirectory, "escaped-pids")
	policy := fixture.runner.policy
	policy.Timeout = 600 * time.Millisecond
	policy.TerminationGrace = 75 * time.Millisecond
	fixture.runner = mustRunner(t, policy)

	result, err := fixture.runner.Run(context.Background(), fixture.request())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Outcome != OutcomeTimedOut || result.Termination != TerminationForced {
		t.Fatalf("Run() result = %#v", result)
	}
	assertRecordedProcessesGone(t, fixture.prepared.pidFile)
}

func TestRunnerReportsAmbiguousWhenSuccessfulLeaderLeavesSurvivor(t *testing.T) {
	fixture := newRunnerFixture(t, "escaped-survivor-root")
	fixture.prepared.pidFile = filepath.Join(fixture.workingDirectory, "survivor-pids")
	policy := fixture.runner.policy
	policy.Timeout = 5 * time.Second
	policy.TerminationGrace = 75 * time.Millisecond
	fixture.runner = mustRunner(t, policy)

	result, err := fixture.runner.Run(context.Background(), fixture.request())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Outcome != OutcomeAmbiguous || result.Termination != TerminationForced || !result.MayHaveChanged {
		t.Fatalf("Run() result = %#v", result)
	}
	assertRecordedProcessesGone(t, fixture.prepared.pidFile)
}

func TestRunnerTracksChildForkedByNonleaderThread(t *testing.T) {
	fixture := newRunnerFixture(t, "thread-survivor-root")
	fixture.prepared.pidFile = filepath.Join(fixture.workingDirectory, "thread-survivor-pids")
	policy := fixture.runner.policy
	policy.Timeout = 5 * time.Second
	policy.TerminationGrace = 75 * time.Millisecond
	fixture.runner = mustRunner(t, policy)

	result, err := fixture.runner.Run(context.Background(), fixture.request())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Outcome != OutcomeAmbiguous || result.Termination != TerminationForced {
		t.Fatalf("Run() result = %#v", result)
	}
	assertRecordedProcessesGone(t, fixture.prepared.pidFile)
}

func TestRunnerMarksImmediateDetachedInheritedPipeAmbiguous(t *testing.T) {
	fixture := newRunnerFixture(t, "thread-immediate-detach-root")
	fixture.prepared.pidFile = filepath.Join(fixture.workingDirectory, "immediate-detach-pids")
	t.Cleanup(func() { killRecordedProcesses(fixture.prepared.pidFile) })
	policy := fixture.runner.policy
	policy.Timeout = 5 * time.Second
	policy.TerminationGrace = 50 * time.Millisecond
	fixture.runner = mustRunner(t, policy)

	result, err := fixture.runner.Run(context.Background(), fixture.request())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Outcome != OutcomeAmbiguous || !result.MayHaveChanged {
		t.Fatalf("Run() result = %#v", result)
	}
	if fields := readRecordedPIDFields(t, fixture.prepared.pidFile); len(fields) < 2 {
		t.Fatalf("recorded PIDs = %q", fields)
	}
}

func TestRunnerTerminatesImmediateDetachedChildWithoutInheritedPipes(t *testing.T) {
	fixture := newRunnerFixture(t, "thread-immediate-detach-no-pipe-root")
	fixture.prepared.pidFile = filepath.Join(fixture.workingDirectory, "immediate-detach-no-pipe-pids")
	policy := fixture.runner.policy
	policy.Timeout = 5 * time.Second
	policy.TerminationGrace = 50 * time.Millisecond
	fixture.runner = mustRunner(t, policy)

	result, err := fixture.runner.Run(context.Background(), fixture.request())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Outcome != OutcomeAmbiguous || result.Termination != TerminationForced || !result.MayHaveChanged {
		t.Fatalf("Run() result = %#v", result)
	}
	assertRecordedProcessesGone(t, fixture.prepared.pidFile)
}

func TestRunnerLeavesUnrelatedDirectChildToItsOwner(t *testing.T) {
	unrelated := exec.Command(os.Args[0],
		"-test.run=^TestBrokerHelperProcess$", "-broker-helper=unrelated-sleep",
		"-broker-helper-pid-file=", "--", "--config", "/tmp/helper-config.yml",
	)
	if err := unrelated.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = unrelated.Process.Kill()
			_ = unrelated.Wait()
		}
	})

	fixture := newRunnerFixture(t, "thread-immediate-detach-no-pipe-root")
	fixture.prepared.pidFile = filepath.Join(fixture.workingDirectory, "coordinated-detach-pids")
	policy := fixture.runner.policy
	policy.Timeout = 5 * time.Second
	policy.TerminationGrace = 50 * time.Millisecond
	fixture.runner = mustRunner(t, policy)
	result, err := fixture.runner.Run(context.Background(), fixture.request())
	if err != nil || result.Outcome != OutcomeAmbiguous {
		t.Fatalf("Run() = %#v, %v", result, err)
	}
	assertRecordedProcessesGone(t, fixture.prepared.pidFile)
	if err := syscall.Kill(unrelated.Process.Pid, 0); err != nil {
		t.Fatalf("unrelated child did not survive broker cleanup: %v", err)
	}
	if err := unrelated.Process.Kill(); err != nil {
		t.Fatalf("kill unrelated child: %v", err)
	}
	if err := unrelated.Wait(); err == nil {
		t.Fatal("unrelated child unexpectedly reported successful exit")
	} else if !strings.Contains(err.Error(), "signal: killed") {
		t.Fatalf("unrelated child wait status was consumed elsewhere: %v", err)
	}
	waited = true
}

func TestRunnerPinsCreatorOSThreadForPdeathsigLifetime(t *testing.T) {
	originalLock, originalUnlock := lockCreatorOSThread, unlockCreatorOSThread
	defer func() {
		lockCreatorOSThread, unlockCreatorOSThread = originalLock, originalUnlock
	}()
	var mu sync.Mutex
	lockCount, unlockCount := 0, 0
	lockCreatorOSThread = func() {
		originalLock()
		mu.Lock()
		lockCount++
		mu.Unlock()
	}
	unlockCreatorOSThread = func() {
		mu.Lock()
		unlockCount++
		mu.Unlock()
		originalUnlock()
	}

	fixture := newRunnerFixture(t, "success")
	result, err := fixture.runner.Run(context.Background(), fixture.request())
	if err != nil || result.Outcome != OutcomeSucceeded {
		t.Fatalf("Run() = %#v, %v", result, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if lockCount != 1 || unlockCount != 1 {
		t.Fatalf("creator OS thread lifecycle = lock %d unlock %d", lockCount, unlockCount)
	}
}

func TestRunnerMapsServiceContextCancellationToInterrupted(t *testing.T) {
	fixture := newRunnerFixture(t, "sleep")
	contextValue, cancel := context.WithCancel(context.Background())
	resultChannel := make(chan struct {
		result Result
		err    error
	}, 1)
	go func() {
		result, err := fixture.runner.Run(contextValue, fixture.request())
		resultChannel <- struct {
			result Result
			err    error
		}{result: result, err: err}
	}()
	select {
	case <-fixture.prepared.started:
	case <-time.After(5 * time.Second):
		t.Fatal("process did not start")
	}
	cancel()
	response := <-resultChannel
	if response.err != nil {
		t.Fatalf("Run() error = %v", response.err)
	}
	if response.result.Outcome != OutcomeInterrupted || response.result.Termination == TerminationNone {
		t.Fatalf("Run() result = %#v", response.result)
	}
}

func TestRunnerReturnsStableStartAndCloseErrors(t *testing.T) {
	t.Run("start", func(t *testing.T) {
		fixture := newRunnerFixture(t, "success")
		fixture.prepared.startErr = errors.New("input-derived start failure /secret/path")
		_, err := fixture.runner.Run(context.Background(), fixture.request())
		if CodeOf(err) != CodeStartFailed || strings.Contains(err.Error(), "secret") {
			t.Fatalf("Run() error = %v", err)
		}
		if fixture.prepared.closeCount != 1 {
			t.Fatalf("Close() count = %d", fixture.prepared.closeCount)
		}
	})

	t.Run("error after child start", func(t *testing.T) {
		fixture := newRunnerFixture(t, "success")
		fixture.prepared.errorAfterStart = errors.New("retained descriptor close failed")
		result, err := fixture.runner.Run(context.Background(), fixture.request())
		if CodeOf(err) != CodeStartFailed || result.Outcome != OutcomeAmbiguous || !result.Started || !result.MayHaveChanged || !result.OutputDiscarded {
			t.Fatalf("Run() = %#v, %v", result, err)
		}
		if fixture.prepared.startCount != 1 || fixture.prepared.closeCount != 1 {
			t.Fatalf("prepared lifecycle = start %d close %d", fixture.prepared.startCount, fixture.prepared.closeCount)
		}
	})

	t.Run("error after descendant escapes", func(t *testing.T) {
		fixture := newRunnerFixture(t, "post-start-error-root")
		fixture.prepared.pidFile = filepath.Join(fixture.workingDirectory, "post-start-error-pids")
		fixture.prepared.errorAfterStart = errors.New("retained descriptor close failed")
		policy := fixture.runner.policy
		policy.TerminationGrace = 50 * time.Millisecond
		fixture.runner = mustRunner(t, policy)

		result, err := fixture.runner.Run(context.Background(), fixture.request())
		if CodeOf(err) != CodeStartFailed || result.Outcome != OutcomeAmbiguous || result.Termination != TerminationForced || !result.MayHaveChanged {
			t.Fatalf("Run() = %#v, %v", result, err)
		}
		assertRecordedProcessesGone(t, fixture.prepared.pidFile)
	})

	t.Run("close", func(t *testing.T) {
		fixture := newRunnerFixture(t, "success")
		fixture.prepared.closeErr = errors.New("close detail")
		result, err := fixture.runner.Run(context.Background(), fixture.request())
		if result.Outcome != OutcomeSucceeded || CodeOf(err) != CodePreparedCloseFailed {
			t.Fatalf("Run() = %#v, %v", result, err)
		}
		if fixture.prepared.closeCount != 1 {
			t.Fatalf("Close() count = %d", fixture.prepared.closeCount)
		}
	})
}

func TestNewRunnerRejectsIncompleteOrExcessivePolicy(t *testing.T) {
	tests := map[string]func(*Policy){
		"timeout":               func(policy *Policy) { policy.Timeout = maximumTimeout + time.Second },
		"grace":                 func(policy *Policy) { policy.TerminationGrace = 0 },
		"stdout":                func(policy *Policy) { policy.StdoutLimit = 0 },
		"aggregate":             func(policy *Policy) { policy.AggregateLimit = policy.StdoutLimit - 1 },
		"environment count":     func(policy *Policy) { policy.MaximumEnvironment = 0 },
		"environment bytes":     func(policy *Policy) { policy.MaximumEnvironmentBytes = maximumEnvironmentByte + 1 },
		"environment aggregate": func(policy *Policy) { policy.MaximumEnvironmentTotal = 0 },
		"secret count":          func(policy *Policy) { policy.MaximumSecrets = 0 },
		"secret bytes":          func(policy *Policy) { policy.MaximumSecretBytes = maximumSecretByte + 1 },
		"secret aggregate":      func(policy *Policy) { policy.MaximumSecretTotal = 0 },
	}
	for name, adjust := range tests {
		t.Run(name, func(t *testing.T) {
			policy := DefaultPolicy()
			adjust(&policy)
			if _, err := NewRunner(policy); CodeOf(err) != CodeInvalidPolicy {
				t.Fatalf("NewRunner() error = %v", err)
			}
		})
	}
}

type runnerFixture struct {
	runner           *Runner
	prepared         *helperPrepared
	workingDirectory string
	configuration    string
}

func newRunnerFixture(t *testing.T, behavior string) runnerFixture {
	t.Helper()
	workingDirectory := t.TempDir()
	if err := os.Chmod(workingDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	return runnerFixture{
		runner:           mustRunner(t, DefaultPolicy()),
		prepared:         &helperPrepared{behavior: behavior, started: make(chan struct{})},
		workingDirectory: workingDirectory,
		configuration:    filepath.Join(workingDirectory, "workspace.yml"),
	}
}

func (fixture runnerFixture) request() Request {
	return Request{
		Prepared: fixture.prepared, WorkingDirectory: fixture.workingDirectory,
		ConfigurationPath: fixture.configuration,
	}
}

func mustRunner(t *testing.T, policy Policy) *Runner {
	t.Helper()
	runner, err := NewRunner(policy)
	if err != nil {
		t.Fatal(err)
	}
	return runner
}

type helperPrepared struct {
	mu sync.Mutex

	behavior        string
	pidFile         string
	started         chan struct{}
	startErr        error
	errorAfterStart error
	closeErr        error

	arguments   []string
	directory   string
	environment []string
	sysProcAttr *syscall.SysProcAttr
	waitDelay   time.Duration
	cancelSet   bool
	startCount  int
	closeCount  int
}

func (prepared *helperPrepared) StartContext(
	ctx context.Context,
	configure func(*exec.Cmd) error,
	arguments ...string,
) (*exec.Cmd, error) {
	commandArguments := []string{
		"-test.run=^TestBrokerHelperProcess$", "-broker-helper=" + prepared.behavior,
		"-broker-helper-pid-file=" + prepared.pidFile, "--",
	}
	commandArguments = append(commandArguments, arguments...)
	command := exec.CommandContext(ctx, os.Args[0], commandArguments...)
	if err := configure(command); err != nil {
		return nil, err
	}

	prepared.mu.Lock()
	prepared.arguments = slices.Clone(arguments)
	prepared.directory = command.Dir
	prepared.environment = slices.Clone(command.Env)
	if command.SysProcAttr != nil {
		copy := *command.SysProcAttr
		prepared.sysProcAttr = &copy
	}
	prepared.waitDelay = command.WaitDelay
	prepared.cancelSet = command.Cancel != nil
	startErr := prepared.startErr
	prepared.mu.Unlock()
	if startErr != nil {
		return nil, startErr
	}
	if err := command.Start(); err != nil {
		return nil, err
	}
	prepared.mu.Lock()
	prepared.startCount++
	select {
	case <-prepared.started:
	default:
		close(prepared.started)
	}
	prepared.mu.Unlock()
	if prepared.errorAfterStart != nil {
		if prepared.behavior == "post-start-error-root" {
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				value, _ := os.ReadFile(prepared.pidFile)
				if len(strings.Fields(string(value))) >= 2 {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		_ = command.Process.Kill()
		_ = command.Wait()
		return nil, prepared.errorAfterStart
	}
	return command, nil
}

func (prepared *helperPrepared) Close() error {
	prepared.mu.Lock()
	defer prepared.mu.Unlock()
	prepared.closeCount++
	return prepared.closeErr
}

func TestBrokerHelperProcess(t *testing.T) {
	if *helperBehavior == "" {
		return
	}
	arguments := helperBrokerArguments(os.Args)
	if len(arguments) != 2 || arguments[0] != "--config" || !filepath.IsAbs(arguments[1]) {
		os.Exit(96)
	}

	switch *helperBehavior {
	case "success":
		os.Exit(0)
	case "contract":
		_, _ = os.Stdout.Write([]byte("stdout broker-sec"))
		time.Sleep(10 * time.Millisecond)
		_, _ = os.Stdout.Write([]byte("ret-canary\x1b[31m\xff recreated\x00secret\n"))
		encoded := base64.StdEncoding.EncodeToString([]byte(helperSecret))
		_, _ = os.Stderr.Write([]byte("stderr " + encoded[:len(encoded)/2]))
		time.Sleep(10 * time.Millisecond)
		_, _ = os.Stderr.Write([]byte(encoded[len(encoded)/2:] + "\n"))
		os.Exit(0)
	case "exit-seven":
		_, _ = fmt.Fprintln(os.Stderr, "failed with", helperSecret)
		os.Exit(7)
	case "flood":
		ignoreTerminationSignal()
		value := []byte(strings.Repeat("x", 4096))
		for {
			_, _ = os.Stdout.Write(value)
		}
	case "sleep":
		time.Sleep(time.Hour)
	case "tree-root":
		ignoreTerminationSignal()
		startHelperChild("tree-child", *helperPIDFile, false)
		recordHelperPID(*helperPIDFile, os.Getpid())
		time.Sleep(time.Hour)
	case "tree-child":
		ignoreTerminationSignal()
		startHelperChild("sleep-child", *helperPIDFile, false)
		recordHelperPID(*helperPIDFile, os.Getpid())
		time.Sleep(time.Hour)
	case "sleep-child":
		ignoreTerminationSignal()
		recordHelperPID(*helperPIDFile, os.Getpid())
		time.Sleep(time.Hour)
	case "escaped-timeout-root":
		ignoreTerminationSignal()
		startHelperChild("escaped-child", *helperPIDFile, true)
		recordHelperPID(*helperPIDFile, os.Getpid())
		waitForRecordedPIDCount(*helperPIDFile, 2)
		time.Sleep(time.Hour)
	case "escaped-survivor-root":
		startHelperChild("escaped-child", *helperPIDFile, true)
		recordHelperPID(*helperPIDFile, os.Getpid())
		waitForRecordedPIDCount(*helperPIDFile, 2)
		// Let the broker's bounded procfs tracker bind the escaped child before
		// this otherwise-successful leader exits.
		time.Sleep(250 * time.Millisecond)
		os.Exit(0)
	case "thread-survivor-root":
		startHelperChildFromNonleader("escaped-child", *helperPIDFile, false)
		recordHelperPID(*helperPIDFile, os.Getpid())
		waitForRecordedPIDCount(*helperPIDFile, 2)
		time.Sleep(250 * time.Millisecond)
		os.Exit(0)
	case "thread-immediate-detach-root":
		startHelperChildFromNonleader("escaped-child", *helperPIDFile, true)
		recordHelperPID(*helperPIDFile, os.Getpid())
		waitForRecordedPIDCount(*helperPIDFile, 2)
		os.Exit(0)
	case "thread-immediate-detach-no-pipe-root":
		startHelperChildFromNonleader("escaped-child", *helperPIDFile, false)
		recordHelperPID(*helperPIDFile, os.Getpid())
		waitForRecordedPIDCount(*helperPIDFile, 2)
		os.Exit(0)
	case "post-start-error-root":
		startHelperChildFromNonleader("escaped-child", *helperPIDFile, false)
		recordHelperPID(*helperPIDFile, os.Getpid())
		waitForRecordedPIDCount(*helperPIDFile, 2)
		time.Sleep(time.Hour)
	case "escaped-child":
		ignoreTerminationSignal()
		recordHelperPID(*helperPIDFile, os.Getpid())
		time.Sleep(time.Hour)
	case "unrelated-sleep":
		time.Sleep(time.Hour)
	default:
		os.Exit(95)
	}
}

func helperBrokerArguments(arguments []string) []string {
	for index, argument := range arguments {
		if argument == "--" {
			return slices.Clone(arguments[index+1:])
		}
	}
	return nil
}

func startHelperChild(behavior, pidFile string, newSession bool) {
	startHelperChildWithOptions(behavior, pidFile, newSession, false)
}

func startHelperChildFromNonleader(behavior, pidFile string, inheritPipes bool) {
	started := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		startHelperChildWithOptions(behavior, pidFile, true, inheritPipes)
		close(started)
	}()
	<-started
}

func startHelperChildWithOptions(behavior, pidFile string, newSession, inheritPipes bool) {
	arguments := []string{
		"-test.run=^TestBrokerHelperProcess$", "-broker-helper=" + behavior,
		"-broker-helper-pid-file=" + pidFile, "--", "--config", "/tmp/helper-config.yml",
	}
	command := exec.Command(os.Args[0], arguments...)
	if newSession {
		command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	}
	if inheritPipes {
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
	}
	if err := command.Start(); err != nil {
		os.Exit(94)
	}
}

func ignoreTerminationSignal() {
	// Ignoring SIGTERM forces the broker to exercise its bounded SIGKILL path.
	signal.Ignore(syscall.SIGTERM)
}

func recordHelperPID(path string, pid int) {
	if path == "" {
		return
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		os.Exit(92)
	}
	_, writeErr := fmt.Fprintln(file, pid)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		os.Exit(91)
	}
}

func waitForRecordedPIDCount(path string, count int) {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		value, _ := os.ReadFile(path)
		if len(strings.Fields(string(value))) >= count {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	os.Exit(90)
}

func assertRecordedProcessesGone(t *testing.T, path string) {
	t.Helper()
	fields := readRecordedPIDFields(t, path)
	if len(fields) < 2 {
		t.Fatalf("recorded PIDs = %q", fields)
	}
	deadline := time.Now().Add(3 * time.Second)
	for _, field := range fields {
		pid, err := strconv.Atoi(field)
		if err != nil {
			t.Fatalf("parse PID %q: %v", field, err)
		}
		for {
			status, err := readProcessStatus(pid)
			if processGoneError(err) || err == nil && terminalProcessState(status.state) {
				break
			}
			if err != nil {
				t.Fatalf("inspect PID %d: %v", pid, err)
			}
			if time.Now().After(deadline) {
				t.Fatalf("helper PID %d survived broker cleanup", pid)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

func readRecordedPIDFields(t *testing.T, path string) []string {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read helper PIDs: %v", err)
	}
	return strings.Fields(string(value))
}

func killRecordedProcesses(path string) {
	value, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, field := range strings.Fields(string(value)) {
		pid, err := strconv.Atoi(field)
		if err == nil && pid > 0 {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
}
