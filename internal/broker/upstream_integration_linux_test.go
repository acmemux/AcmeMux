//go:build linux

package broker

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const sourceBuiltIntegrationGate = "ACMEMUX_TEST_LEGO_INTEGRATION"

// TestSourceBuiltLegoFileMode is opt-in because it starts the pinned upstream
// Pebble/challtestsrv fixtures and performs real local ACME issuance. Invoke it
// through make test-lego-integration with explicit absolute tool/source paths.
// Normal package and race suites skip it without starting external processes.
func TestSourceBuiltLegoFileMode(t *testing.T) {
	if os.Getenv(sourceBuiltIntegrationGate) != "1" {
		t.Skip("use make test-lego-integration with explicit source-built lego, Pebble, challtestsrv, and source paths")
	}

	legoPath := requireIntegrationExecutable(t, "ACMEMUX_TEST_LEGO")
	pebblePath := requireIntegrationExecutable(t, "ACMEMUX_TEST_PEBBLE")
	challtestsrvPath := requireIntegrationExecutable(t, "ACMEMUX_TEST_CHALLTESTSRV")
	sourcePath := requireIntegrationDirectory(t, "ACMEMUX_TEST_LEGO_SOURCE")
	e2ePath := filepath.Join(sourcePath, "e2e")
	pebbleConfig := filepath.Join(e2ePath, "fixtures", "pebble-config-file.json")
	caCertificate := filepath.Join(e2ePath, "fixtures", "certs", "pebble.minica.pem")
	for _, path := range []string{pebbleConfig, caCertificate} {
		if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
			t.Fatalf("required upstream fixture %q is unavailable: %v", path, err)
		}
	}

	serverContext, cancelServers := context.WithCancel(context.Background())
	t.Cleanup(cancelServers)
	challtestsrv := startIntegrationProcess(t, serverContext, integrationProcessSpec{
		name: "pebble-challtestsrv", path: challtestsrvPath,
		arguments:   []string{"-dnsserver", ":8853", "-http01", ":5019", "-tlsalpn01", ":5018", "-management", ":8855"},
		environment: []string{"LANG=C", "LC_ALL=C", "TZ=UTC"},
	})
	waitForIntegrationTCP(t, challtestsrv, "127.0.0.1:8855")

	pebble := startIntegrationProcess(t, serverContext, integrationProcessSpec{
		name: "pebble", path: pebblePath, directory: e2ePath,
		arguments: []string{"-strict", "-config", "fixtures/pebble-config-file.json", "-dnsserver", "localhost:8853"},
		environment: []string{
			"LANG=C", "LC_ALL=C", "TZ=UTC", "PEBBLE_VA_NOSLEEP=1", "PEBBLE_WFE_NONCEREJECT=0",
		},
	})
	waitForPebbleDirectory(t, pebble, "https://localhost:17000/dir")

	workingDirectory := t.TempDir()
	if err := os.Chmod(workingDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	storagePath := filepath.Join(workingDirectory, "native-storage")
	configurationPath := filepath.Join(workingDirectory, "workspace.yml")
	configuration := fmt.Sprintf(`storage: %q
servers:
  pebble:
    url: https://localhost:17000/dir
challenges:
  local-http:
    http:
      address: ":5009"
certificates:
  'example.localhost':
    challenge: local-http
    domains:
      - acme.localhost
    renew:
      days: 1
      disableRandomSleep: true
      ari:
        disable: true
accounts:
  integration:
    email: integration@example.test
    server: pebble
    acceptsTermsOfService: true
log:
  level: info
  format: text
`, storagePath)
	if err := os.WriteFile(configurationPath, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}

	policy := DefaultPolicy()
	policy.Timeout = 2 * time.Minute
	runner, err := NewRunner(policy)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{
		WorkingDirectory: workingDirectory, ConfigurationPath: configurationPath,
		Environment: []Variable{{Name: "LEGO_CA_CERTIFICATES", Value: []byte(caCertificate)}},
	}

	firstPrepared := &directPrepared{path: legoPath}
	request.Prepared = firstPrepared
	first, err := runner.Run(context.Background(), request)
	if err != nil {
		t.Fatalf("first source-built lego run error = %v\npebble:\n%s\nchalltestsrv:\n%s", err, pebble.output(), challtestsrv.output())
	}
	assertSuccessfulIntegrationRun(t, first, firstPrepared, "first")
	if transcript := first.Stdout + "\n" + first.Stderr; !strings.Contains(transcript, "Server responded with a certificate") {
		t.Fatalf("first run did not report local issuance:\n%s", transcript)
	}

	artifactsBefore := requireIssuedNativeArtifacts(t, storagePath)
	backupPath := filepath.Join(storagePath, ".lego.bck.yaml")
	backupBefore, err := os.Stat(backupPath)
	if err != nil {
		t.Fatalf("stat first effective configuration backup: %v", err)
	}
	// Ensure a second successful backup write is observable even on a coarse
	// test filesystem while certificate bytes remain the stronger no-renewal
	// assertion.
	time.Sleep(20 * time.Millisecond)

	secondPrepared := &directPrepared{path: legoPath}
	request.Prepared = secondPrepared
	second, err := runner.Run(context.Background(), request)
	if err != nil {
		t.Fatalf("second source-built lego run error = %v\npebble:\n%s\nchalltestsrv:\n%s", err, pebble.output(), challtestsrv.output())
	}
	assertSuccessfulIntegrationRun(t, second, secondPrepared, "second")
	secondTranscript := second.Stdout + "\n" + second.Stderr
	if !strings.Contains(secondTranscript, "Skip renewal:") {
		t.Fatalf("second run did not evaluate and skip renewal:\n%s", secondTranscript)
	}
	artifactsAfter := requireIssuedNativeArtifacts(t, storagePath)
	for path, before := range artifactsBefore {
		if !bytes.Equal(before, artifactsAfter[path]) {
			t.Fatalf("second not-due evaluation rewrote issued artifact %q", path)
		}
	}
	backupAfter, err := os.Stat(backupPath)
	if err != nil {
		t.Fatalf("stat second effective configuration backup: %v", err)
	}
	if !backupAfter.ModTime().After(backupBefore.ModTime()) {
		t.Fatalf("second file-mode run did not refresh native backup: %v -> %v", backupBefore.ModTime(), backupAfter.ModTime())
	}
}

func assertSuccessfulIntegrationRun(t *testing.T, result Result, prepared *directPrepared, label string) {
	t.Helper()
	if result.Outcome != OutcomeSucceeded || !result.Started || !result.ExitCodeKnown || result.ExitCode != 0 ||
		result.OutputDiscarded || result.Termination != TerminationNone || !result.MayHaveChanged {
		t.Fatalf("%s source-built lego result = %#v\nstdout:\n%s\nstderr:\n%s", label, result, result.Stdout, result.Stderr)
	}
	prepared.mu.Lock()
	defer prepared.mu.Unlock()
	if prepared.startCount != 1 || prepared.closeCount != 1 {
		t.Fatalf("%s prepared lifecycle = start %d close %d", label, prepared.startCount, prepared.closeCount)
	}
}

func requireIssuedNativeArtifacts(t *testing.T, storagePath string) map[string][]byte {
	t.Helper()
	certificateDirectory := filepath.Join(storagePath, "certificates")
	paths := []string{
		filepath.Join(certificateDirectory, "example.localhost.crt"),
		filepath.Join(certificateDirectory, "example.localhost.issuer.crt"),
		filepath.Join(certificateDirectory, "example.localhost.key"),
		filepath.Join(certificateDirectory, "example.localhost.pem"),
		filepath.Join(certificateDirectory, "example.localhost.json"),
	}
	artifacts := make(map[string][]byte, len(paths))
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("native issued artifact %q is invalid: mode %v, error %v", path, modeOf(info), err)
		}
		value, err := os.ReadFile(path)
		if err != nil || len(value) == 0 {
			t.Fatalf("read native issued artifact %q: %v", path, err)
		}
		artifacts[path] = value
	}

	certificateBlock, _ := pem.Decode(artifacts[paths[0]])
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" {
		t.Fatalf("issued leaf is not a PEM certificate")
	}
	leaf, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		t.Fatalf("parse issued leaf: %v", err)
	}
	if !slices.Contains(leaf.DNSNames, "acme.localhost") || time.Until(leaf.NotAfter) <= 0 {
		t.Fatalf("issued leaf evidence = names %q validity %v -> %v", leaf.DNSNames, leaf.NotBefore, leaf.NotAfter)
	}

	accountFiles := 0
	err = filepath.WalkDir(filepath.Join(storagePath, "accounts"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && (entry.Name() == "account.json" || strings.HasSuffix(entry.Name(), ".key")) {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
				return fmt.Errorf("account artifact %q has mode %v", path, info.Mode())
			}
			accountFiles++
		}
		return nil
	})
	if err != nil || accountFiles < 2 {
		t.Fatalf("native account evidence = %d files, error %v", accountFiles, err)
	}
	return artifacts
}

func modeOf(info os.FileInfo) os.FileMode {
	if info == nil {
		return 0
	}
	return info.Mode()
}

func requireIntegrationExecutable(t *testing.T, environmentName string) string {
	t.Helper()
	path := os.Getenv(environmentName)
	if path == "" {
		t.Fatalf("%s must name an explicit source-backed executable", environmentName)
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		t.Fatalf("%s must be a canonical absolute path", environmentName)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("%s is not a direct executable regular file: %v", environmentName, err)
	}
	return path
}

func requireIntegrationDirectory(t *testing.T, environmentName string) string {
	t.Helper()
	path := os.Getenv(environmentName)
	if path == "" {
		t.Fatalf("%s must name the upstream source snapshot", environmentName)
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		t.Fatalf("%s must be a canonical absolute path", environmentName)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("%s is not a direct source directory: %v", environmentName, err)
	}
	return path
}

type integrationProcessSpec struct {
	name        string
	path        string
	directory   string
	arguments   []string
	environment []string
}

type integrationProcess struct {
	name    string
	command *exec.Cmd
	log     *boundedIntegrationLog
	done    chan struct{}
	waitMu  sync.Mutex
	waitErr error
	once    sync.Once
}

func startIntegrationProcess(t *testing.T, ctx context.Context, spec integrationProcessSpec) *integrationProcess {
	t.Helper()
	logOutput := &boundedIntegrationLog{limit: 128 << 10}
	command := exec.CommandContext(ctx, spec.path, spec.arguments...)
	command.Dir = spec.directory
	command.Env = slices.Clone(spec.environment)
	command.Stdin = nil
	command.Stdout = logOutput
	command.Stderr = logOutput
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		t.Fatalf("start %s: %v", spec.name, err)
	}
	process := &integrationProcess{name: spec.name, command: command, log: logOutput, done: make(chan struct{})}
	go func() {
		err := command.Wait()
		process.waitMu.Lock()
		process.waitErr = err
		process.waitMu.Unlock()
		close(process.done)
	}()
	t.Cleanup(process.stop)
	return process
}

func (process *integrationProcess) stop() {
	process.once.Do(func() {
		select {
		case <-process.done:
			return
		default:
		}
		_ = syscall.Kill(-process.command.Process.Pid, syscall.SIGKILL)
		select {
		case <-process.done:
		case <-time.After(5 * time.Second):
		}
	})
}

func (process *integrationProcess) output() string { return process.log.String() }

func (process *integrationProcess) assertRunning(t *testing.T) {
	t.Helper()
	select {
	case <-process.done:
		process.waitMu.Lock()
		err := process.waitErr
		process.waitMu.Unlock()
		t.Fatalf("%s exited before becoming ready: %v\n%s", process.name, err, process.output())
	default:
	}
}

func waitForIntegrationTCP(t *testing.T, process *integrationProcess, address string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		process.assertRunning(t)
		connection, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s did not listen on %s\n%s", process.name, address, process.output())
}

func waitForPebbleDirectory(t *testing.T, process *integrationProcess, address string) {
	t.Helper()
	client := &http.Client{
		Timeout:   500 * time.Millisecond,
		Transport: &http.Transport{TLSClientConfig: integrationTLSConfig()},
	}
	defer client.CloseIdleConnections()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		process.assertRunning(t)
		response, err := client.Get(address)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s directory did not become ready\n%s", process.name, process.output())
}

// integrationTLSConfig is test-only: readiness authenticates process health,
// while the actual lego run uses the upstream fixture CA explicitly.
func integrationTLSConfig() *tls.Config { //nolint:gosec // local test fixture only
	return &tls.Config{InsecureSkipVerify: true}
}

type boundedIntegrationLog struct {
	mu        sync.Mutex
	limit     int
	value     []byte
	discarded int
}

func (logOutput *boundedIntegrationLog) Write(value []byte) (int, error) {
	logOutput.mu.Lock()
	defer logOutput.mu.Unlock()
	remaining := max(logOutput.limit-len(logOutput.value), 0)
	if remaining > 0 {
		logOutput.value = append(logOutput.value, value[:min(len(value), remaining)]...)
	}
	logOutput.discarded += max(len(value)-remaining, 0)
	return len(value), nil
}

func (logOutput *boundedIntegrationLog) String() string {
	logOutput.mu.Lock()
	defer logOutput.mu.Unlock()
	if logOutput.discarded == 0 {
		return string(logOutput.value)
	}
	return fmt.Sprintf("%s\n[%d integration-log bytes discarded]", logOutput.value, logOutput.discarded)
}

type directPrepared struct {
	mu         sync.Mutex
	path       string
	startCount int
	closeCount int
}

func (prepared *directPrepared) StartContext(
	ctx context.Context,
	configure func(*exec.Cmd) error,
	arguments ...string,
) (*exec.Cmd, error) {
	command := exec.CommandContext(ctx, prepared.path, arguments...)
	if err := configure(command); err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		return nil, err
	}
	prepared.mu.Lock()
	prepared.startCount++
	prepared.mu.Unlock()
	return command, nil
}

func (prepared *directPrepared) Close() error {
	prepared.mu.Lock()
	defer prepared.mu.Unlock()
	prepared.closeCount++
	return nil
}
