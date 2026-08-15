//go:build linux

package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const helperExpiration = "2031-02-03 04:05:06 +0000 UTC"

type fakePrepared struct {
	mu          sync.Mutex
	behavior    string
	arguments   []string
	directory   string
	environment []string
	sysProcAttr *syscall.SysProcAttr
	startCount  int
	closeCount  int
	startErr    error
	closeErr    error
}

func (prepared *fakePrepared) StartContext(
	ctx context.Context,
	configure func(*exec.Cmd) error,
	arguments ...string,
) (*exec.Cmd, error) {
	prepared.mu.Lock()
	prepared.startCount++
	prepared.arguments = slices.Clone(arguments)
	prepared.mu.Unlock()
	if prepared.startErr != nil {
		return nil, prepared.startErr
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	helperArguments := []string{"-test.run=^TestInventoryHelperProcess$", "--", prepared.behavior}
	helperArguments = append(helperArguments, arguments...)
	command := exec.CommandContext(ctx, executable, helperArguments...)
	if err := configure(command); err != nil {
		return nil, err
	}
	prepared.mu.Lock()
	prepared.directory = command.Dir
	prepared.environment = slices.Clone(command.Env)
	if command.SysProcAttr != nil {
		copy := *command.SysProcAttr
		prepared.sysProcAttr = &copy
	}
	prepared.mu.Unlock()
	if err := command.Start(); err != nil {
		return nil, err
	}
	return command, nil
}

func (prepared *fakePrepared) Close() error {
	prepared.mu.Lock()
	defer prepared.mu.Unlock()
	prepared.closeCount++
	return prepared.closeErr
}

func TestInventoryHelperProcess(t *testing.T) {
	separator := slices.Index(os.Args, "--")
	if separator < 0 || separator+1 >= len(os.Args) {
		return
	}
	arguments := os.Args[separator+1:]
	behavior := arguments[0]
	commandArguments := arguments[1:]
	if len(commandArguments) != 5 {
		os.Exit(97)
	}
	storagePath := commandArguments[3]
	certificatePath := filepath.Join(storagePath, "certificates", "example.com.crt")
	candidate := map[string]any{
		"name":           "example.com",
		"domains":        []string{"example.com", "www.example.com"},
		"expirationDate": helperExpiration,
		"expired":        false,
		"issuer":         "CN=Test CA,O=AcmeMux Test",
		"path":           certificatePath,
	}

	switch behavior {
	case "valid":
		writeHelperJSON(candidate)
	case "no-domains":
		delete(candidate, "domains")
		candidate["ips"] = []string{"192.0.2.10"}
		writeHelperJSON(candidate)
	case "null":
		_, _ = os.Stdout.WriteString("null\n")
	case "empty-array":
		_, _ = os.Stdout.WriteString("[]\n")
	case "malformed":
		_, _ = os.Stdout.WriteString("{\n")
	case "unknown":
		candidate["unexpected"] = true
		writeHelperJSON([]any{candidate})
	case "duplicate":
		writeHelperJSON([]any{candidate, candidate})
	case "outside":
		candidate["path"] = "/etc/passwd"
		writeHelperJSON([]any{candidate})
	case "bad-expiration":
		candidate["expirationDate"] = "2031-02-03T04:05:06Z"
		writeHelperJSON([]any{candidate})
	case "long-name":
		candidate["name"] = strings.Repeat("x", maximumNameBytes+1)
		writeHelperJSON([]any{candidate})
	case "remove":
		_ = os.Remove(certificatePath)
		writeHelperJSON([]any{candidate})
	case "replace":
		replacement := certificatePath + ".replacement"
		_ = os.WriteFile(replacement, []byte("replacement certificate evidence"), 0o600)
		_ = os.Rename(replacement, certificatePath)
		writeHelperJSON([]any{candidate})
	case "timeout":
		time.Sleep(10 * time.Second)
	case "stdout-overflow":
		_, _ = os.Stdout.WriteString(strings.Repeat("x", 1<<20))
	case "stderr-overflow":
		_, _ = os.Stderr.WriteString(strings.Repeat("x", 1<<20))
	case "failure":
		_, _ = os.Stderr.WriteString("super-secret-child-diagnostic")
		os.Exit(7)
	case "missing-directory":
		message := "stat " + filepath.Join(storagePath, "certificates") + ": " + syscall.ENOENT.Error()
		_, _ = fmt.Fprintf(os.Stdout, "%s ERROR Error error=%q\n", time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z07:00"), message)
		os.Exit(1)
	default:
		os.Exit(98)
	}
	os.Exit(0)
}

func writeHelperJSON(value any) {
	if _, ok := value.(map[string]any); ok {
		value = []any{value}
	}
	if err := json.NewEncoder(os.Stdout).Encode(value); err != nil {
		os.Exit(99)
	}
}

func TestReaderReturnsReconciledMetadataWithExactBrokerControls(t *testing.T) {
	fixture := newInventoryFixture(t, true)
	fixture.writeCertificatePair(t, "example.com")
	prepared := &fakePrepared{behavior: "valid"}
	reader := fixture.reader(t)

	certificates, err := reader.Read(context.Background(), prepared, fixture.storage)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(certificates) != 1 {
		t.Fatalf("Read() certificate count = %d, want 1", len(certificates))
	}
	certificate := certificates[0]
	if certificate.Name != "example.com" || !slices.Equal(certificate.DNSNames, []string{"example.com", "www.example.com"}) {
		t.Fatalf("Read() certificate identity = %#v", certificate)
	}
	if certificate.Issuer != "CN=Test CA,O=AcmeMux Test" {
		t.Fatalf("Read() issuer = %q", certificate.Issuer)
	}
	if certificate.ExpiresAt.Format(legoExpirationLayout) != helperExpiration || certificate.ExpiresAt.Location() != time.UTC {
		t.Fatalf("Read() expiration = %v", certificate.ExpiresAt)
	}
	if certificate.NativePath != fixture.certificatePath("example.com") {
		t.Fatalf("Read() native path = %q", certificate.NativePath)
	}
	if certificate.Artifact.UID != uint32(os.Geteuid()) || certificate.Artifact.LinkCount != 1 || certificate.Artifact.Size == 0 {
		t.Fatalf("Read() artifact = %#v", certificate.Artifact)
	}

	wantArguments := []string{"certificates", "list", "--path", fixture.storage, "--json"}
	if !slices.Equal(prepared.arguments, wantArguments) {
		t.Fatalf("StartContext arguments = %q, want %q", prepared.arguments, wantArguments)
	}
	if prepared.directory != fixture.neutral {
		t.Fatalf("command directory = %q, want %q", prepared.directory, fixture.neutral)
	}
	if !slices.Equal(prepared.environment, controlledEnvironment(fixture.neutral)) {
		t.Fatalf("command environment = %q", prepared.environment)
	}
	if prepared.sysProcAttr == nil || !prepared.sysProcAttr.Setpgid || prepared.sysProcAttr.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("command process controls = %#v", prepared.sysProcAttr)
	}
	if prepared.startCount != 1 || prepared.closeCount != 1 {
		t.Fatalf("prepared counts = start %d, close %d", prepared.startCount, prepared.closeCount)
	}
}

func TestReaderNormalizesMissingDNSNamesToEmpty(t *testing.T) {
	fixture := newInventoryFixture(t, true)
	fixture.writeCertificatePair(t, "example.com")
	certificates, err := fixture.reader(t).Read(context.Background(), &fakePrepared{behavior: "no-domains"}, fixture.storage)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(certificates) != 1 || certificates[0].DNSNames == nil || len(certificates[0].DNSNames) != 0 {
		t.Fatalf("certificates = %#v, want one non-nil empty DNS name slice", certificates)
	}
}

func TestReaderAcceptsEmptyOutputsForEmptyAndMissingCertificateDirectories(t *testing.T) {
	for _, behavior := range []string{"null", "empty-array"} {
		for _, certificateDirectory := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s_directory_%t", behavior, certificateDirectory), func(t *testing.T) {
				fixture := newInventoryFixture(t, certificateDirectory)
				prepared := &fakePrepared{behavior: behavior}
				certificates, err := fixture.reader(t).Read(context.Background(), prepared, fixture.storage)
				if err != nil {
					t.Fatalf("Read() error = %v", err)
				}
				if certificates == nil || len(certificates) != 0 {
					t.Fatalf("Read() = %#v, want non-nil empty slice", certificates)
				}
				if prepared.closeCount != 1 {
					t.Fatalf("Close() count = %d", prepared.closeCount)
				}
			})
		}
	}
}

func TestReaderNormalizesOnlyStableMissingCertificateDirectoryFailure(t *testing.T) {
	fixture := newInventoryFixture(t, false)
	prepared := &fakePrepared{behavior: "missing-directory"}
	certificates, err := fixture.reader(t).Read(context.Background(), prepared, fixture.storage)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if certificates == nil || len(certificates) != 0 {
		t.Fatalf("Read() = %#v, want non-nil empty slice", certificates)
	}
	if prepared.startCount != 1 || prepared.closeCount != 1 {
		t.Fatalf("prepared counts = start %d, close %d", prepared.startCount, prepared.closeCount)
	}

	_, err = fixture.reader(t).Read(context.Background(), &fakePrepared{behavior: "failure"}, fixture.storage)
	assertInventoryCode(t, err, CodeExecutionFailed)

	if err := os.Mkdir(fixture.certificates, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err = fixture.reader(t).Read(context.Background(), &fakePrepared{behavior: "missing-directory"}, fixture.storage)
	assertInventoryCode(t, err, CodeExecutionFailed)
}

func TestReaderAllowsOnlyOneConcurrentInventory(t *testing.T) {
	fixture := newInventoryFixture(t, true)
	reader := fixture.reader(t)
	blocking := &blockingPrepared{started: make(chan struct{}), release: make(chan struct{})}
	firstResult := make(chan error, 1)
	go func() {
		_, err := reader.Read(context.Background(), blocking, fixture.storage)
		firstResult <- err
	}()

	<-blocking.started
	second := &fakePrepared{behavior: "null"}
	_, err := reader.Read(context.Background(), second, fixture.storage)
	assertInventoryCode(t, err, CodeExecutionBusy)
	if second.startCount != 0 || second.closeCount != 1 {
		t.Fatalf("busy prepared counts = start %d, close %d", second.startCount, second.closeCount)
	}

	close(blocking.release)
	assertInventoryCode(t, <-firstResult, CodeExecutionFailed)
	if blocking.closeCount != 1 {
		t.Fatalf("blocking Close() count = %d", blocking.closeCount)
	}
}

type blockingPrepared struct {
	started    chan struct{}
	release    chan struct{}
	closeCount int
}

func (prepared *blockingPrepared) StartContext(context.Context, func(*exec.Cmd) error, ...string) (*exec.Cmd, error) {
	close(prepared.started)
	<-prepared.release
	return nil, errors.New("released test inventory")
}

func (prepared *blockingPrepared) Close() error {
	prepared.closeCount++
	return nil
}

func TestReaderRejectsNeutralConfigurationWithoutStarting(t *testing.T) {
	fixture := newInventoryFixture(t, true)
	if err := os.WriteFile(filepath.Join(fixture.neutral, ".lego.yml"), []byte("storage: /elsewhere\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prepared := &fakePrepared{behavior: "null"}
	_, err := fixture.reader(t).Read(context.Background(), prepared, fixture.storage)
	assertInventoryCode(t, err, CodeConfigurationPresent)
	if prepared.startCount != 0 || prepared.closeCount != 1 {
		t.Fatalf("prepared counts = start %d, close %d", prepared.startCount, prepared.closeCount)
	}
}

func TestReaderRejectsUnsafePreExecutionTrees(t *testing.T) {
	tests := map[string]struct {
		arrange func(*testing.T, inventoryFixture)
		code    ErrorCode
	}{
		"symlink_resource": {
			arrange: func(t *testing.T, fixture inventoryFixture) {
				if err := os.Symlink("missing", fixture.resourcePath("example.com")); err != nil {
					t.Fatal(err)
				}
			},
			code: CodeSymlink,
		},
		"symlink_certificate": {
			arrange: func(t *testing.T, fixture inventoryFixture) {
				fixture.writeResource(t, "example.com")
				target := filepath.Join(fixture.base, "outside.crt")
				if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, fixture.certificatePath("example.com")); err != nil {
					t.Fatal(err)
				}
			},
			code: CodeSymlink,
		},
		"unsafe_resource_permissions": {
			arrange: func(t *testing.T, fixture inventoryFixture) {
				fixture.writeCertificatePair(t, "example.com")
				if err := os.Chmod(fixture.resourcePath("example.com"), 0o660); err != nil {
					t.Fatal(err)
				}
			},
			code: CodeUnsafePermissions,
		},
		"unreadable_certificate": {
			arrange: func(t *testing.T, fixture inventoryFixture) {
				fixture.writeCertificatePair(t, "example.com")
				if err := os.Chmod(fixture.certificatePath("example.com"), 0); err != nil {
					t.Fatal(err)
				}
			},
			code: CodeNotReadable,
		},
		"hard_link_certificate": {
			arrange: func(t *testing.T, fixture inventoryFixture) {
				fixture.writeCertificatePair(t, "example.com")
				if err := os.Link(fixture.certificatePath("example.com"), filepath.Join(fixture.certificates, "alias.crt")); err != nil {
					t.Fatal(err)
				}
			},
			code: CodeHardLink,
		},
		"empty_certificate": {
			arrange: func(t *testing.T, fixture inventoryFixture) {
				fixture.writeResource(t, "example.com")
				if err := os.WriteFile(fixture.certificatePath("example.com"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			code: CodeArtifactSize,
		},
		"fifo_resource": {
			arrange: func(t *testing.T, fixture inventoryFixture) {
				if err := unix.Mkfifo(fixture.resourcePath("example.com"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			code: CodeNotRegular,
		},
		"control_character_name": {
			arrange: func(t *testing.T, fixture inventoryFixture) {
				if err := os.WriteFile(filepath.Join(fixture.certificates, "bad\nname"), []byte("evidence"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			code: CodePathNotCanonical,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newInventoryFixture(t, true)
			test.arrange(t, fixture)
			prepared := &fakePrepared{behavior: "null"}
			_, err := fixture.reader(t).Read(context.Background(), prepared, fixture.storage)
			assertInventoryCode(t, err, test.code)
			if prepared.startCount != 0 || prepared.closeCount != 1 {
				t.Fatalf("prepared counts = start %d, close %d", prepared.startCount, prepared.closeCount)
			}
		})
	}
}

func TestReaderRequiresReadableAndPrivateNativeArtifacts(t *testing.T) {
	t.Run("every regular artifact must be readable", func(t *testing.T) {
		fixture := newInventoryFixture(t, true)
		path := filepath.Join(fixture.certificates, "unrelated.txt")
		if err := os.WriteFile(path, []byte("evidence"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0); err != nil {
			t.Fatal(err)
		}
		_, err := fixture.reader(t).Read(context.Background(), &fakePrepared{behavior: "null"}, fixture.storage)
		assertInventoryCode(t, err, CodeNotReadable)
	})

	for _, extension := range []string{".key", ".pem", ".pfx"} {
		t.Run("private artifact "+extension, func(t *testing.T) {
			fixture := newInventoryFixture(t, true)
			path := filepath.Join(fixture.certificates, "example.com"+extension)
			if err := os.WriteFile(path, []byte("private artifact evidence"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := fixture.reader(t).Read(context.Background(), &fakePrepared{behavior: "null"}, fixture.storage)
			assertInventoryCode(t, err, CodeUnsafePermissions)
		})
	}
}

func TestReaderEnforcesTreeAndCertificateBoundsBeforeExecution(t *testing.T) {
	tests := map[string]struct {
		arrange func(*testing.T, inventoryFixture)
		adjust  func(*Policy)
		code    ErrorCode
	}{
		"entries": {
			arrange: func(t *testing.T, fixture inventoryFixture) {
				for _, name := range []string{"one.txt", "two.txt"} {
					if err := os.WriteFile(filepath.Join(fixture.certificates, name), []byte("evidence"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			},
			adjust: func(policy *Policy) { policy.MaximumTreeEntries = 1 },
			code:   CodeTreeEntryLimit,
		},
		"depth": {
			arrange: func(t *testing.T, fixture inventoryFixture) {
				if err := os.MkdirAll(filepath.Join(fixture.certificates, "one", "two"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
			adjust: func(policy *Policy) { policy.MaximumTreeDepth = 1 },
			code:   CodeTreeDepthLimit,
		},
		"certificates": {
			arrange: func(t *testing.T, fixture inventoryFixture) {
				fixture.writeCertificatePair(t, "one.example")
				fixture.writeCertificatePair(t, "two.example")
			},
			adjust: func(policy *Policy) { policy.MaximumCertificates = 1 },
			code:   CodeCertificateLimit,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newInventoryFixture(t, true)
			test.arrange(t, fixture)
			policy := DefaultPolicy(fixture.neutral)
			test.adjust(&policy)
			reader, err := NewReader(policy)
			if err != nil {
				t.Fatal(err)
			}
			prepared := &fakePrepared{behavior: "null"}
			_, err = reader.Read(context.Background(), prepared, fixture.storage)
			assertInventoryCode(t, err, test.code)
			if prepared.startCount != 0 || prepared.closeCount != 1 {
				t.Fatalf("prepared counts = start %d, close %d", prepared.startCount, prepared.closeCount)
			}
		})
	}
}

func TestReaderStrictlyRejectsMalformedOrUnreconciledOutput(t *testing.T) {
	tests := map[string]struct {
		behavior string
		arrange  func(*testing.T, inventoryFixture)
		code     ErrorCode
	}{
		"malformed":       {behavior: "malformed", code: CodeMalformedOutput},
		"unknown_field":   {behavior: "unknown", code: CodeMalformedOutput},
		"outside_storage": {behavior: "outside", code: CodePathOutsideStorage},
		"bad_expiration":  {behavior: "bad-expiration", code: CodeMalformedOutput},
		"long_name":       {behavior: "long-name", code: CodeMalformedOutput},
		"duplicate": {
			behavior: "duplicate",
			arrange: func(t *testing.T, fixture inventoryFixture) {
				fixture.writeCertificatePair(t, "other.example")
			},
			code: CodeDuplicate,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newInventoryFixture(t, true)
			fixture.writeCertificatePair(t, "example.com")
			if test.arrange != nil {
				test.arrange(t, fixture)
			}
			_, err := fixture.reader(t).Read(context.Background(), &fakePrepared{behavior: test.behavior}, fixture.storage)
			assertInventoryCode(t, err, test.code)
		})
	}
}

func TestReaderDetectsDisappearingAndReplacedArtifacts(t *testing.T) {
	for _, behavior := range []string{"remove", "replace"} {
		t.Run(behavior, func(t *testing.T) {
			fixture := newInventoryFixture(t, true)
			fixture.writeCertificatePair(t, "example.com")
			_, err := fixture.reader(t).Read(context.Background(), &fakePrepared{behavior: behavior}, fixture.storage)
			assertInventoryCode(t, err, CodeArtifactsChanged)
		})
	}
}

func TestReaderBoundsExecutionWithoutReturningChildDiagnostics(t *testing.T) {
	tests := map[string]struct {
		behavior string
		adjust   func(*Policy)
		code     ErrorCode
	}{
		"timeout": {
			behavior: "timeout",
			adjust: func(policy *Policy) {
				policy.Timeout = 100 * time.Millisecond
			},
			code: CodeExecutionTimeout,
		},
		"stdout": {
			behavior: "stdout-overflow",
			adjust: func(policy *Policy) {
				policy.StdoutLimit = 128
			},
			code: CodeOutputLimit,
		},
		"stderr": {
			behavior: "stderr-overflow",
			adjust: func(policy *Policy) {
				policy.StderrLimit = 128
			},
			code: CodeOutputLimit,
		},
		"child_failure": {behavior: "failure", code: CodeExecutionFailed},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newInventoryFixture(t, true)
			policy := DefaultPolicy(fixture.neutral)
			if test.adjust != nil {
				test.adjust(&policy)
			}
			reader, err := NewReader(policy)
			if err != nil {
				t.Fatal(err)
			}
			_, err = reader.Read(context.Background(), &fakePrepared{behavior: test.behavior}, fixture.storage)
			assertInventoryCode(t, err, test.code)
			if strings.Contains(err.Error(), "super-secret") {
				t.Fatalf("error leaks child stderr: %v", err)
			}
		})
	}
}

func TestReaderSurfacesPreparedCloseFailureOnlyAfterSuccessfulRead(t *testing.T) {
	fixture := newInventoryFixture(t, true)
	prepared := &fakePrepared{behavior: "null", closeErr: errors.New("close failed")}
	_, err := fixture.reader(t).Read(context.Background(), prepared, fixture.storage)
	assertInventoryCode(t, err, CodePreparedCloseFailed)
}

type inventoryFixture struct {
	base         string
	storage      string
	neutral      string
	certificates string
}

func newInventoryFixture(t *testing.T, certificateDirectory bool) inventoryFixture {
	t.Helper()
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture := inventoryFixture{
		base:         base,
		storage:      filepath.Join(base, "storage"),
		neutral:      filepath.Join(base, "neutral"),
		certificates: filepath.Join(base, "storage", "certificates"),
	}
	for _, path := range []string{fixture.storage, fixture.neutral} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if certificateDirectory {
		if err := os.Mkdir(fixture.certificates, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

func (fixture inventoryFixture) reader(t *testing.T) *Reader {
	t.Helper()
	reader, err := NewReader(DefaultPolicy(fixture.neutral))
	if err != nil {
		t.Fatal(err)
	}
	return reader
}

func (fixture inventoryFixture) resourcePath(name string) string {
	return filepath.Join(fixture.certificates, name+".json")
}

func (fixture inventoryFixture) certificatePath(name string) string {
	return filepath.Join(fixture.certificates, name+".crt")
}

func (fixture inventoryFixture) writeResource(t *testing.T, name string) {
	t.Helper()
	if err := os.WriteFile(fixture.resourcePath(name), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (fixture inventoryFixture) writeCertificatePair(t *testing.T, name string) {
	t.Helper()
	fixture.writeResource(t, name)
	if err := os.WriteFile(fixture.certificatePath(name), []byte("certificate evidence only"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertInventoryCode(t *testing.T, err error, code ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want %s", code)
	}
	if got := CodeOf(err); got != code {
		t.Fatalf("CodeOf(%v) = %s, want %s", err, got, code)
	}
}
