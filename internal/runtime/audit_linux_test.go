//go:build linux

package runtime

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestAuditExecutableCapturesSafeFileEvidence(t *testing.T) {
	t.Parallel()

	contents := []byte("#!/bin/sh\nprintf 'lego version 5.3.1 linux/amd64\\n'\n")
	path := writeExecutable(t, contents, 0o700)
	identity, err := AuditExecutable(path, CurrentAuditPolicy())
	if err != nil {
		t.Fatalf("AuditExecutable() error = %v", err)
	}
	wantDigest := sha256.Sum256(contents)
	if identity.CanonicalPath != path || identity.Size != int64(len(contents)) || identity.SHA256 != hex.EncodeToString(wantDigest[:]) {
		t.Fatalf("identity = %#v", identity)
	}
	if identity.Device == 0 || identity.Inode == 0 || identity.Mode&syscall.S_IFMT != syscall.S_IFREG {
		t.Fatalf("missing stat evidence: %#v", identity)
	}
	if identity.ModifiedAt.IsZero() || identity.ChangedAt.IsZero() {
		t.Fatalf("missing timestamp evidence: %#v", identity)
	}
}

func TestAuditExecutableRejectsInvalidPaths(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	valid := writeExecutableIn(t, directory, "lego", []byte("x"), 0o700)
	tests := []struct {
		name string
		path string
		code ErrorCode
	}{
		{name: "empty", code: CodePathRequired},
		{name: "relative", path: "lego", code: CodePathNotAbsolute},
		{name: "dot segment", path: directory + "/sub/../lego", code: CodePathNotCanonical},
		{name: "double slash", path: directory + "//lego", code: CodePathNotCanonical},
		{name: "control character", path: directory + "/bad\nname", code: CodePathNotCanonical},
		{name: "invalid utf8", path: directory + "/bad\xffname", code: CodePathNotCanonical},
		{name: "root", path: "/", code: CodePathNotCanonical},
		{name: "too long", path: "/" + string(make([]byte, maximumPathLength)), code: CodePathTooLong},
		{name: "missing", path: valid + "-missing", code: CodePathUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := AuditExecutable(test.path, CurrentAuditPolicy())
			if CodeOf(err) != test.code {
				t.Fatalf("CodeOf(error) = %q, want %q; error = %v", CodeOf(err), test.code, err)
			}
		})
	}
}

func TestAuditExecutableRejectsSymlinkAndSymlinkTraversal(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	targetDirectory := filepath.Join(directory, "real")
	if err := os.Mkdir(targetDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := writeExecutableIn(t, targetDirectory, "lego", []byte("x"), 0o700)
	fileLink := filepath.Join(directory, "lego-link")
	if err := os.Symlink(target, fileLink); err != nil {
		t.Fatal(err)
	}
	directoryLink := filepath.Join(directory, "directory-link")
	if err := os.Symlink(targetDirectory, directoryLink); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{fileLink, filepath.Join(directoryLink, "lego")} {
		_, err := AuditExecutable(path, CurrentAuditPolicy())
		if CodeOf(err) != CodeSymlink {
			t.Fatalf("AuditExecutable(%q) code = %q, error = %v", path, CodeOf(err), err)
		}
	}
}

func TestAuditExecutableRejectsUnsafeFileKindsModesAndOwners(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	directoryPath := filepath.Join(directory, "subdirectory")
	if err := os.Mkdir(directoryPath, 0o700); err != nil {
		t.Fatal(err)
	}
	nonExecutable := writeExecutableIn(t, directory, "non-executable", []byte("x"), 0o600)
	empty := writeExecutableIn(t, directory, "empty", nil, 0o700)
	tooLarge := writeExecutableIn(t, directory, "too-large", []byte("x"), 0o700)
	if err := os.Truncate(tooLarge, maximumExecutableSize+1); err != nil {
		t.Fatal(err)
	}
	groupWritable := writeExecutableIn(t, directory, "group-writable", []byte("x"), 0o720)
	otherWritable := writeExecutableIn(t, directory, "other-writable", []byte("x"), 0o702)
	setuid := writeExecutableIn(t, directory, "setuid", []byte("x"), os.ModeSetuid|0o700)
	setgid := writeExecutableIn(t, directory, "setgid", []byte("x"), os.ModeSetgid|0o700)
	sticky := writeExecutableIn(t, directory, "sticky", []byte("x"), os.ModeSticky|0o700)
	untrustedOwner := writeExecutableIn(t, directory, "untrusted-owner", []byte("x"), 0o700)

	tests := []struct {
		name   string
		path   string
		policy AuditPolicy
		code   ErrorCode
	}{
		{name: "directory", path: directoryPath, policy: CurrentAuditPolicy(), code: CodeNotRegular},
		{name: "non executable", path: nonExecutable, policy: CurrentAuditPolicy(), code: CodeNotExecutable},
		{name: "empty", path: empty, policy: CurrentAuditPolicy(), code: CodeEmptyExecutable},
		{name: "too large", path: tooLarge, policy: CurrentAuditPolicy(), code: CodeExecutableTooLarge},
		{name: "group writable", path: groupWritable, policy: CurrentAuditPolicy(), code: CodeUnsafePermissions},
		{name: "other writable", path: otherWritable, policy: CurrentAuditPolicy(), code: CodeUnsafePermissions},
		{name: "setuid", path: setuid, policy: CurrentAuditPolicy(), code: CodeUnsafePermissions},
		{name: "setgid", path: setgid, policy: CurrentAuditPolicy(), code: CodeUnsafePermissions},
		{name: "sticky", path: sticky, policy: CurrentAuditPolicy(), code: CodeUnsafePermissions},
		{name: "untrusted owner", path: untrustedOwner, policy: AuditPolicy{EffectiveUID: CurrentAuditPolicy().EffectiveUID + 10000}, code: CodeUntrustedOwner},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := AuditExecutable(test.path, test.policy)
			if CodeOf(err) != test.code {
				t.Fatalf("CodeOf(error) = %q, want %q; error = %v", CodeOf(err), test.code, err)
			}
		})
	}
}

func TestAuditExecutableRejectsSpecialFilesBeforeReadOpen(t *testing.T) {
	t.Parallel()

	pipePath := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(pipePath, 0o700); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name string
		path string
	}{
		{name: "named pipe", path: pipePath},
		{name: "character device", path: "/dev/null"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := AuditExecutable(test.path, CurrentAuditPolicy())
			if CodeOf(err) != CodeNotRegular {
				t.Fatalf("AuditExecutable(%q) code = %q, want %q; error = %v", test.path, CodeOf(err), CodeNotRegular, err)
			}
		})
	}
}

func TestParseLinuxFileCapabilitiesAllowsOnlyNetBindServiceEffectivePermitted(t *testing.T) {
	t.Parallel()
	allowed := make([]byte, linuxCapabilityRevision2Size)
	binary.LittleEndian.PutUint32(allowed[0:4], linuxCapabilityRevision2|linuxCapabilityEffective)
	binary.LittleEndian.PutUint32(allowed[4:8], uint32(1)<<unix.CAP_NET_BIND_SERVICE)
	value, err := parseLinuxFileCapabilities(allowed, "/lego")
	if err != nil || value != allowedLinuxFileCapability {
		t.Fatalf("allowed capability = %q, error = %v", value, err)
	}

	tests := [][]byte{
		nil,
		append([]byte(nil), allowed[:len(allowed)-1]...),
		func() []byte {
			value := append([]byte(nil), allowed...)
			binary.LittleEndian.PutUint32(value[0:4], 0x03000000|linuxCapabilityEffective)
			return value
		}(),
		func() []byte {
			value := append([]byte(nil), allowed...)
			binary.LittleEndian.PutUint32(value[0:4], linuxCapabilityRevision2)
			return value
		}(),
		func() []byte {
			value := append([]byte(nil), allowed...)
			binary.LittleEndian.PutUint32(value[4:8], uint32(1)<<unix.CAP_CHOWN)
			return value
		}(),
		func() []byte {
			value := append([]byte(nil), allowed...)
			binary.LittleEndian.PutUint32(value[8:12], uint32(1)<<unix.CAP_NET_BIND_SERVICE)
			return value
		}(),
		func() []byte {
			value := append([]byte(nil), allowed...)
			binary.LittleEndian.PutUint32(value[12:16], 1)
			return value
		}(),
	}
	for _, encoded := range tests {
		if _, err := parseLinuxFileCapabilities(encoded, "/lego"); CodeOf(err) != CodeUnsafeCapabilities {
			t.Fatalf("capability %x error = %v", encoded, err)
		}
	}
}

func writeExecutable(t *testing.T, contents []byte, mode os.FileMode) string {
	t.Helper()
	return writeExecutableIn(t, t.TempDir(), "lego", contents, mode)
}

func writeExecutableIn(t *testing.T, directory, name string, contents []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}
