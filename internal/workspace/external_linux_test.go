//go:build linux

package workspace

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExternalCloudAccessUsesNoFollowConfidentialAndExecutablePolicy(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("workspace policy deliberately rejects root")
	}
	inspector, err := NewInspector(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	credential := filepath.Join(directory, "credentials")
	if err := os.WriteFile(credential, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := inspector.ReadExternalCredential(t.Context(), credential, 64)
	if err != nil {
		t.Fatal(err)
	}
	if string(file.Content) != "secret" || !file.Evidence.Safe {
		t.Fatalf("external file = %#v", file)
	}
	file.Close()
	if len(file.Content) != 0 {
		t.Fatal("external credential close retained content")
	}

	unsafe := filepath.Join(directory, "unsafe")
	if err := os.WriteFile(unsafe, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := inspector.ReadExternalCredential(t.Context(), unsafe, 64); err == nil {
		t.Fatal("world-readable credential was accepted")
	}
	symlink := filepath.Join(directory, "link")
	if err := os.Symlink(credential, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := inspector.ReadExternalCredential(t.Context(), symlink, 64); err == nil {
		t.Fatal("credential symlink was accepted")
	}

	helper := filepath.Join(directory, "az")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := inspector.AuditExternalExecutable(t.Context(), helper); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(helper, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := inspector.AuditExternalExecutable(t.Context(), helper); err == nil {
		t.Fatal("non-executable helper was accepted")
	}
	if _, err := inspector.AuditExternalDirectory(t.Context(), directory); err != nil {
		t.Fatal(err)
	}
}
