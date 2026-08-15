package main

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sgurden-certleap/AcmeMux/internal/inventory"
	acmeruntime "github.com/sgurden-certleap/AcmeMux/internal/runtime"
)

func TestHTTPWriteBudgetCanReturnRuntimeInspectionTimeout(t *testing.T) {
	t.Parallel()
	server := newApplicationHTTPServer("127.0.0.1:0", http.NotFoundHandler())
	minimum := acmeruntime.DefaultProbePolicy().InspectionTimeout + inventory.DefaultPolicy("/private").Timeout + 10*time.Second
	if server.WriteTimeout < minimum {
		t.Fatalf("WriteTimeout = %s, want at least %s", server.WriteTimeout, minimum)
	}
}

func TestPrepareInventoryDirectoryCreatesPrivateNonSymlinkDirectory(t *testing.T) {
	t.Parallel()
	stateDirectory := t.TempDir()
	directory, err := prepareInventoryDirectory(stateDirectory)
	if err != nil {
		t.Fatalf("prepareInventoryDirectory() error = %v", err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		t.Fatalf("inventory directory mode = %v", info.Mode())
	}

	target := filepath.Join(stateDirectory, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(directory); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, directory); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareInventoryDirectory(stateDirectory); err == nil {
		t.Fatal("prepareInventoryDirectory() accepted symbolic link")
	}
}
