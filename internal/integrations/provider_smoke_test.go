package integrations

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestCredentialedDNSProviderSmoke is an explicit release gate, never an
// ordinary test. It invokes an administrator-supplied qualified lego artifact
// and isolated native workspace while discarding all upstream output so a
// provider response cannot enter test logs. The native configuration owns its
// restrictive envFile and credentials exactly as it does in production.
func TestCredentialedDNSProviderSmoke(t *testing.T) {
	if os.Getenv("ACMEMUX_PROVIDER_SMOKE") != "1" {
		t.Skip("credentialed provider smoke is not enabled")
	}
	provider := os.Getenv("ACMEMUX_PROVIDER_SMOKE_PROVIDER")
	if !slices.Contains(SupportedDNSProviders(), provider) {
		t.Fatal("ACMEMUX_PROVIDER_SMOKE_PROVIDER must name a curated DNS provider")
	}
	executable := os.Getenv("ACMEMUX_TEST_LEGO")
	configuration := os.Getenv("ACMEMUX_PROVIDER_SMOKE_CONFIG")
	workingDirectory := os.Getenv("ACMEMUX_PROVIDER_SMOKE_WORKDIR")
	for name, value := range map[string]string{
		"ACMEMUX_TEST_LEGO":              executable,
		"ACMEMUX_PROVIDER_SMOKE_CONFIG":  configuration,
		"ACMEMUX_PROVIDER_SMOKE_WORKDIR": workingDirectory,
	} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			t.Fatalf("%s must be a canonical absolute path", name)
		}
	}
	source, err := os.ReadFile(configuration)
	if err != nil {
		t.Fatal("credentialed provider configuration is unavailable")
	}
	defer clear(source)
	if !strings.Contains(string(source), "provider: "+provider) {
		t.Fatal("credentialed provider configuration does not select the requested provider")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "--config", configuration)
	command.Dir = workingDirectory
	command.Env = []string{"LANG=C", "LC_ALL=C", "TZ=UTC"}
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			t.Fatal("credentialed provider smoke exceeded its timeout")
		}
		t.Fatal("credentialed provider smoke failed; inspect the isolated native workspace directly")
	}
}
