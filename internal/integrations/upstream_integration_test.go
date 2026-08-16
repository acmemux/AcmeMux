package integrations

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestCoreDNSUpstreamProviderFixtures executes the exact upstream fake-server
// suites that back the core curated provider manifest. It is gated with the existing
// source-built lego integration environment and never uses live credentials.
func TestCoreDNSUpstreamProviderFixtures(t *testing.T) {
	if os.Getenv("ACMEMUX_TEST_LEGO_INTEGRATION") != "1" {
		t.Skip("source-backed lego integration is not enabled")
	}
	source := os.Getenv("ACMEMUX_TEST_LEGO_SOURCE")
	if !filepath.IsAbs(source) || filepath.Clean(source) != source {
		t.Fatal("ACMEMUX_TEST_LEGO_SOURCE must be a canonical absolute path")
	}
	command := exec.CommandContext(
		t.Context(), "go", "test", "-count=1",
		"./providers/dns/cloudflare/...",
		"./providers/dns/digitalocean/...",
		"./providers/dns/duckdns/...",
	)
	command.Dir = source
	command.Env = os.Environ()
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		if output.Len() > 64<<10 {
			output.Truncate(64 << 10)
		}
		t.Fatalf("upstream provider fake-server suites failed: %s", output.String())
	}
}

func TestCloudDNSUpstreamProviderFixtures(t *testing.T) {
	if os.Getenv("ACMEMUX_TEST_LEGO_INTEGRATION") != "1" {
		t.Skip("source-backed lego integration is not enabled")
	}
	source := os.Getenv("ACMEMUX_TEST_LEGO_SOURCE")
	if !filepath.IsAbs(source) || filepath.Clean(source) != source {
		t.Fatal("ACMEMUX_TEST_LEGO_SOURCE must be a canonical absolute path")
	}
	command := exec.CommandContext(t.Context(), "go", "test", "-count=1", "./providers/dns/azuredns/...", "./providers/dns/route53/...")
	command.Dir = source
	command.Env = os.Environ()
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		if output.Len() > 64<<10 {
			output.Truncate(64 << 10)
		}
		t.Fatalf("upstream cloud provider fake-server suites failed: %s", output.String())
	}
}
