package appconfig

import (
	"strings"
	"testing"
)

func TestLoadDefaultsToLoopbackAndAbsoluteState(t *testing.T) {
	t.Parallel()

	config, err := Load(nil, func(string) string { return "" })
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if config.ListenAddress != defaultListenAddress {
		t.Fatalf("ListenAddress = %q, want %q", config.ListenAddress, defaultListenAddress)
	}
	if !strings.HasSuffix(config.StateDirectory, "/var") {
		t.Fatalf("StateDirectory = %q, want absolute var path", config.StateDirectory)
	}
}

func TestLoadRejectsNonLoopbackAddress(t *testing.T) {
	t.Parallel()

	_, err := Load([]string{"--listen", "0.0.0.0:8080"}, func(string) string { return "" })
	if err == nil || !strings.Contains(err.Error(), "loopback-only") {
		t.Fatalf("Load() error = %v, want loopback-only error", err)
	}
}

func TestLoadRejectsOversizedEnvironmentValue(t *testing.T) {
	t.Parallel()

	_, err := Load(nil, func(name string) string {
		if name == "ACMEMUX_STATE_DIRECTORY" {
			return strings.Repeat("x", maximumValueLength+1)
		}
		return ""
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("Load() error = %v, want bounded value error", err)
	}
}
