package appconfig

import (
	"net/netip"
	"strings"
	"testing"
)

func testEnvironment(values map[string]string) func(string) string {
	return func(name string) string {
		if value, exists := values[name]; exists {
			return value
		}
		return ""
	}
}

func TestLoadRequiresCanonicalPublicOrigin(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		origin string
		want   string
	}{
		{name: "absent"},
		{name: "HTTP", origin: "http://acmemux.example"},
		{name: "credentials", origin: "https://operator@acmemux.example"},
		{name: "path", origin: "https://acmemux.example/control"},
		{name: "query", origin: "https://acmemux.example?mode=control"},
		{name: "fragment", origin: "https://acmemux.example#control"},
		{name: "trailing dot", origin: "https://acmemux.example."},
		{name: "unicode", origin: "https://acmé.example"},
		{name: "invalid port", origin: "https://acmemux.example:0"},
		{name: "surrounding space", origin: " https://acmemux.example"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := Load(nil, testEnvironment(map[string]string{"ACMEMUX_PUBLIC_ORIGIN": test.origin}))
			if err == nil || (test.want != "" && !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("Load() error = %v, want public-origin rejection", err)
			}
		})
	}
}

func TestLoadCanonicalizesConfiguration(t *testing.T) {
	t.Parallel()

	config, err := Load(nil, testEnvironment(map[string]string{
		"ACMEMUX_PUBLIC_ORIGIN":   "HTTPS://AcmeMux.Example:443/",
		"ACMEMUX_TRUSTED_PROXIES": "127.0.0.1, 127.0.0.8/32, ::1/128",
	}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if config.ListenAddress != defaultListenAddress {
		t.Fatalf("ListenAddress = %q, want %q", config.ListenAddress, defaultListenAddress)
	}
	if !strings.HasSuffix(config.StateDirectory, "/var") {
		t.Fatalf("StateDirectory = %q, want absolute var path", config.StateDirectory)
	}
	if config.PublicOrigin != "https://acmemux.example" {
		t.Fatalf("PublicOrigin = %q, want canonical origin", config.PublicOrigin)
	}
	wantProxies := []netip.Prefix{
		netip.MustParsePrefix("127.0.0.1/32"),
		netip.MustParsePrefix("127.0.0.8/32"),
		netip.MustParsePrefix("::1/128"),
	}
	if len(config.TrustedProxies) != len(wantProxies) {
		t.Fatalf("TrustedProxies = %v, want %v", config.TrustedProxies, wantProxies)
	}
	for index := range wantProxies {
		if config.TrustedProxies[index] != wantProxies[index] {
			t.Errorf("TrustedProxies[%d] = %v, want %v", index, config.TrustedProxies[index], wantProxies[index])
		}
	}
}

func TestLoadAcceptsExplicitNonDefaultHTTPSPortAndIPv6(t *testing.T) {
	t.Parallel()

	config, err := Load([]string{
		"--listen", "[::1]:9080",
		"--public-origin", "https://[2001:db8::1]:8443",
	}, testEnvironment(nil))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if config.PublicOrigin != "https://[2001:db8::1]:8443" {
		t.Fatalf("PublicOrigin = %q", config.PublicOrigin)
	}
}

func TestLoadRejectsUnsafeListenAddress(t *testing.T) {
	t.Parallel()

	for _, address := range []string{
		"0.0.0.0:8080",
		"192.0.2.1:8080",
		"localhost:8080",
		"127.0.0.1:0",
		"127.0.0.1:not-a-port",
		"[fe80::1%lo]:8080",
		"[::ffff:127.0.0.1]:8080",
	} {
		t.Run(address, func(t *testing.T) {
			t.Parallel()
			_, err := Load([]string{"--listen", address}, testEnvironment(map[string]string{
				"ACMEMUX_PUBLIC_ORIGIN": "https://acmemux.example",
			}))
			if err == nil {
				t.Fatalf("Load() error = nil, want listen rejection for %q", address)
			}
		})
	}
}

func TestLoadRejectsUnsafeTrustedProxy(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		"192.0.2.1",
		"0.0.0.0/0",
		"127.0.0.1/8",
		"127.0.0.0/7",
		"::/0",
		"localhost",
		"127.0.0.1,,::1",
		"127.0.0.1,127.0.0.1/32",
	} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			_, err := Load(nil, testEnvironment(map[string]string{
				"ACMEMUX_PUBLIC_ORIGIN":   "https://acmemux.example",
				"ACMEMUX_TRUSTED_PROXIES": value,
			}))
			if err == nil {
				t.Fatalf("Load() error = nil, want trusted-proxy rejection for %q", value)
			}
		})
	}
}

func TestLoadRejectsOversizedEnvironmentValue(t *testing.T) {
	t.Parallel()

	_, err := Load(nil, func(name string) string {
		if name == "ACMEMUX_STATE_DIRECTORY" {
			return strings.Repeat("x", maximumValueLength+1)
		}
		if name == "ACMEMUX_PUBLIC_ORIGIN" {
			return "https://acmemux.example"
		}
		return ""
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("Load() error = %v, want bounded value error", err)
	}
}
