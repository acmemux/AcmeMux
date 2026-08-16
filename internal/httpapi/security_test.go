package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"testing/fstest"
)

func TestRequestBoundaryRequiresExactPublicHost(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t, readinessStub{}, fstest.MapFS{"index.html": {Data: []byte("browser")}})
	for _, test := range []struct {
		name string
		host string
		want int
	}{
		{name: "exact", host: "acmemux.example", want: http.StatusOK},
		{name: "case differs", host: "AcmeMux.example", want: http.StatusMisdirectedRequest},
		{name: "default port", host: "acmemux.example:443", want: http.StatusMisdirectedRequest},
		{name: "subdomain", host: "control.acmemux.example", want: http.StatusMisdirectedRequest},
		{name: "suffix", host: "acmemux.example.attacker.invalid", want: http.StatusMisdirectedRequest},
		{name: "trailing dot", host: "acmemux.example.", want: http.StatusMisdirectedRequest},
		{name: "absent", host: "", want: http.StatusMisdirectedRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.Host = test.host
			request.Header.Set("X-Forwarded-Host", "acmemux.example")
			request.Header.Set("X-Forwarded-Proto", "https")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d", response.Code, test.want)
			}
		})
	}
}

func TestRequestBoundaryRequiresExactOrigin(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t, readinessStub{}, fstest.MapFS{"index.html": {Data: []byte("browser")}})
	for _, test := range []struct {
		name    string
		method  string
		origins []string
		want    int
	}{
		{name: "safe absent", method: http.MethodGet, want: http.StatusNotFound},
		{name: "safe exact", method: http.MethodGet, origins: []string{testPublicOrigin}, want: http.StatusNotFound},
		{name: "safe cross origin", method: http.MethodGet, origins: []string{"https://attacker.invalid"}, want: http.StatusForbidden},
		{name: "unsafe exact", method: http.MethodPost, origins: []string{testPublicOrigin}, want: http.StatusNotFound},
		{name: "unsafe absent", method: http.MethodPost, want: http.StatusForbidden},
		{name: "null", method: http.MethodPost, origins: []string{"null"}, want: http.StatusForbidden},
		{name: "HTTP", method: http.MethodPost, origins: []string{"http://acmemux.example"}, want: http.StatusForbidden},
		{name: "default port", method: http.MethodPost, origins: []string{"https://acmemux.example:443"}, want: http.StatusForbidden},
		{name: "subdomain", method: http.MethodPost, origins: []string{"https://control.acmemux.example"}, want: http.StatusForbidden},
		{name: "suffix", method: http.MethodPost, origins: []string{"https://acmemux.example.attacker.invalid"}, want: http.StatusForbidden},
		{name: "path", method: http.MethodPost, origins: []string{"https://acmemux.example/path"}, want: http.StatusForbidden},
		{name: "comma joined", method: http.MethodPost, origins: []string{"https://acmemux.example, https://attacker.invalid"}, want: http.StatusForbidden},
		{name: "multiple", method: http.MethodPost, origins: []string{testPublicOrigin, "https://attacker.invalid"}, want: http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequest(test.method, "/api/v1/unknown", nil)
			request.Host = "acmemux.example"
			for _, origin := range test.origins {
				request.Header.Add("Origin", origin)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, test.want, response.Body.String())
			}
			if response.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("request boundary unexpectedly emitted a CORS origin")
			}
		})
	}
}

func TestTrustedForwardedHostAndProtoNeverAffectSecurityDecisions(t *testing.T) {
	t.Parallel()

	handler, err := New(
		readinessStub{},
		sharedTestIdentity(t),
		testRuntimeDependencies(),
		testWorkspaceDependencies(),
		testConfigurationDependencies(),
		fstest.MapFS{"index.html": {Data: []byte("browser")}},
		SecurityConfig{
			PublicOrigin:   testPublicOrigin,
			TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		},
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	wrongHost := httptest.NewRequest(http.MethodPost, "/api/v1/unknown", nil)
	wrongHost.RemoteAddr = "127.0.0.1:41000"
	wrongHost.Host = "attacker.invalid"
	wrongHost.Header.Set("Origin", testPublicOrigin)
	wrongHost.Header.Set("X-Forwarded-Host", "acmemux.example")
	wrongHost.Header.Set("X-Forwarded-Proto", "https")
	wrongHostResponse := httptest.NewRecorder()
	handler.ServeHTTP(wrongHostResponse, wrongHost)
	if wrongHostResponse.Code != http.StatusMisdirectedRequest {
		t.Fatalf("forwarded host changed decision: status = %d", wrongHostResponse.Code)
	}

	wrongOrigin := httptest.NewRequest(http.MethodPost, "/api/v1/unknown", nil)
	wrongOrigin.RemoteAddr = "127.0.0.1:41000"
	wrongOrigin.Host = "acmemux.example"
	wrongOrigin.Header.Set("Origin", "https://attacker.invalid")
	wrongOrigin.Header.Set("X-Forwarded-Host", "acmemux.example")
	wrongOrigin.Header.Set("X-Forwarded-Proto", "https")
	wrongOriginResponse := httptest.NewRecorder()
	handler.ServeHTTP(wrongOriginResponse, wrongOrigin)
	if wrongOriginResponse.Code != http.StatusForbidden {
		t.Fatalf("forwarded proto changed decision: status = %d", wrongOriginResponse.Code)
	}
}

func TestSecurityConfigRejectsUnsafeTrustedProxyRanges(t *testing.T) {
	t.Parallel()

	for _, prefix := range []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("192.0.2.1/32"),
		netip.MustParsePrefix("::/0"),
		netip.MustParsePrefix("127.0.0.0/7"),
	} {
		_, err := newRequestSecurity(SecurityConfig{
			PublicOrigin:   testPublicOrigin,
			TrustedProxies: []netip.Prefix{prefix},
		})
		if err == nil {
			t.Errorf("newRequestSecurity(%s) error = nil", prefix)
		}
	}
}

func TestSecurityConfigAcceptsCanonicalAuthorities(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		origin    string
		authority string
	}{
		{origin: "https://acmemux.example", authority: "acmemux.example"},
		{origin: "https://acmemux.example:8443", authority: "acmemux.example:8443"},
		{origin: "https://127.0.0.1", authority: "127.0.0.1"},
		{origin: "https://[2001:db8::1]", authority: "[2001:db8::1]"},
		{origin: "https://[2001:db8::1]:8443", authority: "[2001:db8::1]:8443"},
	} {
		security, err := newRequestSecurity(SecurityConfig{PublicOrigin: test.origin})
		if err != nil {
			t.Errorf("newRequestSecurity(%q) error = %v", test.origin, err)
			continue
		}
		if security.publicAuthority != test.authority {
			t.Errorf("newRequestSecurity(%q) authority = %q, want %q", test.origin, security.publicAuthority, test.authority)
		}
	}
}

func TestSecurityConfigBoundsAndDeduplicatesTrustedProxyConfiguration(t *testing.T) {
	t.Parallel()

	duplicate := netip.MustParsePrefix("127.0.0.1/32")
	if _, err := newRequestSecurity(SecurityConfig{
		PublicOrigin:   testPublicOrigin,
		TrustedProxies: []netip.Prefix{duplicate, duplicate},
	}); err == nil {
		t.Fatal("duplicate trusted proxies were accepted")
	}

	tooMany := make([]netip.Prefix, 33)
	for index := range tooMany {
		tooMany[index] = netip.PrefixFrom(netip.AddrFrom4([4]byte{127, 0, 0, byte(index + 1)}), 32)
	}
	if _, err := newRequestSecurity(SecurityConfig{
		PublicOrigin:   testPublicOrigin,
		TrustedProxies: tooMany,
	}); err == nil {
		t.Fatal("unbounded trusted proxy list was accepted")
	}
}

func TestSecurityConfigDefensivelyCopiesTrustedProxies(t *testing.T) {
	t.Parallel()

	prefixes := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	security, err := newRequestSecurity(SecurityConfig{PublicOrigin: testPublicOrigin, TrustedProxies: prefixes})
	if err != nil {
		t.Fatalf("newRequestSecurity() error = %v", err)
	}
	prefixes[0] = netip.MustParsePrefix("127.0.0.2/32")
	if security.trustedProxies[0] != netip.MustParsePrefix("127.0.0.1/32") {
		t.Fatalf("trusted proxy slice was not copied: %v", security.trustedProxies)
	}
}
