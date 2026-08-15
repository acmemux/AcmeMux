package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestClientIPResolverIgnoresHeadersFromUntrustedPeer(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodPost, testPublicOrigin+"/api/v1/session", nil)
	request.RemoteAddr = "192.0.2.10:41000"
	request.Header.Set("X-Forwarded-For", "198.51.100.20")
	request.Header.Set("X-Real-IP", "198.51.100.21")
	request.Header.Set("Forwarded", "for=198.51.100.22;proto=https;host=attacker.invalid")
	resolver := NewClientIPResolver([]netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	if got := resolver.Resolve(request); got != netip.MustParseAddr("192.0.2.10") {
		t.Fatalf("Resolve() = %v, want direct peer", got)
	}
}

func TestUntrustedForwardingCannotCreateFreshRateLimitIdentities(t *testing.T) {
	t.Parallel()

	limiter := limiterForTest(t, func(config *loginLimiterConfig) {
		config.perClientCapacity = 1
	})
	resolver := NewClientIPResolver([]netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	now := time.Unix(1_700_000_000, 0)
	for index, spoofed := range []string{"198.51.100.1", "198.51.100.2"} {
		request := httptest.NewRequest(http.MethodPost, testPublicOrigin+"/api/v1/session", nil)
		request.RemoteAddr = "192.0.2.10:41000"
		request.Header.Set("X-Forwarded-For", spoofed)
		allowed, _ := limiter.Allow(resolver.Resolve(request), now)
		if allowed != (index == 0) {
			t.Fatalf("attempt %d with spoofed client %s allowed = %v", index, spoofed, allowed)
		}
	}
}

func TestTrustedProxyCanSeparateActualRateLimitClients(t *testing.T) {
	t.Parallel()

	limiter := limiterForTest(t, func(config *loginLimiterConfig) {
		config.perClientCapacity = 1
	})
	resolver := NewClientIPResolver([]netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	now := time.Unix(1_700_000_000, 0)
	for _, forwarded := range []string{"198.51.100.1", "198.51.100.2"} {
		request := httptest.NewRequest(http.MethodPost, testPublicOrigin+"/api/v1/session", nil)
		request.RemoteAddr = "127.0.0.1:41000"
		request.Header.Set("X-Forwarded-For", forwarded)
		if allowed, _ := limiter.Allow(resolver.Resolve(request), now); !allowed {
			t.Fatalf("trusted proxy client %s was unexpectedly limited", forwarded)
		}
	}
}

func TestClientIPResolverFailsClosedForInvalidTrustConfiguration(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodGet, testPublicOrigin, nil)
	request.RemoteAddr = "192.0.2.10:41000"
	request.Header.Set("X-Forwarded-For", "198.51.100.20")
	resolver := NewClientIPResolver([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
	if got := resolver.Resolve(request); got != netip.MustParseAddr("192.0.2.10") {
		t.Fatalf("Resolve() = %v, want invalid trust entry ignored", got)
	}
}

func TestClientIPResolverUsesFirstUntrustedAddressFromRight(t *testing.T) {
	t.Parallel()

	resolver := NewClientIPResolver([]netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
	})
	for _, test := range []struct {
		name      string
		remote    string
		forwarded []string
		want      string
	}{
		{name: "missing", remote: "127.0.0.1:4000", want: "127.0.0.1"},
		{name: "one hop", remote: "127.0.0.1:4000", forwarded: []string{"198.51.100.10"}, want: "198.51.100.10"},
		{name: "spoofed leftmost", remote: "127.0.0.1:4000", forwarded: []string{"203.0.113.99, 198.51.100.10"}, want: "198.51.100.10"},
		{name: "trusted suffix", remote: "127.0.0.1:4000", forwarded: []string{"203.0.113.99, 198.51.100.10, 127.0.0.8"}, want: "198.51.100.10"},
		{name: "multiple fields", remote: "127.0.0.1:4000", forwarded: []string{"203.0.113.99", "198.51.100.10, 127.0.0.8"}, want: "198.51.100.10"},
		{name: "all trusted", remote: "127.0.0.1:4000", forwarded: []string{"127.0.0.2, 127.0.0.8"}, want: "127.0.0.1"},
		{name: "mapped peer", remote: "[::ffff:127.0.0.1]:4000", forwarded: []string{"198.51.100.10"}, want: "198.51.100.10"},
		{name: "IPv6 client", remote: "127.0.0.1:4000", forwarded: []string{"2001:db8::10"}, want: "2001:db8::10"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequest(http.MethodGet, testPublicOrigin, nil)
			request.RemoteAddr = test.remote
			for _, value := range test.forwarded {
				request.Header.Add("X-Forwarded-For", value)
			}
			if got := resolver.Resolve(request); got != netip.MustParseAddr(test.want) {
				t.Fatalf("Resolve() = %v, want %s", got, test.want)
			}
		})
	}
}

func TestClientIPResolverFallsBackForMalformedOrUnboundedChain(t *testing.T) {
	t.Parallel()

	resolver := NewClientIPResolver([]netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	tooMany := make([]string, maximumForwardedForHops+1)
	for index := range tooMany {
		tooMany[index] = "198.51.100.10"
	}
	for _, value := range []string{
		"not-an-ip",
		"198.51.100.10,",
		"198.51.100.10:8080",
		"[2001:db8::10]",
		strings.Join(tooMany, ","),
		strings.Repeat("1", maximumForwardedForBytes+1),
	} {
		request := httptest.NewRequest(http.MethodGet, testPublicOrigin, nil)
		request.RemoteAddr = "127.0.0.1:4000"
		request.Header.Set("X-Forwarded-For", value)
		if got := resolver.Resolve(request); got != netip.MustParseAddr("127.0.0.1") {
			t.Errorf("Resolve(X-Forwarded-For=%q) = %v, want peer", value, got)
		}
	}
}

func TestClientIPResolverReturnsInvalidForMalformedRemoteAddress(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodGet, testPublicOrigin, nil)
	request.RemoteAddr = "malformed"
	request.Header.Set("X-Forwarded-For", "198.51.100.10")
	if got := (ClientIPResolver{}).Resolve(request); got.IsValid() {
		t.Fatalf("Resolve() = %v, want invalid address", got)
	}
}
