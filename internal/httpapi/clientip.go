package httpapi

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

const (
	maximumForwardedForBytes = 4096
	maximumForwardedForHops  = 16
)

// ClientIPResolver derives a rate-limit identity without allowing an
// untrusted peer to select it through forwarding headers.
type ClientIPResolver struct {
	trustedProxies []netip.Prefix
}

// NewClientIPResolver returns a resolver with a defensive copy of the trusted
// proxy prefixes. SecurityConfig validation must run before construction.
func NewClientIPResolver(trustedProxies []netip.Prefix) ClientIPResolver {
	cloned := make([]netip.Prefix, 0, len(trustedProxies))
	for _, prefix := range trustedProxies {
		if len(cloned) >= 32 || !prefix.IsValid() || prefix.Masked() != prefix || !loopbackPrefix(prefix) {
			continue
		}
		cloned = append(cloned, prefix)
	}
	return ClientIPResolver{trustedProxies: cloned}
}

// Resolve returns the direct peer unless that peer is trusted and a bounded,
// valid X-Forwarded-For chain identifies the first untrusted hop from the
// right. Forwarded host, scheme, and X-Real-IP never participate.
func (resolver ClientIPResolver) Resolve(request *http.Request) netip.Addr {
	peer := parseRemoteAddress(request.RemoteAddr)
	if !peer.IsValid() || !resolver.isTrusted(peer) {
		return peer
	}

	values := request.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return peer
	}
	joined := strings.Join(values, ",")
	if len(joined) == 0 || len(joined) > maximumForwardedForBytes {
		return peer
	}
	parts := strings.Split(joined, ",")
	if len(parts) == 0 || len(parts) > maximumForwardedForHops {
		return peer
	}

	chain := make([]netip.Addr, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		address, err := netip.ParseAddr(part)
		if err != nil || address.Zone() != "" {
			return peer
		}
		chain = append(chain, address.Unmap())
	}
	for index := len(chain) - 1; index >= 0; index-- {
		if !resolver.isTrusted(chain[index]) {
			return chain[index]
		}
	}
	return peer
}

func (resolver ClientIPResolver) isTrusted(address netip.Addr) bool {
	address = address.Unmap()
	for _, prefix := range resolver.trustedProxies {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func parseRemoteAddress(remoteAddress string) netip.Addr {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		return netip.Addr{}
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.Zone() != "" {
		return netip.Addr{}
	}
	return address.Unmap()
}
