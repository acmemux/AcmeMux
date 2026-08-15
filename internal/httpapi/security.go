package httpapi

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// SecurityConfig defines the public browser boundary of the loopback service.
type SecurityConfig struct {
	PublicOrigin   string
	TrustedProxies []netip.Prefix
}

type requestSecurity struct {
	publicOrigin    string
	publicAuthority string
	trustedProxies  []netip.Prefix
}

func newRequestSecurity(config SecurityConfig) (requestSecurity, error) {
	origin, authority, err := validatePublicOrigin(config.PublicOrigin)
	if err != nil {
		return requestSecurity{}, err
	}
	if len(config.TrustedProxies) > 32 {
		return requestSecurity{}, errors.New("trusted proxy list exceeds 32 entries")
	}
	trustedProxies := make([]netip.Prefix, 0, len(config.TrustedProxies))
	seen := make(map[netip.Prefix]struct{}, len(config.TrustedProxies))
	for _, prefix := range config.TrustedProxies {
		masked := prefix.Masked()
		if !prefix.IsValid() || masked != prefix || !loopbackPrefix(prefix) {
			return requestSecurity{}, fmt.Errorf("trusted proxy %q must contain only loopback addresses", prefix)
		}
		if _, exists := seen[prefix]; exists {
			return requestSecurity{}, fmt.Errorf("trusted proxy %q is duplicated", prefix)
		}
		seen[prefix] = struct{}{}
		trustedProxies = append(trustedProxies, prefix)
	}
	return requestSecurity{
		publicOrigin:    origin,
		publicAuthority: authority,
		trustedProxies:  trustedProxies,
	}, nil
}

func validatePublicOrigin(value string) (string, string, error) {
	if value == "" || strings.TrimSpace(value) != value || len(value) > 4096 {
		return "", "", errors.New("public origin must be a bounded canonical HTTPS origin")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", "", fmt.Errorf("parse public origin: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" || parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", "", errors.New("public origin must be a canonical HTTPS origin without a path")
	}
	hostname := parsed.Hostname()
	if hostname == "" || hostname != strings.ToLower(hostname) || strings.HasSuffix(hostname, ".") || !asciiHost(hostname) {
		return "", "", errors.New("public origin hostname is not canonical")
	}
	if address, err := netip.ParseAddr(hostname); err == nil {
		if address.Zone() != "" || address.Is4In6() || address.String() != hostname {
			return "", "", errors.New("public origin IP address is not canonical")
		}
	} else if !validDNSHostname(hostname) {
		return "", "", errors.New("public origin hostname is invalid")
	}
	port := parsed.Port()
	if port != "" {
		parsedPort, err := strconv.ParseUint(port, 10, 16)
		if err != nil || parsedPort == 0 || parsedPort == 443 {
			return "", "", errors.New("public origin port is not canonical")
		}
	}
	authority := hostname
	if strings.Contains(hostname, ":") {
		authority = "[" + hostname + "]"
	}
	if port != "" {
		authority = net.JoinHostPort(hostname, port)
	}
	canonical := "https://" + authority
	if canonical != value {
		return "", "", errors.New("public origin is not canonical")
	}
	return canonical, authority, nil
}

func asciiHost(hostname string) bool {
	for _, character := range hostname {
		if character <= 32 || character > 126 {
			return false
		}
	}
	return true
}

func validDNSHostname(hostname string) bool {
	if len(hostname) > 253 {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func loopbackPrefix(prefix netip.Prefix) bool {
	address := prefix.Addr()
	if address.Is4() {
		return prefix.Bits() >= 8 && netip.MustParsePrefix("127.0.0.0/8").Contains(address)
	}
	return address == netip.IPv6Loopback() && prefix.Bits() == 128
}

func (security requestSecurity) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/healthz" && request.URL.Path != "/readyz" {
			if !security.validHost(request.Host) {
				writeAPIError(response, http.StatusMisdirectedRequest, "invalid_host", "The request host is not allowed.")
				return
			}
			if !security.validOrigin(request) {
				writeAPIError(response, http.StatusForbidden, "request_not_allowed", "The request origin is not allowed.")
				return
			}
		}
		next.ServeHTTP(response, request)
	})
}

func (security requestSecurity) validHost(host string) bool {
	return host == security.publicAuthority
}

func (security requestSecurity) validOrigin(request *http.Request) bool {
	values := request.Header.Values("Origin")
	if len(values) == 0 {
		return request.Method == http.MethodGet || request.Method == http.MethodHead || request.Method == http.MethodOptions
	}
	return len(values) == 1 && values[0] == security.publicOrigin
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		response.Header().Set("Strict-Transport-Security", "max-age=31536000")
		response.Header().Set("Referrer-Policy", "no-referrer")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(response, request)
	})
}
