// Package appconfig loads and validates bounded service configuration.
package appconfig

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	defaultListenAddress  = "127.0.0.1:8080"
	defaultStateDirectory = "./var"
	maximumValueLength    = 4096
	maximumTrustedProxies = 32
)

// Config contains the process-level settings needed by the foundation service.
type Config struct {
	ListenAddress  string
	StateDirectory string
	PublicOrigin   string
	TrustedProxies []netip.Prefix
}

// Load parses command-line arguments over bounded environment defaults.
func Load(arguments []string, getenv func(string) string) (Config, error) {
	listenDefault, err := environmentDefault(getenv, "ACMEMUX_LISTEN_ADDRESS", defaultListenAddress)
	if err != nil {
		return Config{}, err
	}
	stateDefault, err := environmentDefault(getenv, "ACMEMUX_STATE_DIRECTORY", defaultStateDirectory)
	if err != nil {
		return Config{}, err
	}
	publicOriginDefault, err := environmentDefault(getenv, "ACMEMUX_PUBLIC_ORIGIN", "")
	if err != nil {
		return Config{}, err
	}
	trustedProxiesDefault, err := environmentDefault(getenv, "ACMEMUX_TRUSTED_PROXIES", "")
	if err != nil {
		return Config{}, err
	}

	flags := flag.NewFlagSet("acmemux serve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	listen := flags.String("listen", listenDefault, "loopback listen address")
	stateDirectory := flags.String("state-dir", stateDefault, "application state directory")
	publicOrigin := flags.String("public-origin", publicOriginDefault, "public HTTPS browser origin")
	trustedProxiesValue := flags.String("trusted-proxies", trustedProxiesDefault, "comma-separated trusted loopback proxy IPs or CIDRs")
	if err := flags.Parse(arguments); err != nil {
		return Config{}, err
	}
	if flags.NArg() != 0 {
		return Config{}, fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if err := validateLoopback(*listen); err != nil {
		return Config{}, err
	}
	if *stateDirectory == "" || len(*stateDirectory) > maximumValueLength {
		return Config{}, errors.New("state directory must be between 1 and 4096 bytes")
	}
	absoluteStateDirectory, err := filepath.Abs(*stateDirectory)
	if err != nil {
		return Config{}, fmt.Errorf("resolve state directory: %w", err)
	}
	canonicalPublicOrigin, err := canonicalPublicOrigin(*publicOrigin)
	if err != nil {
		return Config{}, err
	}
	trustedProxies, err := parseTrustedProxies(*trustedProxiesValue)
	if err != nil {
		return Config{}, err
	}

	return Config{
		ListenAddress:  *listen,
		StateDirectory: absoluteStateDirectory,
		PublicOrigin:   canonicalPublicOrigin,
		TrustedProxies: trustedProxies,
	}, nil
}

func environmentDefault(getenv func(string) string, name, fallback string) (string, error) {
	value := getenv(name)
	if value == "" {
		return fallback, nil
	}
	if len(value) > maximumValueLength {
		return "", fmt.Errorf("%s exceeds 4096 bytes", name)
	}
	return value, nil
}

func validateLoopback(address string) error {
	if len(address) > maximumValueLength {
		return errors.New("listen address exceeds 4096 bytes")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return fmt.Errorf("listen address must include a loopback host and port: %q", address)
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 {
		return fmt.Errorf("listen address must include a valid port: %q", address)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" || ip.Is4In6() || !ip.IsLoopback() {
		return fmt.Errorf("listen address must be loopback-only: %q", address)
	}
	return nil
}

func canonicalPublicOrigin(value string) (string, error) {
	if value == "" {
		return "", errors.New("public origin is required")
	}
	if len(value) > maximumValueLength || strings.TrimSpace(value) != value {
		return "", errors.New("public origin must be a bounded canonical HTTPS origin")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("parse public origin: %w", err)
	}
	if !strings.EqualFold(parsed.Scheme, "https") || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") || (parsed.RawPath != "" && parsed.RawPath != "/") {
		return "", errors.New("public origin must contain only an HTTPS scheme and authority")
	}

	hostname := parsed.Hostname()
	if hostname == "" || strings.HasSuffix(hostname, ".") || !isASCIIHostname(hostname) {
		return "", errors.New("public origin must contain a canonical ASCII hostname or IP address")
	}
	canonicalHostname, err := canonicalHostname(hostname)
	if err != nil {
		return "", err
	}
	port := parsed.Port()
	if port != "" {
		parsedPort, err := strconv.ParseUint(port, 10, 16)
		if err != nil || parsedPort == 0 {
			return "", errors.New("public origin contains an invalid port")
		}
		if parsedPort == 443 {
			port = ""
		}
	}
	authority := canonicalHostname
	if strings.Contains(canonicalHostname, ":") {
		authority = "[" + canonicalHostname + "]"
	}
	if port != "" {
		authority = net.JoinHostPort(canonicalHostname, port)
	}
	return "https://" + authority, nil
}

func canonicalHostname(hostname string) (string, error) {
	if address, err := netip.ParseAddr(hostname); err == nil {
		if address.Zone() != "" || address.Is4In6() {
			return "", errors.New("public origin contains a non-canonical IP address")
		}
		return address.String(), nil
	}

	hostname = strings.ToLower(hostname)
	if len(hostname) > 253 {
		return "", errors.New("public origin hostname is too long")
	}
	for _, label := range strings.Split(hostname, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("public origin contains an invalid hostname")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", errors.New("public origin contains an invalid hostname")
			}
		}
	}
	return hostname, nil
}

func isASCIIHostname(hostname string) bool {
	for _, character := range hostname {
		if character > 127 || character <= 32 || character == 127 {
			return false
		}
	}
	return true
}

func parseTrustedProxies(value string) ([]netip.Prefix, error) {
	if value == "" {
		return nil, nil
	}
	if len(value) > maximumValueLength {
		return nil, errors.New("trusted proxy list exceeds 4096 bytes")
	}
	parts := strings.Split(value, ",")
	if len(parts) > maximumTrustedProxies {
		return nil, fmt.Errorf("trusted proxy list exceeds %d entries", maximumTrustedProxies)
	}

	result := make([]netip.Prefix, 0, len(parts))
	seen := make(map[netip.Prefix]struct{}, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, errors.New("trusted proxy list contains an empty entry")
		}
		prefix, err := parseTrustedProxy(part)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[prefix]; exists {
			return nil, fmt.Errorf("trusted proxy %q is duplicated", part)
		}
		seen[prefix] = struct{}{}
		result = append(result, prefix)
	}
	return result, nil
}

func parseTrustedProxy(value string) (netip.Prefix, error) {
	var prefix netip.Prefix
	if strings.Contains(value, "/") {
		parsed, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("trusted proxy %q is not an IP address or CIDR", value)
		}
		prefix = parsed.Masked()
		if prefix != parsed {
			return netip.Prefix{}, fmt.Errorf("trusted proxy %q is not a canonical CIDR", value)
		}
	} else {
		address, err := netip.ParseAddr(value)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("trusted proxy %q is not an IP address or CIDR", value)
		}
		if address.Is4In6() || address.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("trusted proxy %q is not canonical", value)
		}
		prefix = netip.PrefixFrom(address, address.BitLen())
	}
	if !isLoopbackPrefix(prefix) {
		return netip.Prefix{}, fmt.Errorf("trusted proxy %q must contain only loopback addresses", value)
	}
	return prefix, nil
}

func isLoopbackPrefix(prefix netip.Prefix) bool {
	address := prefix.Addr()
	if address.Is4() {
		return prefix.Bits() >= 8 && netip.MustParsePrefix("127.0.0.0/8").Contains(address)
	}
	return address == netip.IPv6Loopback() && prefix.Bits() == 128
}
