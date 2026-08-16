package integrations

import (
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/sgurden-certleap/AcmeMux/internal/compatibility"
)

const (
	// CoreDNSManifestID extends the Task 07 native contract with the three
	// source-backed DNS providers delivered by Task 09.
	CoreDNSManifestID ManifestID = "native-core-dns-providers-v1"

	FieldChallengeDNSProvider                        FieldID = "challenge.dns.provider"
	FieldChallengeDNSTimeout                         FieldID = "challenge.dns.dns_timeout"
	FieldChallengeDNSResolvers                       FieldID = "challenge.dns.resolvers"
	FieldChallengeDNSEnvFile                         FieldID = "challenge.dns.env_file"
	FieldChallengeDNSDisableAuthoritativeNameservers FieldID = "challenge.dns.propagation.disable_authoritative_nameservers"
	FieldChallengeDNSDisableRecursiveNameservers     FieldID = "challenge.dns.propagation.disable_recursive_nameservers"
	FieldChallengeDNSPropagationWait                 FieldID = "challenge.dns.propagation.wait"

	FieldCloudflareEmail              FieldID = "provider.cloudflare.email"
	FieldCloudflareAPIKey             FieldID = "provider.cloudflare.api_key"
	FieldCloudflareDNSAPIToken        FieldID = "provider.cloudflare.dns_api_token"
	FieldCloudflareZoneAPIToken       FieldID = "provider.cloudflare.zone_api_token"
	FieldCloudflareEmailAlias         FieldID = "provider.cloudflare.email_alias"
	FieldCloudflareAPIKeyAlias        FieldID = "provider.cloudflare.api_key_alias"
	FieldCloudflareDNSAPITokenAlias   FieldID = "provider.cloudflare.dns_api_token_alias"
	FieldCloudflareZoneAPITokenAlias  FieldID = "provider.cloudflare.zone_api_token_alias"
	FieldCloudflareBaseURL            FieldID = "provider.cloudflare.base_url"
	FieldCloudflareTTL                FieldID = "provider.cloudflare.ttl"
	FieldCloudflarePropagationTimeout FieldID = "provider.cloudflare.propagation_timeout"
	FieldCloudflarePollingInterval    FieldID = "provider.cloudflare.polling_interval"
	FieldCloudflareHTTPTimeout        FieldID = "provider.cloudflare.http_timeout"

	FieldDigitalOceanAuthToken          FieldID = "provider.digitalocean.auth_token"
	FieldDigitalOceanAPIURL             FieldID = "provider.digitalocean.api_url"
	FieldDigitalOceanTTL                FieldID = "provider.digitalocean.ttl"
	FieldDigitalOceanPropagationTimeout FieldID = "provider.digitalocean.propagation_timeout"
	FieldDigitalOceanPollingInterval    FieldID = "provider.digitalocean.polling_interval"
	FieldDigitalOceanHTTPTimeout        FieldID = "provider.digitalocean.http_timeout"

	FieldDuckDNSToken              FieldID = "provider.duckdns.token"
	FieldDuckDNSPropagationTimeout FieldID = "provider.duckdns.propagation_timeout"
	FieldDuckDNSPollingInterval    FieldID = "provider.duckdns.polling_interval"
	FieldDuckDNSHTTPTimeout        FieldID = "provider.duckdns.http_timeout"
	FieldDuckDNSSequenceInterval   FieldID = "provider.duckdns.sequence_interval"
)

var (
	coreDNSOnce     sync.Once
	coreDNSManifest Manifest
)

var providerFieldCodes = map[FieldID]string{
	FieldCloudflareEmail: "cloudflare", FieldCloudflareAPIKey: "cloudflare",
	FieldCloudflareDNSAPIToken: "cloudflare", FieldCloudflareZoneAPIToken: "cloudflare",
	FieldCloudflareEmailAlias: "cloudflare", FieldCloudflareAPIKeyAlias: "cloudflare",
	FieldCloudflareDNSAPITokenAlias: "cloudflare", FieldCloudflareZoneAPITokenAlias: "cloudflare",
	FieldCloudflareBaseURL: "cloudflare", FieldCloudflareTTL: "cloudflare",
	FieldCloudflarePropagationTimeout: "cloudflare", FieldCloudflarePollingInterval: "cloudflare",
	FieldCloudflareHTTPTimeout: "cloudflare",
	FieldDigitalOceanAuthToken: "digitalocean", FieldDigitalOceanAPIURL: "digitalocean",
	FieldDigitalOceanTTL: "digitalocean", FieldDigitalOceanPropagationTimeout: "digitalocean",
	FieldDigitalOceanPollingInterval: "digitalocean", FieldDigitalOceanHTTPTimeout: "digitalocean",
	FieldDuckDNSToken: "duckdns", FieldDuckDNSPropagationTimeout: "duckdns",
	FieldDuckDNSPollingInterval: "duckdns", FieldDuckDNSHTTPTimeout: "duckdns",
	FieldDuckDNSSequenceInterval: "duckdns",
}

func SupportedCoreDNSProviders() []string {
	return []string{"cloudflare", "digitalocean", "duckdns"}
}

func SupportedDNSProviders() []string {
	return []string{"azuredns", "cloudflare", "digitalocean", "duckdns", "route53"}
}

func SupportsCoreDNSProvider(code string) bool {
	for _, supported := range SupportedDNSProviders() {
		if code == supported {
			return true
		}
	}
	return false
}

// ProviderCodeForField identifies conditional dotenv fields without exposing
// native environment keys to a browser request.
func ProviderCodeForField(id FieldID) (string, bool) {
	code, ok := providerFieldCodes[id]
	return code, ok
}

func buildCoreDNSManifest() Manifest {
	return buildCoreDNSManifestForProviders(SupportedCoreDNSProviders())
}

func buildCoreDNSManifestForProviders(providers []string) Manifest {
	core := buildCoreManifest()
	dns := []SelectorSegment{YAMLKey("challenges"), YAMLBinding(BindingChallenge), YAMLKey("dns")}
	envFile := appendSelector(dns, "envFile")
	minimumZero, maximumTimeout := int64(0), int64(600)
	defaultZero := IntegerValue(0)
	defaultFalse := BooleanValue(false)
	defaultDuration := StringValue("0s")
	fields := []FieldSpec{
		mustField(FieldDefinition{ID: FieldChallengeDNSProvider, Label: "DNS provider", Kind: FieldString, Target: TargetYAML,
			Sensitivity: SensitivityPublic, Disposition: DispositionManaged, Selector: appendSelector(dns, "provider"),
			Rules: Rules{MaxBytes: 32, Enum: providers}}),
		mustField(FieldDefinition{ID: FieldChallengeDNSTimeout, Label: "DNS resolver timeout", Kind: FieldInteger, Target: TargetYAML,
			Sensitivity: SensitivityPublic, Disposition: DispositionManaged, Selector: appendSelector(dns, "dnsTimeout"), Default: &defaultZero,
			Rules: Rules{Minimum: &minimumZero, Maximum: &maximumTimeout}}),
		mustField(FieldDefinition{ID: FieldChallengeDNSResolvers, Label: "Recursive DNS resolvers", Kind: FieldStringList, Target: TargetYAML,
			Sensitivity: SensitivityPublic, Disposition: DispositionManaged, Selector: appendSelector(dns, "resolvers"),
			Rules: Rules{AllowEmpty: true, MaxItems: 8, MaxBytes: 256}}),
		mustField(FieldDefinition{ID: FieldChallengeDNSEnvFile, Label: "Provider credential file", Kind: FieldString, Target: TargetYAML,
			Sensitivity: SensitivityPublic, Disposition: DispositionManaged, Selector: envFile, Rules: Rules{MaxBytes: 4095}}),
		mustField(FieldDefinition{ID: FieldChallengeDNSDisableAuthoritativeNameservers, Label: "Disable authoritative nameserver checks", Kind: FieldBoolean, Target: TargetYAML,
			Sensitivity: SensitivityPublic, Disposition: DispositionManaged, Selector: appendSelector(dns, "propagation", "disableAuthoritativeNameservers"), Default: &defaultFalse}),
		mustField(FieldDefinition{ID: FieldChallengeDNSDisableRecursiveNameservers, Label: "Disable recursive nameserver checks", Kind: FieldBoolean, Target: TargetYAML,
			Sensitivity: SensitivityPublic, Disposition: DispositionManaged, Selector: appendSelector(dns, "propagation", "disableRecursiveNameservers"), Default: &defaultFalse}),
		mustField(FieldDefinition{ID: FieldChallengeDNSPropagationWait, Label: "Fixed propagation wait", Kind: FieldString, Target: TargetYAML,
			Sensitivity: SensitivityPublic, Disposition: DispositionManaged, Selector: appendSelector(dns, "propagation", "wait"), Default: &defaultDuration,
			Rules: Rules{MaxBytes: 64}}),
	}
	fields = append(fields,
		dotenvField(FieldCloudflareEmail, "Cloudflare legacy account email", SensitivityPublic, envFile, "CLOUDFLARE_EMAIL", 254),
		dotenvField(FieldCloudflareAPIKey, "Cloudflare legacy global API key", SensitivitySecret, envFile, "CLOUDFLARE_API_KEY", 4096),
		dotenvField(FieldCloudflareDNSAPIToken, "Cloudflare DNS API token", SensitivitySecret, envFile, "CLOUDFLARE_DNS_API_TOKEN", 4096),
		dotenvField(FieldCloudflareZoneAPIToken, "Cloudflare zone API token", SensitivitySecret, envFile, "CLOUDFLARE_ZONE_API_TOKEN", 4096),
		dotenvField(FieldCloudflareEmailAlias, "Cloudflare legacy CF account email", SensitivityPublic, envFile, "CF_API_EMAIL", 254),
		dotenvField(FieldCloudflareAPIKeyAlias, "Cloudflare legacy CF global API key", SensitivitySecret, envFile, "CF_API_KEY", 4096),
		dotenvField(FieldCloudflareDNSAPITokenAlias, "Cloudflare CF DNS API token", SensitivitySecret, envFile, "CF_DNS_API_TOKEN", 4096),
		dotenvField(FieldCloudflareZoneAPITokenAlias, "Cloudflare CF zone API token", SensitivitySecret, envFile, "CF_ZONE_API_TOKEN", 4096),
		dotenvField(FieldCloudflareBaseURL, "Cloudflare API base URL", SensitivityPublic, envFile, "CLOUDFLARE_BASE_URL", 2048),
		dotenvField(FieldCloudflareTTL, "Cloudflare TXT TTL", SensitivityPublic, envFile, "CLOUDFLARE_TTL", 10),
		dotenvField(FieldCloudflarePropagationTimeout, "Cloudflare propagation timeout", SensitivityPublic, envFile, "CLOUDFLARE_PROPAGATION_TIMEOUT", 10),
		dotenvField(FieldCloudflarePollingInterval, "Cloudflare polling interval", SensitivityPublic, envFile, "CLOUDFLARE_POLLING_INTERVAL", 10),
		dotenvField(FieldCloudflareHTTPTimeout, "Cloudflare HTTP timeout", SensitivityPublic, envFile, "CLOUDFLARE_HTTP_TIMEOUT", 10),
		dotenvField(FieldDigitalOceanAuthToken, "DigitalOcean API token", SensitivitySecret, envFile, "DO_AUTH_TOKEN", 4096),
		dotenvField(FieldDigitalOceanAPIURL, "DigitalOcean API URL", SensitivityPublic, envFile, "DO_API_URL", 2048),
		dotenvField(FieldDigitalOceanTTL, "DigitalOcean TXT TTL", SensitivityPublic, envFile, "DO_TTL", 10),
		dotenvField(FieldDigitalOceanPropagationTimeout, "DigitalOcean propagation timeout", SensitivityPublic, envFile, "DO_PROPAGATION_TIMEOUT", 10),
		dotenvField(FieldDigitalOceanPollingInterval, "DigitalOcean polling interval", SensitivityPublic, envFile, "DO_POLLING_INTERVAL", 10),
		dotenvField(FieldDigitalOceanHTTPTimeout, "DigitalOcean HTTP timeout", SensitivityPublic, envFile, "DO_HTTP_TIMEOUT", 10),
		dotenvField(FieldDuckDNSToken, "DuckDNS account token", SensitivitySecret, envFile, "DUCKDNS_TOKEN", 4096),
		dotenvField(FieldDuckDNSPropagationTimeout, "DuckDNS propagation timeout", SensitivityPublic, envFile, "DUCKDNS_PROPAGATION_TIMEOUT", 10),
		dotenvField(FieldDuckDNSPollingInterval, "DuckDNS polling interval", SensitivityPublic, envFile, "DUCKDNS_POLLING_INTERVAL", 10),
		dotenvField(FieldDuckDNSHTTPTimeout, "DuckDNS HTTP timeout", SensitivityPublic, envFile, "DUCKDNS_HTTP_TIMEOUT", 10),
		dotenvField(FieldDuckDNSSequenceInterval, "DuckDNS sequential request interval", SensitivityPublic, envFile, "DUCKDNS_SEQUENCE_INTERVAL", 10),
	)
	manifest, err := core.Extend(CoreDNSManifestID, fields...)
	if err != nil {
		panic("invalid core DNS integration manifest: " + err.Error())
	}
	return manifest
}

func dotenvField(id FieldID, label string, sensitivity Sensitivity, selector []SelectorSegment, key string, maximum int) FieldSpec {
	return mustField(FieldDefinition{ID: id, Label: label, Kind: FieldString, Target: TargetDotenv,
		Sensitivity: sensitivity, Disposition: DispositionManaged, Selector: selector, EnvironmentKey: key,
		Rules: Rules{MaxBytes: maximum}})
}

// CoreDNSManifest returns the Task 09 contract for one exact admitted runtime.
func CoreDNSManifest(runtimeID compatibility.ManifestID) (Manifest, bool) {
	coreDNSOnce.Do(func() { coreDNSManifest = buildCoreDNSManifest() })
	if !coreDNSManifest.SupportsRuntime(runtimeID) {
		return Manifest{}, false
	}
	return coreDNSManifest, true
}

// ValidateCoreDNSDotenvValue applies source-backed provider semantics to one
// exact allowlisted dotenv value. Errors never echo the rejected value.
func ValidateCoreDNSDotenvValue(id FieldID, value []byte) error {
	text := string(value)
	switch id {
	case FieldCloudflareEmail, FieldCloudflareEmailAlias:
		address, err := mail.ParseAddress(text)
		if err != nil || address.Address != text || address.Name != "" || !strings.Contains(text, "@") {
			return fmt.Errorf("provider account email is invalid")
		}
	case FieldCloudflareBaseURL, FieldDigitalOceanAPIURL:
		parsed, err := url.Parse(text)
		if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return fmt.Errorf("provider endpoint is invalid")
		}
		loopback := net.ParseIP(parsed.Hostname()) != nil && net.ParseIP(parsed.Hostname()).IsLoopback()
		if parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopback) {
			return fmt.Errorf("provider endpoint must use HTTPS or loopback HTTP")
		}
	case FieldCloudflareTTL:
		return validateDecimalRange(text, 120, 86400)
	case FieldDigitalOceanTTL:
		return validateDecimalRange(text, 1, 86400)
	case FieldCloudflarePropagationTimeout, FieldCloudflarePollingInterval, FieldCloudflareHTTPTimeout,
		FieldDigitalOceanPropagationTimeout, FieldDigitalOceanPollingInterval, FieldDigitalOceanHTTPTimeout,
		FieldDuckDNSPropagationTimeout, FieldDuckDNSPollingInterval, FieldDuckDNSHTTPTimeout, FieldDuckDNSSequenceInterval:
		return validateDecimalRange(text, 1, 3600)
	}
	return ValidateCloudDNSDotenvValue(id, value)
}

func validateDecimalRange(value string, minimum, maximum int64) error {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || strconv.FormatInt(parsed, 10) != value || parsed < minimum || parsed > maximum {
		return fmt.Errorf("provider numeric setting is outside its curated range")
	}
	return nil
}

// CoreDNSCredentialIssues returns logical fields involved in an invalid or
// mixed authentication selection. A nil result is a complete accepted mode.
func CoreDNSCredentialIssues(provider string, present map[FieldID]bool) []FieldID {
	presentCount := func(fields ...FieldID) int {
		count := 0
		for _, field := range fields {
			if present[field] {
				count++
			}
		}
		return count
	}
	switch provider {
	case "cloudflare":
		email := presentCount(FieldCloudflareEmail, FieldCloudflareEmailAlias)
		key := presentCount(FieldCloudflareAPIKey, FieldCloudflareAPIKeyAlias)
		dnsToken := presentCount(FieldCloudflareDNSAPIToken, FieldCloudflareDNSAPITokenAlias)
		zoneToken := presentCount(FieldCloudflareZoneAPIToken, FieldCloudflareZoneAPITokenAlias)
		legacyValid := email == 1 && key == 1 && dnsToken == 0 && zoneToken == 0
		tokenValid := email == 0 && key == 0 && dnsToken == 1 && zoneToken <= 1
		if legacyValid || tokenValid {
			return nil
		}
		return []FieldID{FieldCloudflareEmail, FieldCloudflareAPIKey, FieldCloudflareDNSAPIToken, FieldCloudflareZoneAPIToken}
	case "digitalocean":
		if present[FieldDigitalOceanAuthToken] {
			return nil
		}
		return []FieldID{FieldDigitalOceanAuthToken}
	case "duckdns":
		if present[FieldDuckDNSToken] {
			return nil
		}
		return []FieldID{FieldDuckDNSToken}
	default:
		// Cloud provider modes are value-aware and are validated by
		// CloudDNSCredentialIssues after dotenv projection.
		if provider == "azuredns" || provider == "route53" {
			return nil
		}
		return []FieldID{FieldChallengeDNSProvider}
	}
}
