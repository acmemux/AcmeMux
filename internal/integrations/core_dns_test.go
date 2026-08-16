package integrations

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/sgurden-certleap/AcmeMux/internal/compatibility"
)

func TestCoreDNSManifestBindsExactProvidersAndRuntimeIdentities(t *testing.T) {
	for _, runtimeID := range []compatibility.ManifestID{compatibility.ManifestLegoV531, compatibility.ManifestLegoRevision2A58} {
		manifest, ok := CoreDNSManifest(runtimeID)
		if !ok || manifest.ID() != CoreDNSManifestID || !manifest.SupportsRuntime(runtimeID) {
			t.Fatalf("CoreDNSManifest(%s) = %#v, %v", runtimeID, manifest, ok)
		}
		for _, code := range []string{"cloudflare", "digitalocean", "duckdns"} {
			if !SupportsCoreDNSProvider(code) {
				t.Fatalf("provider %q is not supported", code)
			}
		}
	}
	if _, ok := CoreDNSManifest("unknown"); ok {
		t.Fatal("unknown runtime received the DNS manifest")
	}
}

func TestCoreDNSManifestEnvironmentKeysMatchExactUpstreamDescriptors(t *testing.T) {
	want := map[string][]string{
		"cloudflare": {
			"CF_API_EMAIL", "CF_API_KEY", "CF_DNS_API_TOKEN", "CF_ZONE_API_TOKEN",
			"CLOUDFLARE_API_KEY", "CLOUDFLARE_BASE_URL", "CLOUDFLARE_DNS_API_TOKEN", "CLOUDFLARE_EMAIL",
			"CLOUDFLARE_HTTP_TIMEOUT", "CLOUDFLARE_POLLING_INTERVAL", "CLOUDFLARE_PROPAGATION_TIMEOUT",
			"CLOUDFLARE_TTL", "CLOUDFLARE_ZONE_API_TOKEN",
		},
		"digitalocean": {"DO_API_URL", "DO_AUTH_TOKEN", "DO_HTTP_TIMEOUT", "DO_POLLING_INTERVAL", "DO_PROPAGATION_TIMEOUT", "DO_TTL"},
		"duckdns":      {"DUCKDNS_HTTP_TIMEOUT", "DUCKDNS_POLLING_INTERVAL", "DUCKDNS_PROPAGATION_TIMEOUT", "DUCKDNS_SEQUENCE_INTERVAL", "DUCKDNS_TOKEN"},
	}
	manifest, _ := CoreDNSManifest(compatibility.ManifestLegoV531)
	for _, runtimeDirectory := range []string{"lego-v5.3.1", "lego-revision-2a58c3522708"} {
		for provider, expected := range want {
			descriptor, err := os.ReadFile("../compatibility/assets/source/" + runtimeDirectory + "/providers/" + provider + ".toml")
			if err != nil {
				t.Fatal(err)
			}
			got := descriptorEnvironmentKeys(string(descriptor))
			if !slices.Equal(got, expected) {
				t.Fatalf("%s/%s descriptor keys = %v, want %v", runtimeDirectory, provider, got, expected)
			}
		}
	}
	got := make(map[string][]string)
	for _, field := range manifest.Fields() {
		provider, conditional := ProviderCodeForField(field.ID())
		if !conditional {
			continue
		}
		key, ok := field.EnvironmentKey()
		if !ok {
			t.Fatalf("provider field %s is not dotenv-backed", field.ID())
		}
		got[provider] = append(got[provider], key)
	}
	for provider := range got {
		slices.Sort(got[provider])
		if !slices.Equal(got[provider], want[provider]) {
			t.Fatalf("%s manifest keys = %v, want %v", provider, got[provider], want[provider])
		}
	}
}

func descriptorEnvironmentKeys(descriptor string) []string {
	pattern := regexp.MustCompile(`(?m)^    ([A-Z][A-Z0-9_]+) = `)
	matches := pattern.FindAllStringSubmatch(descriptor, -1)
	result := make([]string, 0, len(matches))
	for _, match := range matches {
		result = append(result, match[1])
	}
	slices.Sort(result)
	return result
}

func TestCloudflareAuthenticationAlternativesAreExclusive(t *testing.T) {
	valid := []map[FieldID]bool{
		{FieldCloudflareDNSAPIToken: true},
		{FieldCloudflareDNSAPITokenAlias: true},
		{FieldCloudflareDNSAPIToken: true, FieldCloudflareZoneAPIToken: true},
		{FieldCloudflareDNSAPITokenAlias: true, FieldCloudflareZoneAPITokenAlias: true},
		{FieldCloudflareEmail: true, FieldCloudflareAPIKey: true},
		{FieldCloudflareEmailAlias: true, FieldCloudflareAPIKeyAlias: true},
		{FieldCloudflareEmail: true, FieldCloudflareAPIKeyAlias: true},
	}
	for index, present := range valid {
		if issues := CoreDNSCredentialIssues("cloudflare", present); len(issues) != 0 {
			t.Fatalf("valid alternative %d returned %v", index, issues)
		}
	}
	invalid := []map[FieldID]bool{
		{},
		{FieldCloudflareZoneAPIToken: true},
		{FieldCloudflareEmail: true},
		{FieldCloudflareEmail: true, FieldCloudflareAPIKey: true, FieldCloudflareDNSAPIToken: true},
		{FieldCloudflareDNSAPIToken: true, FieldCloudflareDNSAPITokenAlias: true},
		{FieldCloudflareDNSAPIToken: true, FieldCloudflareZoneAPIToken: true, FieldCloudflareZoneAPITokenAlias: true},
	}
	for index, present := range invalid {
		if issues := CoreDNSCredentialIssues("cloudflare", present); len(issues) == 0 {
			t.Fatalf("invalid alternative %d was accepted", index)
		}
	}
}

func TestProviderDotenvValueBoundsAreSourceBackedAndValueFree(t *testing.T) {
	valid := map[FieldID]string{
		FieldCloudflareEmail: "operator@example.com", FieldCloudflareTTL: "120",
		FieldCloudflarePropagationTimeout: "120", FieldCloudflareBaseURL: "https://api.cloudflare.com/client/v4",
		FieldDigitalOceanTTL: "30", FieldDigitalOceanAPIURL: "https://api.digitalocean.com",
		FieldDuckDNSSequenceInterval: "60", FieldDuckDNSToken: "token-value",
	}
	for field, value := range valid {
		if err := ValidateCoreDNSDotenvValue(field, []byte(value)); err != nil {
			t.Fatalf("%s rejected %q: %v", field, value, err)
		}
	}
	invalid := map[FieldID]string{
		FieldCloudflareEmail: "not-an-email", FieldCloudflareTTL: "119",
		FieldCloudflareBaseURL: "http://api.cloudflare.com", FieldDigitalOceanTTL: "0",
		FieldDigitalOceanAPIURL: "https://user@example.com", FieldDuckDNSSequenceInterval: "-1",
	}
	for field, value := range invalid {
		err := ValidateCoreDNSDotenvValue(field, []byte(value))
		if err == nil || strings.Contains(err.Error(), value) {
			t.Fatalf("%s validation error = %v", field, err)
		}
	}
}
