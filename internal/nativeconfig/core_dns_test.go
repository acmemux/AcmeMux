package nativeconfig

import (
	"slices"
	"strings"
	"testing"

	"github.com/sgurden-certleap/AcmeMux/internal/compatibility"
	"github.com/sgurden-certleap/AcmeMux/internal/integrations"
)

func coreDNSEngine(t *testing.T) *Engine {
	t.Helper()
	schema, err := compatibility.Schema(compatibility.ManifestLegoV531)
	if err != nil {
		t.Fatal(err)
	}
	manifest, ok := integrations.CoreDNSManifest(compatibility.ManifestLegoV531)
	if !ok {
		t.Fatal("core DNS manifest unavailable")
	}
	engine, err := NewEngine(compatibility.ManifestLegoV531, schema, manifest, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

const validCoreDNSConfiguration = `storage: ./native-storage
accounts:
  home:
    server: letsencrypt
    email: admin@example.com
    keyType: EC256
    acceptsTermsOfService: true
challenges:
  dns-home:
    dns:
      provider: cloudflare
      dnsTimeout: 30
      resolvers: [1.1.1.1:53]
      envFile: .cloudflare.env
      propagation:
        disableAuthoritativeNameservers: false
        disableRecursiveNameservers: false
        wait: 0s
certificates:
  wildcard:
    domains: ["*.home.example", home.example]
    keyType: EC256
    account: home
    challenge: dns-home
    renew:
      days: 0
      reuseKey: false
      disableRandomSleep: false
      ari:
        disable: false
        waitToRenewDuration: 0s
`

func TestCoreDNSInspectionProjectsOnlySelectedProviderContract(t *testing.T) {
	inspection, err := coreDNSEngine(t).InspectCreation([]byte(validCoreDNSConfiguration))
	if err != nil {
		t.Fatal(err)
	}
	if !inspection.SchemaValid || !inspection.SemanticValid || !inspection.Replaceable || !inspection.Executable {
		t.Fatalf("inspection = %#v", inspection)
	}
	routes := inspection.DotenvRoutes()
	if len(routes) != 13 {
		t.Fatalf("Cloudflare routes = %d, want 13", len(routes))
	}
	for _, route := range routes {
		provider, ok := integrations.ProviderCodeForField(route.FieldID())
		if !ok || provider != "cloudflare" || route.Reference() != ".cloudflare.env" {
			t.Fatalf("unexpected route = %#v", route)
		}
	}
	for _, field := range inspection.Projection {
		if provider, conditional := integrations.ProviderCodeForField(field.FieldID); conditional && provider != "cloudflare" {
			t.Fatalf("projection leaked %s field %s", provider, field.FieldID)
		}
	}
}

func TestCoreDNSCredentialPresenceAcceptsOneModeAndRejectsMixedCandidate(t *testing.T) {
	inspection, err := coreDNSEngine(t).Inspect([]byte(validCoreDNSConfiguration))
	if err != nil {
		t.Fatal(err)
	}
	binding := []Binding{{ID: integrations.BindingChallenge, Value: "dns-home"}}
	valid := inspection.WithDotenvPresence([]DotenvPresence{{
		FieldID: integrations.FieldCloudflareDNSAPIToken, Bindings: binding, Present: true, Valid: true,
	}}).WithCoreDNSCredentialValidation(true)
	if !valid.Executable || slices.ContainsFunc(valid.Issues, func(issue Issue) bool { return issue.Class == IssueConstraint }) {
		t.Fatalf("single token validation = %#v", valid.Issues)
	}
	mixed := inspection.WithDotenvPresence([]DotenvPresence{
		{FieldID: integrations.FieldCloudflareDNSAPIToken, Bindings: binding, Present: true, Valid: true},
		{FieldID: integrations.FieldCloudflareEmail, Bindings: binding, Present: true, Valid: true, Value: integrations.StringValue("admin@example.com"), HasValue: true},
		{FieldID: integrations.FieldCloudflareAPIKey, Bindings: binding, Present: true, Valid: true},
	}).WithCoreDNSCredentialValidation(true)
	if mixed.Executable || !slices.ContainsFunc(mixed.Issues, func(issue Issue) bool { return issue.Class == IssueConstraint }) {
		t.Fatalf("mixed credential validation = %#v", mixed.Issues)
	}
	repairable := inspection.WithCoreDNSCredentialValidation(false)
	if repairable.Executable || !slices.ContainsFunc(repairable.Issues, func(issue Issue) bool { return issue.Class == IssueUnsupported }) {
		t.Fatalf("missing existing credentials = %#v", repairable.Issues)
	}
}

func TestCoreDNSPreviewMapsExactYAMLAndDotenvTargets(t *testing.T) {
	engine := coreDNSEngine(t)
	binding := []Binding{{ID: integrations.BindingChallenge, Value: "dns-home"}}
	candidate, err := engine.Preview([]byte(validCoreDNSConfiguration), []Change{
		{FieldID: integrations.FieldChallengeDNSTimeout, Bindings: binding, Operation: OperationSet, Value: integrations.IntegerValue(45)},
		{FieldID: integrations.FieldCloudflareDNSAPIToken, Bindings: binding, Operation: OperationSet, Value: integrations.StringValue("replacement-token")},
		{FieldID: integrations.FieldCloudflareTTL, Bindings: binding, Operation: OperationSet, Value: integrations.StringValue("300")},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Clear()
	if !strings.Contains(string(candidate.YAML()), "dnsTimeout: 45") {
		t.Fatalf("candidate YAML = %s", candidate.YAML())
	}
	external := candidate.ExternalChanges()
	if len(external) != 2 || external[0].Reference() != ".cloudflare.env" || external[1].Reference() != ".cloudflare.env" {
		t.Fatalf("external changes = %#v", external)
	}
	keys := []string{external[0].EnvironmentKey(), external[1].EnvironmentKey()}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"CLOUDFLARE_DNS_API_TOKEN", "CLOUDFLARE_TTL"}) {
		t.Fatalf("external keys = %v", keys)
	}
}

func TestCloudflareAuthenticationAlternativesMapToExactEnvironmentKeys(t *testing.T) {
	engine := coreDNSEngine(t)
	binding := []Binding{{ID: integrations.BindingChallenge, Value: "dns-home"}}
	tests := []struct {
		name    string
		changes []Change
		want    []string
	}{
		{
			name: "least privilege token",
			changes: []Change{
				{FieldID: integrations.FieldCloudflareDNSAPIToken, Bindings: binding, Operation: OperationSet, Value: integrations.StringValue("dns-token")},
			},
			want: []string{"CLOUDFLARE_DNS_API_TOKEN"},
		},
		{
			name: "split tokens",
			changes: []Change{
				{FieldID: integrations.FieldCloudflareDNSAPIToken, Bindings: binding, Operation: OperationSet, Value: integrations.StringValue("dns-token")},
				{FieldID: integrations.FieldCloudflareZoneAPIToken, Bindings: binding, Operation: OperationSet, Value: integrations.StringValue("zone-token")},
			},
			want: []string{"CLOUDFLARE_DNS_API_TOKEN", "CLOUDFLARE_ZONE_API_TOKEN"},
		},
		{
			name: "legacy email and global key",
			changes: []Change{
				{FieldID: integrations.FieldCloudflareEmail, Bindings: binding, Operation: OperationSet, Value: integrations.StringValue("operator@example.com")},
				{FieldID: integrations.FieldCloudflareAPIKey, Bindings: binding, Operation: OperationSet, Value: integrations.StringValue("global-key")},
			},
			want: []string{"CLOUDFLARE_API_KEY", "CLOUDFLARE_EMAIL"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate, err := engine.Preview([]byte(validCoreDNSConfiguration), test.changes)
			if err != nil {
				t.Fatal(err)
			}
			defer candidate.Clear()
			got := make([]string, 0, len(candidate.ExternalChanges()))
			for _, change := range candidate.ExternalChanges() {
				got = append(got, change.EnvironmentKey())
			}
			slices.Sort(got)
			if !slices.Equal(got, test.want) {
				t.Fatalf("environment keys = %v, want %v", got, test.want)
			}
		})
	}
}

func TestCoreDNSRejectsUnsupportedProviderAndUnsafePropagationCombination(t *testing.T) {
	engine := coreDNSEngine(t)
	unsupported := strings.Replace(validCoreDNSConfiguration, "provider: cloudflare", "provider: route53", 1)
	inspection, err := engine.Inspect([]byte(unsupported))
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Executable || !slices.ContainsFunc(inspection.Issues, func(issue Issue) bool { return issue.Class == IssueUnsupported }) {
		t.Fatalf("unsupported provider inspection = %#v", inspection.Issues)
	}
	mixed := strings.Replace(validCoreDNSConfiguration, "disableAuthoritativeNameservers: false", "disableAuthoritativeNameservers: true", 1)
	mixed = strings.Replace(mixed, "wait: 0s", "wait: 5s", 1)
	inspection, err = engine.Inspect([]byte(mixed))
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Executable || !slices.ContainsFunc(inspection.Issues, func(issue Issue) bool {
		return issue.Class == IssueConstraint || issue.Class == IssueSemantic
	}) {
		t.Fatalf("mixed propagation inspection = %#v", inspection.Issues)
	}
}
