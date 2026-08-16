package integrations

import (
	"os"
	"strings"
	"testing"

	"github.com/sgurden-certleap/AcmeMux/internal/compatibility"
)

func TestCloudManifestReconcilesDescriptorAndSDKOnlyVariables(t *testing.T) {
	manifest, _ := CloudDNSManifest(compatibility.ManifestLegoV531)
	keys := map[string]map[string]bool{"azuredns": {}, "route53": {}}
	for _, field := range manifest.Fields() {
		provider, ok := ProviderCodeForField(field.ID())
		if !ok || keys[provider] == nil {
			continue
		}
		key, ok := field.EnvironmentKey()
		if !ok {
			t.Fatalf("cloud field %s is not dotenv backed", field.ID())
		}
		keys[provider][key] = true
	}
	for _, provider := range []string{"azuredns", "route53"} {
		descriptor, err := os.ReadFile("../compatibility/assets/source/lego-v5.3.1/providers/" + provider + ".toml")
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range descriptorEnvironmentKeys(string(descriptor)) {
			if provider == "azuredns" && key == "AZURE_SERVICEDISCOVERY_FILTER" {
				continue
			} // Raw Kusto fragments are deliberately outside the managed trust boundary.
			if !keys[provider][key] {
				t.Fatalf("%s descriptor key %s is not reconciled", provider, key)
			}
		}
	}
	for _, key := range []string{"AZURE_CLIENT_CERTIFICATE_PASSWORD", "AZURE_FEDERATED_TOKEN_FILE", "SYSTEM_OIDCREQUESTURI", "AWS_SESSION_TOKEN", "AWS_EC2_METADATA_DISABLED"} {
		provider := "azuredns"
		if strings.HasPrefix(key, "AWS_") {
			provider = "route53"
		}
		if !keys[provider][key] {
			t.Fatalf("SDK-only control %s is absent", key)
		}
	}
}

func TestCloudDNSManifestBindsExactProvidersAndRuntimeIdentities(t *testing.T) {
	for _, runtimeID := range []compatibility.ManifestID{compatibility.ManifestLegoV531, compatibility.ManifestLegoRevision2A58} {
		manifest, ok := CloudDNSManifest(runtimeID)
		if !ok || manifest.ID() != CloudDNSManifestID || !manifest.SupportsRuntime(runtimeID) {
			t.Fatalf("CloudDNSManifest(%s) was not bound", runtimeID)
		}
		provider, ok := manifest.Field(FieldChallengeDNSProvider)
		if !ok {
			t.Fatal("cloud provider field is absent")
		}
		for _, code := range SupportedDNSProviders() {
			if provider.ValidateValue(StringValue(code)) != nil {
				t.Fatalf("provider %q is absent from the cloud enum", code)
			}
		}
	}
	if _, ok := CloudDNSManifest("unknown"); ok {
		t.Fatal("unknown runtime received cloud manifest")
	}
}

func TestAzureAuthenticationModesAreMutuallyExclusive(t *testing.T) {
	base := map[FieldID]bool{FieldAzureAuthMethod: true, FieldAzureSubscriptionID: true, FieldAzureResourceGroup: true, FieldAzureEnvironment: true, FieldAzurePrivateZone: true}
	tests := []struct {
		method string
		fields []FieldID
	}{
		{"env", []FieldID{FieldAzureTenantID, FieldAzureClientID, FieldAzureClientSecret}},
		{"env", []FieldID{FieldAzureTenantID, FieldAzureClientID, FieldAzureClientCertificatePath}},
		{"wli", []FieldID{FieldAzureTenantID, FieldAzureClientID, FieldAzureFederatedTokenFile}},
		{"msi", nil},
		{"cli", []FieldID{FieldAzureCLIPath, FieldAzureCLIConfigDirectory}},
		{"oidc", []FieldID{FieldAzureTenantID, FieldAzureClientID, FieldAzureOIDCToken}},
		{"oidc", []FieldID{FieldAzureTenantID, FieldAzureClientID, FieldAzureOIDCTokenFile}},
		{"oidc", []FieldID{FieldAzureTenantID, FieldAzureClientID, FieldAzureOIDCRequestURL, FieldAzureOIDCRequestToken}},
		{"pipeline", []FieldID{FieldAzureTenantID, FieldAzureClientID, FieldAzureServiceConnectionID, FieldAzureSystemAccessToken, FieldAzureSystemOIDCRequestURI}},
	}
	for _, test := range tests {
		present := clonePresence(base)
		for _, field := range test.fields {
			present[field] = true
		}
		if issues := CloudDNSCredentialIssues("azuredns", present, map[FieldID]string{FieldAzureAuthMethod: test.method}); len(issues) != 0 {
			t.Fatalf("%s fields %v rejected: %v", test.method, test.fields, issues)
		}
	}
	mixed := clonePresence(base)
	for _, field := range []FieldID{FieldAzureTenantID, FieldAzureClientID, FieldAzureOIDCToken, FieldAzureOIDCTokenFile} {
		mixed[field] = true
	}
	if issues := CloudDNSCredentialIssues("azuredns", mixed, map[FieldID]string{FieldAzureAuthMethod: "oidc"}); len(issues) == 0 {
		t.Fatal("mixed OIDC sources were accepted")
	}
	arc := clonePresence(base)
	arc[FieldAzureIMDSEndpoint] = true
	if issues := CloudDNSCredentialIssues("azuredns", arc, map[FieldID]string{FieldAzureAuthMethod: "msi"}); len(issues) == 0 {
		t.Fatal("half-configured Azure Arc endpoint was accepted")
	}
}

func TestRoute53AuthenticationModesAndAssumeRoleAreExclusive(t *testing.T) {
	base := map[FieldID]bool{FieldAWSRegion: true, FieldAWSEC2MetadataDisabled: true, FieldAWSSDKLoadConfig: true}
	valid := []struct {
		fields []FieldID
		values map[FieldID]string
	}{
		{[]FieldID{FieldAWSAccessKeyID, FieldAWSSecretAccessKey}, map[FieldID]string{FieldAWSEC2MetadataDisabled: "true", FieldAWSSDKLoadConfig: "false"}},
		{[]FieldID{FieldAWSProfile, FieldAWSSharedCredentialsFile}, map[FieldID]string{FieldAWSEC2MetadataDisabled: "true", FieldAWSSDKLoadConfig: "false"}},
		{nil, map[FieldID]string{FieldAWSEC2MetadataDisabled: "false", FieldAWSSDKLoadConfig: "false"}},
	}
	for _, test := range valid {
		present := clonePresence(base)
		for _, field := range test.fields {
			present[field] = true
		}
		if issues := CloudDNSCredentialIssues("route53", present, test.values); len(issues) != 0 {
			t.Fatalf("valid Route53 mode rejected: %v", issues)
		}
	}
	invalid := clonePresence(base)
	invalid[FieldAWSExternalID] = true
	if issues := CloudDNSCredentialIssues("route53", invalid, map[FieldID]string{FieldAWSEC2MetadataDisabled: "false", FieldAWSSDKLoadConfig: "false"}); len(issues) == 0 {
		t.Fatal("external ID without assume role was accepted")
	}
}

func TestCloudValueValidationRejectsUnsafePathsEndpointsAndAmbientChoices(t *testing.T) {
	valid := map[FieldID]string{FieldAzureEnvironment: "usgovernment", FieldAzureAuthMethod: "wli", FieldAzureFederatedTokenFile: "/run/secrets/token", FieldAzureOIDCRequestURL: "https://issuer.example/token", FieldAzureIMDSEndpoint: "http://127.0.0.1:40342", FieldAWSRegion: "us-gov-west-1", FieldAWSProfile: "acmemux.prod", FieldAWSEC2MetadataDisabled: "true"}
	for field, value := range valid {
		if err := ValidateCloudDNSDotenvValue(field, []byte(value)); err != nil {
			t.Fatalf("%s rejected: %v", field, err)
		}
	}
	invalid := map[FieldID]string{FieldAzureEnvironment: "default", FieldAzureAuthMethod: "default", FieldAzureFederatedTokenFile: "relative", FieldAzureOIDCRequestURL: "http://issuer.example/token", FieldAzureIMDSEndpoint: "http://169.254.169.254", FieldAWSRegion: "auto", FieldAWSProfile: "bad profile", FieldAWSEC2MetadataDisabled: "1"}
	for field, value := range invalid {
		err := ValidateCloudDNSDotenvValue(field, []byte(value))
		if err == nil || strings.Contains(err.Error(), value) {
			t.Fatalf("%s validation error = %v", field, err)
		}
	}
}

func clonePresence(source map[FieldID]bool) map[FieldID]bool {
	result := make(map[FieldID]bool, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
