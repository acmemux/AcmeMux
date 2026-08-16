package integrations

import (
	"slices"
	"testing"

	"github.com/sgurden-certleap/AcmeMux/internal/compatibility"
)

func TestCoreManifestExposesExactTask07FieldContract(t *testing.T) {
	manifest, ok := CoreManifest(compatibility.ManifestLegoV531)
	if !ok || manifest.ID() != CoreManifestID {
		t.Fatalf("CoreManifest() = %#v, %v", manifest, ok)
	}
	want := []FieldID{
		FieldWorkspaceStorage,
		FieldAccountServer, FieldAccountEmail, FieldAccountKeyType, FieldAccountAcceptsTerms,
		FieldAccountEABKID, FieldAccountEABHMACKey,
		FieldCertificateDomains, FieldCertificateKeyType, FieldCertificateAccount, FieldCertificateChallenge,
		FieldCertificateRenewDays, FieldCertificateRenewReuseKey, FieldCertificateRenewRandomSleep,
		FieldCertificateRenewARIDisable, FieldCertificateRenewARIWait,
		FieldChallengeHTTPAddress, FieldChallengeHTTPDelay, FieldChallengeHTTPProxyHeader, FieldChallengeHTTPWebroot,
	}
	fields := manifest.Fields()
	got := make([]FieldID, len(fields))
	for index, field := range fields {
		got[index] = field.ID()
	}
	for _, id := range want {
		if !slices.Contains(got, id) {
			t.Fatalf("manifest fields = %v, missing %s", got, id)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("manifest fields = %v, want exactly %v", got, want)
	}
	hmac, _ := manifest.Field(FieldAccountEABHMACKey)
	if hmac.Sensitivity() != SensitivitySecret || !hmac.PruneEmptyParents() {
		t.Fatalf("EAB HMAC contract = %#v", hmac)
	}
	kid, _ := manifest.Field(FieldAccountEABKID)
	if kid.Sensitivity() != SensitivityPublic || !kid.PruneEmptyParents() {
		t.Fatalf("EAB KID contract = %#v", kid)
	}
	address, _ := manifest.Field(FieldChallengeHTTPAddress)
	value, present := address.Default()
	text, textOK := value.String()
	if !present || !textOK || text != ":80" {
		t.Fatalf("HTTP address default = %#v, %v", value, present)
	}
}

func TestAcceptedCAServerValuesAreExactAndDefensive(t *testing.T) {
	want := []string{
		"letsencrypt", "letsencrypt-staging", "zerossl", "googletrust", "googletrust-staging", "sslcomrsa", "sslcomecc",
		"https://acme-v02.api.letsencrypt.org/directory",
		"https://acme-staging-v02.api.letsencrypt.org/directory",
		"https://acme.zerossl.com/v2/DV90",
		"https://dv.acme-v02.api.pki.goog/directory",
		"https://dv.acme-v02.test-api.pki.goog/directory",
		"https://acme.ssl.com/sslcom-dv-rsa",
		"https://acme.ssl.com/sslcom-dv-ecc",
		GoDaddyDirectoryURL,
	}
	values := AcceptedCAServerValues()
	for _, value := range want {
		if !slices.Contains(values, value) {
			t.Fatalf("accepted CA values = %v, missing %q", values, value)
		}
	}
	if len(values) != len(want) {
		t.Fatalf("accepted CA values = %v, want exactly %v", values, want)
	}
	values[0] = "mutated"
	if slices.Contains(AcceptedCAServerValues(), "mutated") {
		t.Fatal("accepted CA values exposed mutable global state")
	}
}

func TestCoreBindingsUseCollisionAndTraversalSafeEntityGrammar(t *testing.T) {
	manifest, _ := CoreManifest(compatibility.ManifestLegoV531)
	field, _ := manifest.Field(FieldCertificateDomains)
	for _, value := range []string{"a+b", "../certificate", ".leading", "slash/name"} {
		if _, err := field.Resolve(map[BindingID]string{BindingCertificate: value}); err == nil {
			t.Fatalf("unsafe certificate binding %q resolved", value)
		}
	}
	for _, value := range []string{"gateway", "gateway.example", "admin@example.com", "A_01-okay"} {
		if _, err := field.Resolve(map[BindingID]string{BindingCertificate: value}); err != nil {
			t.Fatalf("safe certificate binding %q failed: %v", value, err)
		}
	}
}

func TestCoreKeyTypesMatchExactUpstreamSchemaIntersection(t *testing.T) {
	manifest, _ := CoreManifest(compatibility.ManifestLegoV531)
	for _, fieldID := range []FieldID{FieldAccountKeyType, FieldCertificateKeyType} {
		field, _ := manifest.Field(fieldID)
		for _, value := range []string{"EC256", "EC384", "RSA2048", "RSA4096", "RSA8192"} {
			if err := field.ValidateValue(StringValue(value)); err != nil {
				t.Fatalf("%s rejected %s: %v", fieldID, value, err)
			}
		}
		for _, value := range []string{"RSA3072", "EC521", "rsa2048"} {
			if err := field.ValidateValue(StringValue(value)); err == nil {
				t.Fatalf("%s accepted unsupported %s", fieldID, value)
			}
		}
	}
}
