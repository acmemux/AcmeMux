package nativeconfig

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/acmemux/AcmeMux/internal/compatibility"
	"github.com/acmemux/AcmeMux/internal/integrations"
)

func coreEngine(t *testing.T) *Engine {
	t.Helper()
	schema, err := compatibility.Schema(compatibility.ManifestLegoV531)
	if err != nil {
		t.Fatal(err)
	}
	manifest, ok := integrations.CoreManifest(compatibility.ManifestLegoV531)
	if !ok {
		t.Fatal("core manifest unavailable")
	}
	engine, err := NewEngine(compatibility.ManifestLegoV531, schema, manifest, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func coreCreationSource(server, accountExtra, challengeBody, domains string) []byte {
	if accountExtra != "" && !strings.HasSuffix(accountExtra, "\n") {
		accountExtra += "\n"
	}
	if challengeBody == "" {
		challengeBody = "      address: \":8080\"\n      delay: 0s\n"
	}
	if domains == "" {
		domains = "gateway.home.example"
	}
	return []byte(fmt.Sprintf(`storage: ./native-storage
accounts:
  home:
    server: %q
    keyType: EC256
    acceptsTermsOfService: true
%schallenges:
  web:
    http:
%scertificates:
  gateway:
    domains: [%s]
    keyType: EC256
    account: home
    challenge: web
    renew:
      days: 0
      reuseKey: false
      disableRandomSleep: false
      ari:
        disable: false
        waitToRenewDuration: 0s
`, server, accountExtra, challengeBody, domains))
}

func accountPrerequisites(server string) string {
	switch acceptedCAServers[server] {
	case caLetsEncrypt, caZeroSSL:
		return "    email: admin@example.com\n"
	case caGoogleTrust, caSSLCom, caGoDaddy:
		return "    eab:\n      kid: public-key-id\n      hmacKey: AQ\n"
	default:
		return ""
	}
}

func TestCoreCreationAcceptsEveryCuratedCASpelling(t *testing.T) {
	engine := coreEngine(t)
	for _, server := range integrations.AcceptedCAServerValues() {
		t.Run(strings.NewReplacer(":", "_", "/", "_").Replace(server), func(t *testing.T) {
			inspection, err := engine.InspectCreation(coreCreationSource(server, accountPrerequisites(server), "", ""))
			if err != nil {
				t.Fatal(err)
			}
			if !inspection.SchemaValid || !inspection.SemanticValid || !inspection.Replaceable || !inspection.Executable || hasCoreConstraint(inspection, "") {
				t.Fatalf("server %q inspection = %#v", server, inspection)
			}
		})
	}
}

func TestCorePreservesButBlocksUnsupportedNativeChoices(t *testing.T) {
	engine := coreEngine(t)
	tests := []struct {
		name, source, path string
	}{
		{
			name:   "arbitrary ACME directory",
			source: string(coreCreationSource("https://ca.example/directory", "", "", "")),
			path:   "/accounts/home/server",
		},
		{
			name:   "named server map",
			source: "servers:\n  private:\n    url: https://ca.example/directory\n" + string(coreCreationSource("private", "", "", "")),
			path:   "/servers",
		},
		{
			name:   "HTTP memcached",
			source: string(coreCreationSource("letsencrypt", "    email: admin@example.com\n", "      memcachedHosts: [127.0.0.1:11211]\n", "")),
			path:   "/challenges/web/http/memcachedHosts",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inspection, err := engine.Inspect([]byte(test.source))
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, issue := range inspection.Issues {
				if issue.Class == IssueUnsupported && (issue.Path == test.path || strings.HasPrefix(issue.Path, test.path+"/")) {
					found = true
				}
			}
			if !found || inspection.Executable {
				t.Fatalf("unsupported inspection = %#v, want path %s", inspection, test.path)
			}
		})
	}
}

func TestCoreUnsupportedChallengeContainersDoNotProjectOrMaterializeHTTPFields(t *testing.T) {
	engine := coreEngine(t)
	tests := []struct {
		name, challengeName, challengeYAML, retained string
	}{
		{
			name: "TLS-ALPN", challengeName: "alpn",
			challengeYAML: "    tls:\n      address: \":443\"\n", retained: "tls:\n      address: \":443\"",
		},
		{
			name: "HTTP memcached", challengeName: "cache",
			challengeYAML: "    http:\n      memcachedHosts: [127.0.0.1:11211]\n", retained: "memcachedHosts:",
		},
		{
			name: "HTTP S3", challengeName: "object",
			challengeYAML: "    http:\n      s3Bucket: acme-tokens\n", retained: "s3Bucket: acme-tokens",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := []byte("storage: ./native-storage\naccounts:\n  home:\n    server: letsencrypt\nchallenges:\n  " +
				test.challengeName + ":\n" + test.challengeYAML +
				"certificates:\n  gateway:\n    domains: [gateway.home.example]\n    account: home\n    challenge: " + test.challengeName + "\n")
			inspection, err := engine.Inspect(source)
			if err != nil {
				t.Fatal(err)
			}
			if !inspection.SchemaValid || !inspection.SemanticValid || !inspection.Replaceable || inspection.Executable ||
				hasCoreConstraint(inspection, "") || !hasIssue(inspection.Issues, IssueUnsupported) {
				t.Fatalf("unsupported container inspection = %#v", inspection)
			}
			assertNoHTTPProjectionForChallenge(t, inspection, test.challengeName)

			candidate, err := engine.Preview(source, []Change{{
				FieldID: integrations.FieldWorkspaceStorage, Operation: OperationSet,
				Value: integrations.StringValue("./other-native-storage"),
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer candidate.Clear()
			if !bytes.Contains(candidate.YAML(), []byte(test.retained)) ||
				bytes.Contains(candidate.YAML(), []byte("address: :80")) || candidate.Inspection.Executable {
				t.Fatalf("unrelated edit materialized HTTP fields: %s, %#v", candidate.YAML(), candidate.Inspection)
			}
			assertNoHTTPProjectionForChallenge(t, candidate.Inspection, test.challengeName)
		})
	}
}

func TestCoreSoleUnsupportedChallengeProjectsEffectiveCertificateReferenceOnly(t *testing.T) {
	engine := coreEngine(t)
	source := []byte(`storage: ./native-storage
accounts:
  home:
    server: letsencrypt
challenges:
  alpn:
    tls:
      address: ":443"
certificates:
  gateway:
    domains: [gateway.home.example]
    account: home
`)
	inspection, err := engine.Inspect(source)
	if err != nil {
		t.Fatal(err)
	}
	if !inspection.SchemaValid || !inspection.SemanticValid || !inspection.Replaceable || inspection.Executable ||
		hasCoreConstraint(inspection, "") {
		t.Fatalf("implicit unsupported reference inspection = %#v", inspection)
	}
	assertNoHTTPProjectionForChallenge(t, inspection, "alpn")
	foundReference := false
	for _, field := range inspection.Projection {
		if field.FieldID != integrations.FieldCertificateChallenge ||
			!slices.Contains(field.Bindings, Binding{ID: integrations.BindingCertificate, Value: "gateway"}) {
			continue
		}
		value, ok := field.Value()
		text, textOK := value.String()
		foundReference = !field.Present && field.Defaulted && field.Configured && ok && textOK && text == "alpn"
	}
	if !foundReference {
		t.Fatalf("effective unsupported certificate reference projection = %#v", inspection.Projection)
	}

	candidate, err := engine.Preview(source, []Change{{
		FieldID: integrations.FieldWorkspaceStorage, Operation: OperationSet,
		Value: integrations.StringValue("./other-native-storage"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Clear()
	if bytes.Contains(candidate.YAML(), []byte("\n    challenge:")) ||
		bytes.Contains(candidate.YAML(), []byte("http:")) || candidate.Inspection.Executable {
		t.Fatalf("unrelated edit materialized unsupported default: %s, %#v", candidate.YAML(), candidate.Inspection)
	}
}

func TestCoreCSRCertificateRemainsUnsupportedWithoutManagedProjection(t *testing.T) {
	engine := coreEngine(t)
	source := []byte(`storage: ./native-storage
accounts:
  home:
    server: letsencrypt
certificates:
  imported:
    csr: request.csr
    account: home
    challenge: http-01
`)
	inspection, err := engine.Inspect(source)
	if err != nil {
		t.Fatal(err)
	}
	if !inspection.SchemaValid || !inspection.SemanticValid || !inspection.Replaceable || inspection.Executable ||
		hasCoreConstraint(inspection, "") || !hasIssueAt(inspection, IssueUnsupported, "/certificates/imported/csr") {
		t.Fatalf("CSR inspection = %#v", inspection)
	}
	assertNoCertificateProjection(t, inspection, "imported")
	assertNoHTTPProjectionForChallenge(t, inspection, "http-01")

	candidate, err := engine.Preview(source, []Change{{
		FieldID: integrations.FieldWorkspaceStorage, Operation: OperationSet,
		Value: integrations.StringValue("./other-native-storage"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Clear()
	if !bytes.Contains(candidate.YAML(), []byte("csr: request.csr")) ||
		bytes.Contains(candidate.YAML(), []byte("domains:")) ||
		bytes.Contains(candidate.YAML(), []byte("challenges:")) || candidate.Inspection.Executable {
		t.Fatalf("unrelated edit changed CSR certificate: %s, %#v", candidate.YAML(), candidate.Inspection)
	}
	assertNoCertificateProjection(t, candidate.Inspection, "imported")
}

func TestCoreCreationEnforcesRegistrationPrerequisites(t *testing.T) {
	tests := []struct {
		name, server, extra, path string
	}{
		{name: "terms", server: "letsencrypt", extra: "    email: admin@example.com\n", path: "/accounts/home/acceptsTermsOfService"},
		{name: "lets encrypt email", server: "letsencrypt", path: "/accounts/home/email"},
		{name: "zerossl assisted email", server: "zerossl", path: "/accounts/home/email"},
		{name: "google eab", server: "googletrust", path: "/accounts/home/eab"},
		{name: "sslcom eab", server: "sslcomrsa", path: "/accounts/home/eab"},
		{name: "godaddy eab", server: integrations.GoDaddyDirectoryURL, path: "/accounts/home/eab"},
	}
	engine := coreEngine(t)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := coreCreationSource(test.server, test.extra, "", "")
			if test.name == "terms" {
				source = []byte(strings.Replace(string(source), "acceptsTermsOfService: true", "acceptsTermsOfService: false", 1))
			}
			inspection, err := engine.InspectCreation(source)
			if err != nil {
				t.Fatal(err)
			}
			if !hasCoreConstraint(inspection, test.path) {
				t.Fatalf("issues = %#v, want %s", inspection.Issues, test.path)
			}
		})
	}
}

func TestCoreAdoptedAccountAllowsRemovedRegistrationInputsButValidatesRetainedEAB(t *testing.T) {
	engine := coreEngine(t)
	source := coreCreationSource("googletrust", "", "", "")
	inspection, err := engine.Inspect(source)
	if err != nil {
		t.Fatal(err)
	}
	if hasCoreConstraint(inspection, "/accounts/home/eab") || hasCoreConstraint(inspection, "/accounts/home/acceptsTermsOfService") {
		t.Fatalf("adopted account unexpectedly requires registration inputs: %#v", inspection.Issues)
	}

	invalidHMAC := coreCreationSource("googletrust", "    eab:\n      kid: public\n      hmacKey: ====\n", "", "")
	inspection, err = engine.Inspect(invalidHMAC)
	if err != nil {
		t.Fatal(err)
	}
	if !hasCoreConstraint(inspection, "/accounts/home/eab/hmacKey") {
		t.Fatalf("invalid retained HMAC issues = %#v", inspection.Issues)
	}

	letsEncryptEAB := coreCreationSource("letsencrypt", "    email: admin@example.com\n    eab:\n      kid: public\n      hmacKey: AQ\n", "", "")
	inspection, err = engine.Inspect(letsEncryptEAB)
	if err != nil {
		t.Fatal(err)
	}
	if !hasCoreConstraint(inspection, "/accounts/home/eab") {
		t.Fatalf("Let's Encrypt retained EAB issues = %#v", inspection.Issues)
	}
}

func TestCoreServerTransitionUsesEffectiveURLAndRejectsSharedStorageHost(t *testing.T) {
	engine := coreEngine(t)
	base := coreCreationSource("letsencrypt", "    email: admin@example.com\n", "", "")
	alias, err := engine.Preview(base, []Change{{
		FieldID:   integrations.FieldAccountServer,
		Bindings:  []Binding{{ID: integrations.BindingAccount, Value: "home"}},
		Operation: OperationSet,
		Value:     integrations.StringValue("https://acme-v02.api.letsencrypt.org/directory"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer alias.Clear()
	if hasCoreConstraint(alias.Inspection, "/accounts/home/server") {
		t.Fatalf("equivalent alias triggered transition issue: %#v", alias.Inspection.Issues)
	}

	ssl := coreCreationSource("sslcomrsa", "    eab:\n      kid: public\n      hmacKey: AQ\n", "", "")
	transition, err := engine.Preview(ssl, []Change{{
		FieldID:   integrations.FieldAccountServer,
		Bindings:  []Binding{{ID: integrations.BindingAccount, Value: "home"}},
		Operation: OperationSet,
		Value:     integrations.StringValue("sslcomecc"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer transition.Clear()
	if !hasCoreConstraint(transition.Inspection, "/accounts/home/server") {
		t.Fatalf("SSL.com shared-host transition issues = %#v", transition.Inspection.Issues)
	}
}

func TestCoreServerTransitionRequiresCurrentEABInputsInReviewedRequest(t *testing.T) {
	engine := coreEngine(t)
	account := []Binding{{ID: integrations.BindingAccount, Value: "home"}}
	tests := []struct {
		name, baseServer, nextServer string
	}{
		{name: "GTS production to staging", baseServer: "googletrust", nextServer: "googletrust-staging"},
		{name: "retained EAB into GTS", baseServer: "letsencrypt", nextServer: "googletrust"},
		{name: "retained explicit EAB into ZeroSSL", baseServer: "letsencrypt", nextServer: "zerossl"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			base := coreCreationSource(test.baseServer, "    email: admin@example.com\n    eab:\n      kid: prior-kid\n      hmacKey: AQ\n", "", "")
			serverChange := Change{
				FieldID: integrations.FieldAccountServer, Bindings: account,
				Operation: OperationSet, Value: integrations.StringValue(test.nextServer),
			}
			withoutReplacement, err := engine.Preview(base, []Change{serverChange})
			if err != nil {
				t.Fatal(err)
			}
			if !hasCoreConstraint(withoutReplacement.Inspection, "/accounts/home/eab") {
				withoutReplacement.Clear()
				t.Fatalf("transition reused retained EAB: %#v", withoutReplacement.Inspection.Issues)
			}
			withoutReplacement.Clear()

			withReplacement, err := engine.Preview(base, []Change{
				serverChange,
				{FieldID: integrations.FieldAccountEABKID, Bindings: account, Operation: OperationSet, Value: integrations.StringValue("current-kid")},
				{FieldID: integrations.FieldAccountEABHMACKey, Bindings: account, Operation: OperationSet, Value: integrations.StringValue("Ag")},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer withReplacement.Clear()
			if hasCoreConstraint(withReplacement.Inspection, "/accounts/home/eab") {
				t.Fatalf("explicit current EAB replacement was rejected: %#v", withReplacement.Inspection.Issues)
			}
		})
	}
}

func TestCoreManagedIdentifiersAndDomainsRejectCollisions(t *testing.T) {
	engine := coreEngine(t)
	for _, name := range []string{".leading", "a+b", "../escape", strings.Repeat("a", 65)} {
		if validManagedEntityName(name) {
			t.Fatalf("validManagedEntityName(%q) = true", name)
		}
	}
	for _, name := range []string{"a", "home_lab-01", "admin@example.com", strings.Repeat("a", 64)} {
		if !validManagedEntityName(name) {
			t.Fatalf("validManagedEntityName(%q) = false", name)
		}
	}
	_, err := engine.Preview([]byte("{}\n"), []Change{{
		FieldID:   integrations.FieldAccountServer,
		Bindings:  []Binding{{ID: integrations.BindingAccount, Value: "a+b"}},
		Operation: OperationSet, Value: integrations.StringValue("letsencrypt"),
	}})
	if CodeOf(err) != ErrorInvalidChange {
		t.Fatalf("unsafe binding error = %v", err)
	}

	inspection, err := engine.Inspect(coreCreationSource("letsencrypt", "    email: admin@example.com\n", "", "gateway.home.example, gateway.home.example"))
	if err != nil {
		t.Fatal(err)
	}
	if !hasCoreConstraint(inspection, "/certificates/gateway/domains") {
		t.Fatalf("duplicate-domain issues = %#v", inspection.Issues)
	}
	inspection, err = engine.Inspect(coreCreationSource("letsencrypt", "    email: admin@example.com\n", "", "\"*.home.example\""))
	if err != nil {
		t.Fatal(err)
	}
	if !hasCoreConstraint(inspection, "/certificates/gateway/challenge") {
		t.Fatalf("wildcard HTTP issues = %#v", inspection.Issues)
	}
}

func TestCoreHTTPModesDurationsAndProxyContract(t *testing.T) {
	engine := coreEngine(t)
	validWebroot := coreCreationSource("letsencrypt", "    email: admin@example.com\n", "      webroot: ./public\n      delay: 10m\n", "")
	inspection, err := engine.InspectCreation(validWebroot)
	if err != nil {
		t.Fatal(err)
	}
	if hasCoreConstraint(inspection, "") {
		t.Fatalf("valid relative webroot issues = %#v", inspection.Issues)
	}

	invalid := coreCreationSource("letsencrypt", "    email: admin@example.com\n", "      address: \":8080\"\n      webroot: ./public\n      delay: 10m1s\n      proxyHeader: bad header\n", "")
	inspection, err = engine.Inspect(invalid)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/challenges/web/http", "/challenges/web/http/delay", "/challenges/web/http/proxyHeader"} {
		if !hasCoreConstraint(inspection, path) {
			t.Fatalf("issues = %#v, want %s", inspection.Issues, path)
		}
	}
	for _, header := range []string{"Host", "Forwarded", "X-Forwarded-Host", "X-Acmemux-Test"} {
		if !validProxyHeader(header) {
			t.Fatalf("validProxyHeader(%q) = false", header)
		}
	}
	for _, header := range []string{"x-forwarded-host", "Bad Header", "Bad:Header", strings.Repeat("X", 65)} {
		if validProxyHeader(header) {
			t.Fatalf("validProxyHeader(%q) = true", header)
		}
	}
}

func TestCoreRemovalPrunesOnlyEABStructuralParent(t *testing.T) {
	engine := coreEngine(t)
	bindings := []Binding{{ID: integrations.BindingAccount, Value: "home"}}
	source := coreCreationSource("googletrust", "    eab:\n      kid: public\n      hmacKey: AQ\n", "", "")
	candidate, err := engine.Preview(source, []Change{
		{FieldID: integrations.FieldAccountEABKID, Bindings: bindings, Operation: OperationRemove},
		{FieldID: integrations.FieldAccountEABHMACKey, Bindings: bindings, Operation: OperationRemove},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Clear()
	if strings.Contains(string(candidate.YAML()), "eab:") || !candidate.Inspection.SchemaValid {
		t.Fatalf("EAB removal candidate = %s, inspection = %#v", candidate.YAML(), candidate.Inspection)
	}

	webroot := coreCreationSource("letsencrypt", "    email: admin@example.com\n", "      webroot: ./public\n      delay: 0s\n", "")
	httpCandidate, err := engine.Preview(webroot, []Change{
		{FieldID: integrations.FieldChallengeHTTPAddress, Bindings: []Binding{{ID: integrations.BindingChallenge, Value: "web"}}, Operation: OperationSet, Value: integrations.StringValue(":8080")},
		{FieldID: integrations.FieldChallengeHTTPWebroot, Bindings: []Binding{{ID: integrations.BindingChallenge, Value: "web"}}, Operation: OperationRemove},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer httpCandidate.Clear()
	if !strings.Contains(string(httpCandidate.YAML()), "address: :8080") || !httpCandidate.Inspection.SchemaValid || hasCoreConstraint(httpCandidate.Inspection, "/challenges/web/http") {
		t.Fatalf("webroot-to-listener candidate = %s, issues = %#v", httpCandidate.YAML(), httpCandidate.Inspection.Issues)
	}

	renewCandidate, err := engine.Preview(source, []Change{{
		FieldID:   integrations.FieldCertificateRenewDays,
		Bindings:  []Binding{{ID: integrations.BindingCertificate, Value: "gateway"}},
		Operation: OperationRemove,
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer renewCandidate.Clear()
	if !renewCandidate.Inspection.SchemaValid || !strings.Contains(string(renewCandidate.YAML()), "renew:") {
		t.Fatalf("renewal removal candidate = %s, inspection = %#v", renewCandidate.YAML(), renewCandidate.Inspection)
	}
}

func TestCoreSyntheticHTTPDefaultIsRepairableIntoExplicitManagedChallenge(t *testing.T) {
	engine := coreEngine(t)
	source := []byte(`storage: ./native-storage
accounts:
  home:
    server: letsencrypt
certificates:
  gateway:
    domains: [gateway.home.example]
    account: home
    challenge: http-01
`)
	inspection, err := engine.Inspect(source)
	if err != nil {
		t.Fatal(err)
	}
	if !inspection.SchemaValid || !inspection.SemanticValid || !inspection.Replaceable || inspection.Executable ||
		!hasCoreConstraint(inspection, "/challenges/http-01/http") {
		t.Fatalf("synthetic-default base inspection = %#v", inspection)
	}
	projectedAddress, projectedDelay := false, false
	for _, field := range inspection.Projection {
		bound := slices.Contains(field.Bindings, Binding{ID: integrations.BindingChallenge, Value: "http-01"})
		if !bound || field.Present || !field.Defaulted || !field.Configured {
			continue
		}
		switch field.FieldID {
		case integrations.FieldChallengeHTTPAddress:
			value, ok := field.Value()
			text, textOK := value.String()
			projectedAddress = ok && textOK && text == ":80"
		case integrations.FieldChallengeHTTPDelay:
			value, ok := field.Value()
			text, textOK := value.String()
			projectedDelay = ok && textOK && text == "0s"
		}
	}
	if !projectedAddress || !projectedDelay {
		t.Fatalf("synthetic HTTP projection = %#v", inspection.Projection)
	}
	candidate, err := engine.Preview(source, []Change{{
		FieldID:   integrations.FieldChallengeHTTPAddress,
		Bindings:  []Binding{{ID: integrations.BindingChallenge, Value: "http-01"}},
		Operation: OperationSet, Value: integrations.StringValue(":8080"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Clear()
	if !candidate.Inspection.SchemaValid || !candidate.Inspection.SemanticValid ||
		!candidate.Inspection.Replaceable || !candidate.Inspection.Executable || hasCoreConstraint(candidate.Inspection, "") {
		t.Fatalf("repaired explicit candidate = %s, inspection = %#v", candidate.YAML(), candidate.Inspection)
	}
}

func TestCoreImplicitUnsupportedBuiltInsRemainPreservedAndBlocking(t *testing.T) {
	engine := coreEngine(t)
	for _, challengeName := range []string{"tls-alpn-01", "dns-persist-01"} {
		t.Run(challengeName, func(t *testing.T) {
			source := []byte(`storage: ./native-storage
accounts:
  home:
    server: letsencrypt
certificates:
  gateway:
    domains: [gateway.home.example]
    account: home
    challenge: ` + challengeName + "\n")
			inspection, err := engine.Inspect(source)
			if err != nil {
				t.Fatal(err)
			}
			unsupportedPath := "/challenges/" + challengeName
			if !inspection.SchemaValid || !inspection.SemanticValid || !inspection.Replaceable || inspection.Executable ||
				!hasIssueAt(inspection, IssueUnsupported, unsupportedPath) || hasCoreConstraint(inspection, "") {
				t.Fatalf("implicit built-in inspection = %#v", inspection)
			}

			candidate, err := engine.Preview(source, []Change{{
				FieldID: integrations.FieldWorkspaceStorage, Operation: OperationSet,
				Value: integrations.StringValue("./other-native-storage"),
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer candidate.Clear()
			if !bytes.Contains(candidate.YAML(), []byte("challenge: "+challengeName)) ||
				bytes.Contains(candidate.YAML(), []byte("challenges:")) ||
				!hasIssueAt(candidate.Inspection, IssueUnsupported, unsupportedPath) || candidate.Inspection.Executable {
				t.Fatalf("unrelated edit failed to preserve implicit built-in: %s, %#v", candidate.YAML(), candidate.Inspection)
			}
		})
	}
}

func TestCoreImplicitAccountAndChallengeReferencesAreRepairable(t *testing.T) {
	engine := coreEngine(t)
	source := []byte(`storage: ./native-storage
accounts:
  home: {}
challenges:
  web:
    http:
      address: ":8080"
certificates:
  gateway:
    domains: [gateway.home.example]
`)
	inspection, err := engine.Inspect(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/accounts/home/server", "/certificates/gateway/account", "/certificates/gateway/challenge"} {
		if !hasCoreConstraint(inspection, path) {
			t.Fatalf("base issues = %#v, want repair finding %s", inspection.Issues, path)
		}
	}
	candidate, err := engine.Preview(source, []Change{
		{
			FieldID:   integrations.FieldAccountServer,
			Bindings:  []Binding{{ID: integrations.BindingAccount, Value: "home"}},
			Operation: OperationSet, Value: integrations.StringValue("letsencrypt"),
		},
		{
			FieldID:   integrations.FieldCertificateAccount,
			Bindings:  []Binding{{ID: integrations.BindingCertificate, Value: "gateway"}},
			Operation: OperationSet, Value: integrations.StringValue("home"),
		},
		{
			FieldID:   integrations.FieldCertificateChallenge,
			Bindings:  []Binding{{ID: integrations.BindingCertificate, Value: "gateway"}},
			Operation: OperationSet, Value: integrations.StringValue("web"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Clear()
	if hasCoreConstraint(candidate.Inspection, "") || !candidate.Inspection.Executable {
		t.Fatalf("repaired relationship candidate = %s, inspection = %#v", candidate.YAML(), candidate.Inspection)
	}
}

func TestCoreARIWaitIsBoundedForBrokerOperation(t *testing.T) {
	engine := coreEngine(t)
	source := []byte(strings.Replace(string(coreCreationSource("letsencrypt", "    email: admin@example.com\n", "", "")), "waitToRenewDuration: 0s", "waitToRenewDuration: 10m1s", 1))
	inspection, err := engine.Inspect(source)
	if err != nil {
		t.Fatal(err)
	}
	if !hasCoreConstraint(inspection, "/certificates/gateway/renew/ari/waitToRenewDuration") {
		t.Fatalf("ARI wait issues = %#v", inspection.Issues)
	}
}

func hasCoreConstraint(inspection Inspection, path string) bool {
	for _, issue := range inspection.Issues {
		if issue.Class == IssueConstraint && (path == "" || issue.Path == path) {
			return true
		}
	}
	return false
}

func hasIssueAt(inspection Inspection, class IssueClass, path string) bool {
	for _, issue := range inspection.Issues {
		if issue.Class == class && issue.Path == path {
			return true
		}
	}
	return false
}

func assertNoHTTPProjectionForChallenge(t *testing.T, inspection Inspection, challengeName string) {
	t.Helper()
	for _, field := range inspection.Projection {
		if !strings.HasPrefix(string(field.FieldID), "challenge.http.") {
			continue
		}
		for _, binding := range field.Bindings {
			if binding.ID == integrations.BindingChallenge && binding.Value == challengeName {
				t.Fatalf("unsupported challenge HTTP projection = %#v", field)
			}
		}
	}
}

func assertNoCertificateProjection(t *testing.T, inspection Inspection, certificateName string) {
	t.Helper()
	for _, field := range inspection.Projection {
		for _, binding := range field.Bindings {
			if binding.ID == integrations.BindingCertificate && binding.Value == certificateName {
				t.Fatalf("unsupported CSR certificate projection = %#v", field)
			}
		}
	}
}
