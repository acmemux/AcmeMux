package integrations

import (
	"slices"
	"sync"

	"github.com/acmemux/AcmeMux/internal/compatibility"
)

const (
	// CoreManifestID is the curated native contract for CA accounts,
	// certificates, renewal settings, and HTTP-01. Provider credentials extend
	// this manifest in later integration packets.
	CoreManifestID ManifestID = "native-ca-certificate-http-v1"

	FieldAccountServer               FieldID = "account.server"
	FieldAccountEmail                FieldID = "account.email"
	FieldAccountKeyType              FieldID = "account.key_type"
	FieldAccountAcceptsTerms         FieldID = "account.accepts_terms_of_service"
	FieldAccountEABKID               FieldID = "account.eab.kid"
	FieldAccountEABHMACKey           FieldID = "account.eab.hmac_key"
	FieldCertificateDomains          FieldID = "certificate.domains"
	FieldCertificateKeyType          FieldID = "certificate.key_type"
	FieldCertificateAccount          FieldID = "certificate.account"
	FieldCertificateChallenge        FieldID = "certificate.challenge"
	FieldCertificateRenewDays        FieldID = "certificate.renew.days"
	FieldCertificateRenewReuseKey    FieldID = "certificate.renew.reuse_key"
	FieldCertificateRenewRandomSleep FieldID = "certificate.renew.disable_random_sleep"
	FieldCertificateRenewARIDisable  FieldID = "certificate.renew.ari.disable"
	FieldCertificateRenewARIWait     FieldID = "certificate.renew.ari.wait_to_renew_duration"
	FieldChallengeHTTPAddress        FieldID = "challenge.http.address"
	FieldChallengeHTTPDelay          FieldID = "challenge.http.delay"
	FieldChallengeHTTPProxyHeader    FieldID = "challenge.http.proxy_header"
	FieldChallengeHTTPWebroot        FieldID = "challenge.http.webroot"

	BindingAccount     BindingID = "account"
	BindingCertificate BindingID = "certificate"
	BindingChallenge   BindingID = "challenge"

	GoDaddyDirectoryURL = "https://acme.godaddy.com/v1/acme/directory"
)

var (
	coreOnce     sync.Once
	coreManifest Manifest
)

// AcceptedCAServerValues are the only native account.server spellings managed
// by the core manifest. New forms emit shortcodes; exact upstream URLs remain
// accepted so an equivalent native workspace can be adopted without rewrite.
func AcceptedCAServerValues() []string {
	values := []string{
		"googletrust",
		"googletrust-staging",
		"https://acme-staging-v02.api.letsencrypt.org/directory",
		"https://acme.godaddy.com/v1/acme/directory",
		"https://acme.ssl.com/sslcom-dv-ecc",
		"https://acme.ssl.com/sslcom-dv-rsa",
		"https://acme.zerossl.com/v2/DV90",
		"https://acme-v02.api.letsencrypt.org/directory",
		"https://dv.acme-v02.api.pki.goog/directory",
		"https://dv.acme-v02.test-api.pki.goog/directory",
		"letsencrypt",
		"letsencrypt-staging",
		"sslcomecc",
		"sslcomrsa",
		"zerossl",
	}
	slices.Sort(values)
	return values
}

func buildCoreManifest() Manifest {
	base := buildBaseManifest()
	account := []SelectorSegment{YAMLKey("accounts"), YAMLBinding(BindingAccount)}
	certificate := []SelectorSegment{YAMLKey("certificates"), YAMLBinding(BindingCertificate)}
	challenge := []SelectorSegment{YAMLKey("challenges"), YAMLBinding(BindingChallenge), YAMLKey("http")}

	keyTypes := []string{"EC256", "EC384", "RSA2048", "RSA4096", "RSA8192"}
	defaultKeyType := StringValue("EC256")
	defaultFalse := BooleanValue(false)
	defaultAddress := StringValue(":80")
	defaultDuration := StringValue("0s")
	minimumDays, maximumDays := int64(0), int64(365)

	fields := []FieldSpec{
		mustField(FieldDefinition{
			ID: FieldAccountServer, Label: "ACME server", Kind: FieldString, Target: TargetYAML,
			Sensitivity: SensitivityPublic, Disposition: DispositionManaged,
			Selector: appendSelector(account, "server"), Rules: Rules{MaxBytes: 2048, Enum: AcceptedCAServerValues()},
		}),
		mustField(FieldDefinition{
			ID: FieldAccountEmail, Label: "Account email", Kind: FieldString, Target: TargetYAML,
			Sensitivity: SensitivityPublic, Disposition: DispositionManaged,
			Selector: appendSelector(account, "email"), Rules: Rules{MaxBytes: 254},
		}),
		mustField(FieldDefinition{
			ID: FieldAccountKeyType, Label: "Account key type", Kind: FieldString, Target: TargetYAML,
			Sensitivity: SensitivityPublic, Disposition: DispositionManaged,
			Selector: appendSelector(account, "keyType"), Default: &defaultKeyType,
			Rules: Rules{MaxBytes: 16, Enum: keyTypes},
		}),
		mustField(FieldDefinition{
			ID: FieldAccountAcceptsTerms, Label: "Terms of service accepted", Kind: FieldBoolean, Target: TargetYAML,
			Sensitivity: SensitivityPublic, Disposition: DispositionManaged,
			Selector: appendSelector(account, "acceptsTermsOfService"), Default: &defaultFalse,
		}),
		mustField(FieldDefinition{
			ID: FieldAccountEABKID, Label: "External Account Binding key ID", Kind: FieldString, Target: TargetYAML,
			Sensitivity: SensitivityPublic, Disposition: DispositionManaged,
			Selector: appendSelector(account, "eab", "kid"), PruneEmptyParents: true, Rules: Rules{MaxBytes: 4096},
		}),
		mustField(FieldDefinition{
			ID: FieldAccountEABHMACKey, Label: "External Account Binding HMAC key", Kind: FieldString, Target: TargetYAML,
			Sensitivity: SensitivitySecret, Disposition: DispositionManaged,
			Selector: appendSelector(account, "eab", "hmacKey"), PruneEmptyParents: true, Rules: Rules{MaxBytes: 8192},
		}),
		mustField(FieldDefinition{
			ID: FieldCertificateDomains, Label: "Certificate DNS names", Kind: FieldStringList, Target: TargetYAML,
			Sensitivity: SensitivityPublic, Disposition: DispositionManaged,
			Selector: appendSelector(certificate, "domains"), Rules: Rules{MinItems: 1, MaxItems: 100, MaxBytes: 253},
		}),
		mustField(FieldDefinition{
			ID: FieldCertificateKeyType, Label: "Certificate key type", Kind: FieldString, Target: TargetYAML,
			Sensitivity: SensitivityPublic, Disposition: DispositionManaged,
			Selector: appendSelector(certificate, "keyType"), Rules: Rules{MaxBytes: 16, Enum: keyTypes},
		}),
		mustField(FieldDefinition{
			ID: FieldCertificateAccount, Label: "Certificate account", Kind: FieldString, Target: TargetYAML,
			Sensitivity: SensitivityPublic, Disposition: DispositionManaged,
			Selector: appendSelector(certificate, "account"), Rules: Rules{MaxBytes: 128},
		}),
		mustField(FieldDefinition{
			ID: FieldCertificateChallenge, Label: "Certificate challenge", Kind: FieldString, Target: TargetYAML,
			Sensitivity: SensitivityPublic, Disposition: DispositionManaged,
			Selector: appendSelector(certificate, "challenge"), Rules: Rules{MaxBytes: 128},
		}),
		mustField(FieldDefinition{
			ID: FieldCertificateRenewDays, Label: "Renew with days remaining", Kind: FieldInteger, Target: TargetYAML,
			Sensitivity: SensitivityPublic, Disposition: DispositionManaged,
			Selector: appendSelector(certificate, "renew", "days"), Rules: Rules{Minimum: &minimumDays, Maximum: &maximumDays},
		}),
		mustField(FieldDefinition{
			ID: FieldCertificateRenewReuseKey, Label: "Reuse certificate key", Kind: FieldBoolean, Target: TargetYAML,
			Sensitivity: SensitivityPublic, Disposition: DispositionManaged,
			Selector: appendSelector(certificate, "renew", "reuseKey"), Default: &defaultFalse,
		}),
		mustField(FieldDefinition{
			ID: FieldCertificateRenewRandomSleep, Label: "Disable renewal random sleep", Kind: FieldBoolean, Target: TargetYAML,
			Sensitivity: SensitivityPublic, Disposition: DispositionManaged,
			Selector: appendSelector(certificate, "renew", "disableRandomSleep"), Default: &defaultFalse,
		}),
		mustField(FieldDefinition{
			ID: FieldCertificateRenewARIDisable, Label: "Disable ACME Renewal Information", Kind: FieldBoolean, Target: TargetYAML,
			Sensitivity: SensitivityPublic, Disposition: DispositionManaged,
			Selector: appendSelector(certificate, "renew", "ari", "disable"), Default: &defaultFalse,
		}),
		mustField(FieldDefinition{
			ID: FieldCertificateRenewARIWait, Label: "Maximum ARI wait", Kind: FieldString, Target: TargetYAML,
			Sensitivity: SensitivityPublic, Disposition: DispositionManaged,
			Selector: appendSelector(certificate, "renew", "ari", "waitToRenewDuration"), Default: &defaultDuration,
			Rules: Rules{MaxBytes: 64},
		}),
		mustField(FieldDefinition{
			ID: FieldChallengeHTTPAddress, Label: "HTTP-01 listener address", Kind: FieldString, Target: TargetYAML,
			Sensitivity: SensitivityPublic, Disposition: DispositionManaged,
			Selector: appendSelector(challenge, "address"), Default: &defaultAddress, Rules: Rules{MaxBytes: 256},
		}),
		mustField(FieldDefinition{
			ID: FieldChallengeHTTPDelay, Label: "HTTP-01 validation delay", Kind: FieldString, Target: TargetYAML,
			Sensitivity: SensitivityPublic, Disposition: DispositionManaged,
			Selector: appendSelector(challenge, "delay"), Default: &defaultDuration, Rules: Rules{MaxBytes: 64},
		}),
		mustField(FieldDefinition{
			ID: FieldChallengeHTTPProxyHeader, Label: "HTTP-01 proxy domain header", Kind: FieldString, Target: TargetYAML,
			Sensitivity: SensitivityPublic, Disposition: DispositionManaged,
			Selector: appendSelector(challenge, "proxyHeader"), Rules: Rules{MaxBytes: 64},
		}),
		mustField(FieldDefinition{
			ID: FieldChallengeHTTPWebroot, Label: "HTTP-01 webroot", Kind: FieldString, Target: TargetYAML,
			Sensitivity: SensitivityPublic, Disposition: DispositionManaged,
			Selector: appendSelector(challenge, "webroot"), Rules: Rules{MaxBytes: 4095},
		}),
	}
	manifest, err := base.Extend(CoreManifestID, fields...)
	if err != nil {
		panic("invalid core integration manifest: " + err.Error())
	}
	return manifest
}

func appendSelector(prefix []SelectorSegment, keys ...string) []SelectorSegment {
	selector := append([]SelectorSegment(nil), prefix...)
	for _, key := range keys {
		selector = append(selector, YAMLKey(key))
	}
	return selector
}

func mustField(definition FieldDefinition) FieldSpec {
	field, err := NewFieldSpec(definition)
	if err != nil {
		panic("invalid core integration field " + string(definition.ID) + ": " + err.Error())
	}
	return field
}

// CoreManifest returns the Task 07 curated contract for an exact admitted
// runtime identity.
func CoreManifest(runtimeID compatibility.ManifestID) (Manifest, bool) {
	coreOnce.Do(func() { coreManifest = buildCoreManifest() })
	if !coreManifest.SupportsRuntime(runtimeID) {
		return Manifest{}, false
	}
	return coreManifest, true
}
