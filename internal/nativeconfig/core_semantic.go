package nativeconfig

import (
	"encoding/base64"
	"net"
	"net/mail"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sgurden-certleap/AcmeMux/internal/integrations"
	"go.yaml.in/yaml/v3"
)

const (
	maximumHTTPDelay = 10 * time.Minute
	maximumARIWait   = 10 * time.Minute
	maximumDNSWait   = 10 * time.Minute
)

type caKind string

const (
	caLetsEncrypt caKind = "letsencrypt"
	caZeroSSL     caKind = "zerossl"
	caGoogleTrust caKind = "googletrust"
	caSSLCom      caKind = "sslcom"
	caGoDaddy     caKind = "godaddy"
)

var acceptedCAServers = map[string]caKind{
	"letsencrypt":         caLetsEncrypt,
	"letsencrypt-staging": caLetsEncrypt,
	"https://acme-v02.api.letsencrypt.org/directory":         caLetsEncrypt,
	"https://acme-staging-v02.api.letsencrypt.org/directory": caLetsEncrypt,
	"zerossl":                          caZeroSSL,
	"https://acme.zerossl.com/v2/DV90": caZeroSSL,
	"googletrust":                      caGoogleTrust,
	"googletrust-staging":              caGoogleTrust,
	"https://dv.acme-v02.api.pki.goog/directory":      caGoogleTrust,
	"https://dv.acme-v02.test-api.pki.goog/directory": caGoogleTrust,
	"sslcomrsa":                          caSSLCom,
	"sslcomecc":                          caSSLCom,
	"https://acme.ssl.com/sslcom-dv-rsa": caSSLCom,
	"https://acme.ssl.com/sslcom-dv-ecc": caSSLCom,
	integrations.GoDaddyDirectoryURL:     caGoDaddy,
}

var canonicalCAServerURLs = map[string]string{
	"letsencrypt":         "https://acme-v02.api.letsencrypt.org/directory",
	"letsencrypt-staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
	"https://acme-v02.api.letsencrypt.org/directory":         "https://acme-v02.api.letsencrypt.org/directory",
	"https://acme-staging-v02.api.letsencrypt.org/directory": "https://acme-staging-v02.api.letsencrypt.org/directory",
	"zerossl":                          "https://acme.zerossl.com/v2/DV90",
	"https://acme.zerossl.com/v2/DV90": "https://acme.zerossl.com/v2/DV90",
	"googletrust":                      "https://dv.acme-v02.api.pki.goog/directory",
	"googletrust-staging":              "https://dv.acme-v02.test-api.pki.goog/directory",
	"https://dv.acme-v02.api.pki.goog/directory":      "https://dv.acme-v02.api.pki.goog/directory",
	"https://dv.acme-v02.test-api.pki.goog/directory": "https://dv.acme-v02.test-api.pki.goog/directory",
	"sslcomrsa":                          "https://acme.ssl.com/sslcom-dv-rsa",
	"sslcomecc":                          "https://acme.ssl.com/sslcom-dv-ecc",
	"https://acme.ssl.com/sslcom-dv-rsa": "https://acme.ssl.com/sslcom-dv-rsa",
	"https://acme.ssl.com/sslcom-dv-ecc": "https://acme.ssl.com/sslcom-dv-ecc",
	integrations.GoDaddyDirectoryURL:     integrations.GoDaddyDirectoryURL,
}

// validateCoreConstraints applies the curated non-interactive product
// contract after the exact upstream schema and source semantics have passed.
// Violations remain repairable through typed edits but block saving a new
// violating candidate and block managed execution.
func validateCoreConstraints(document *yaml.Node, limit int, creation bool, allowCoreDNS bool) []Issue {
	var configuration nativeConfiguration
	if err := document.Content[0].Decode(&configuration); err != nil {
		return nil // validateSemantics already owns source-model decode failures.
	}
	applyNativeDefaults(&configuration)
	issues := make([]Issue, 0)
	addIssue := func(class IssueClass, path []string, summary string) {
		if len(issues) >= limit {
			return
		}
		line, column := position(document, path)
		issues = append(issues, Issue{
			Class: class, Path: pointer(path), Line: line, Column: column,
			Summary: summary, BlocksExecution: true,
		})
	}
	add := func(path []string, summary string) {
		addIssue(IssueConstraint, path, summary)
	}
	addUnsupported := func(path []string, summary string) {
		addIssue(IssueUnsupported, path, summary)
	}
	if _, present := nodeAtPath(document, []string{"storage"}); !present {
		if creation {
			add([]string{"storage"}, "New managed workspaces require an explicit storage directory.")
		}
	}
	if creation && len(configuration.Accounts) == 0 {
		add([]string{"accounts"}, "New managed workspaces require at least one ACME account.")
	}
	if creation && len(configuration.Challenges) == 0 {
		add([]string{"challenges"}, "New managed workspaces require at least one supported challenge.")
	}
	if creation && len(configuration.Certificates) == 0 {
		add([]string{"certificates"}, "New managed workspaces require at least one certificate.")
	}
	unsupportedNativeChallenges := unsupportedChallengeBindings(document.Content[0], allowCoreDNS)
	unsupportedCertificates := unsupportedCertificateBindings(document.Content[0])
	managedChallengeReferences := make(map[string]struct{})
	for name, certificate := range configuration.Certificates {
		if certificate == nil {
			continue
		}
		if _, unsupported := unsupportedCertificates[name]; unsupported {
			continue
		}
		if certificate.Challenge != "" {
			managedChallengeReferences[certificate.Challenge] = struct{}{}
		}
	}

	// lego materializes these named built-ins only after the raw YAML walk.
	// Classify them explicitly so an omitted challenges map cannot make a
	// TLS-ALPN-01 or DNS-persist certificate look like a repairable HTTP form.
	implicitUnsupportedChallenges := make(map[string]struct{})
	for _, name := range sortedKeys(configuration.Challenges) {
		challenge := configuration.Challenges[name]
		if _, configured := nodeAtPath(document, []string{"challenges", name}); configured || challenge == nil {
			continue
		}
		syntheticUnsupported := name == "tls-alpn-01" && challenge.TLS != nil ||
			name == "dns-persist-01" && challenge.DNSPersist != nil
		if !syntheticUnsupported {
			continue
		}
		implicitUnsupportedChallenges[name] = struct{}{}
		addUnsupported(
			[]string{"challenges", name},
			"This implicit lego challenge is preserved but is outside the managed HTTP-01 integration.",
		)
	}

	for _, name := range sortedKeys(configuration.Accounts) {
		account := configuration.Accounts[name]
		if account == nil {
			continue
		}
		base := []string{"accounts", name}
		if !validManagedEntityName(name) {
			add(base, "Account name is outside the collision- and traversal-safe managed identifier grammar.")
		}
		if _, present := nodeAtPath(document, appendPath(base, "server")); !present {
			add(appendPath(base, "server"), "Managed accounts must select an explicit supported ACME server.")
		}
		if creation {
			if _, present := nodeAtPath(document, appendPath(base, "keyType")); !present {
				add(appendPath(base, "keyType"), "New managed accounts require an explicit account key type.")
			}
			if _, present := nodeAtPath(document, appendPath(base, "acceptsTermsOfService")); !present {
				add(appendPath(base, "acceptsTermsOfService"), "New managed accounts require explicit terms acknowledgement.")
			}
		}
		kind, supported := acceptedCAServers[account.Server]
		if !supported {
			// Classification reports the unsupported native server value. Do not
			// pile dependent EAB guidance on top of it.
			continue
		}
		if creation && !account.AcceptsTermsOfService {
			add(appendPath(base, "acceptsTermsOfService"), "Managed accounts must explicitly accept the selected CA terms of service.")
		}
		if account.Email != "" && !validAccountEmail(account.Email) {
			add(appendPath(base, "email"), "Account email must be one canonical mailbox address.")
		}
		if account.ExternalAccountBinding != nil && !validEABHMAC(account.ExternalAccountBinding.HMACKey) {
			add(appendPath(appendPath(base, "eab"), "hmacKey"), "External Account Binding HMAC must be URL-safe base64.")
		}
		if kind == caLetsEncrypt && account.ExternalAccountBinding != nil {
			add(appendPath(base, "eab"), "Let's Encrypt managed presets do not accept retained External Account Binding credentials.")
		}
		if creation && kind == caLetsEncrypt && !validAccountEmail(account.Email) {
			add(appendPath(base, "email"), "Let's Encrypt account registration requires an account email.")
		}
		requiresEAB := kind == caGoogleTrust || kind == caSSLCom || kind == caGoDaddy
		if creation && requiresEAB && account.ExternalAccountBinding == nil {
			add(appendPath(base, "eab"), "The selected CA requires External Account Binding credentials.")
		}
		if creation && kind == caZeroSSL && account.ExternalAccountBinding == nil && !validAccountEmail(account.Email) {
			add(appendPath(base, "email"), "ZeroSSL email-assisted registration requires an account email when explicit EAB is absent.")
		}
	}

	for _, name := range sortedKeys(configuration.Challenges) {
		challenge := configuration.Challenges[name]
		if !validManagedEntityName(name) {
			add([]string{"challenges", name}, "Challenge name is outside the collision- and traversal-safe managed identifier grammar.")
		}
		if _, unsupported := unsupportedNativeChallenges[name]; unsupported {
			if creation {
				add([]string{"challenges", name}, "New managed challenges must use a supported HTTP-01 or curated DNS-01 integration.")
			}
			continue
		}
		if _, configured := nodeAtPath(document, []string{"challenges", name}); !configured {
			if _, required := managedChallengeReferences[name]; !required {
				continue
			}
		}
		if challenge == nil {
			continue
		}
		if challenge.DNS != nil && allowCoreDNS && integrations.SupportsCoreDNSProvider(challenge.DNS.Provider) {
			validateCoreDNSChallenge(document, name, challenge.DNS, creation, add)
			continue
		}
		if challenge.HTTP == nil {
			if creation {
				add([]string{"challenges", name}, "New managed challenges require an HTTP-01 or curated DNS-01 configuration.")
			}
			continue
		}
		base := []string{"challenges", name, "http"}
		_, addressPresent := nodeAtPath(document, appendPath(base, "address"))
		_, webrootPresent := nodeAtPath(document, appendPath(base, "webroot"))
		webrootMode := webrootPresent && challenge.HTTP.Webroot != ""
		if !addressPresent && !webrootMode {
			add(base, "Managed HTTP-01 must explicitly select a built-in listener address or a webroot.")
		}
		if creation {
			if _, present := nodeAtPath(document, appendPath(base, "delay")); !present {
				add(appendPath(base, "delay"), "New managed HTTP-01 challenges require an explicit validation delay.")
			}
		}
		if !validHTTPAddress(challenge.HTTP.Address) {
			add(appendPath(base, "address"), "HTTP-01 listener address must contain a literal IPv4 or bracketed IPv6 host and a nonzero port.")
		}
		if challenge.HTTP.Delay < 0 || challenge.HTTP.Delay > maximumHTTPDelay {
			add(appendPath(base, "delay"), "HTTP-01 validation delay is outside the supported zero-to-ten-minute range.")
		}
		if challenge.HTTP.ProxyHeader != "" && !validProxyHeader(challenge.HTTP.ProxyHeader) {
			add(appendPath(base, "proxyHeader"), "HTTP-01 proxy header must be Host, Forwarded, or one canonical HTTP header name.")
		}
		if challenge.HTTP.Webroot != "" && anyNativePathPresent(document, base, "address", "proxyHeader") {
			add(base, "HTTP-01 webroot mode cannot retain built-in listener address or proxy-header settings.")
		}
	}

	for _, name := range sortedKeys(configuration.Certificates) {
		certificate := configuration.Certificates[name]
		if certificate == nil {
			continue
		}
		base := []string{"certificates", name}
		if !validManagedEntityName(name) {
			add(base, "Certificate name is outside the collision-safe managed identifier grammar.")
		}
		if _, unsupported := unsupportedCertificates[name]; unsupported {
			continue
		}
		if _, present := nodeAtPath(document, appendPath(base, "domains")); !present {
			add(appendPath(base, "domains"), "Managed certificates require explicit DNS names.")
		}
		if _, present := nodeAtPath(document, appendPath(base, "account")); !present {
			add(appendPath(base, "account"), "Managed certificates require an explicit account reference.")
		}
		_, unsupportedSelectedChallenge := unsupportedNativeChallenges[certificate.Challenge]
		if _, present := nodeAtPath(document, appendPath(base, "challenge")); !present && !unsupportedSelectedChallenge {
			add(appendPath(base, "challenge"), "Managed certificates require an explicit challenge reference.")
		}
		if creation {
			if _, present := nodeAtPath(document, appendPath(base, "keyType")); !present {
				add(appendPath(base, "keyType"), "New managed certificates require an explicit certificate key type.")
			}
			for _, path := range [][]string{
				appendPath(appendPath(base, "renew"), "days"),
				appendPath(appendPath(base, "renew"), "reuseKey"),
				appendPath(appendPath(base, "renew"), "disableRandomSleep"),
				appendPath(appendPath(appendPath(base, "renew"), "ari"), "disable"),
				appendPath(appendPath(appendPath(base, "renew"), "ari"), "waitToRenewDuration"),
			} {
				if _, present := nodeAtPath(document, path); !present {
					add(path, "New managed certificates require explicit renewal behavior.")
				}
			}
		}
		selectedChallenge := configuration.Challenges[certificate.Challenge]
		_, implicitUnsupported := implicitUnsupportedChallenges[certificate.Challenge]
		explicitUnsupported := selectedChallenge != nil &&
			(selectedChallenge.TLS != nil || selectedChallenge.DNSPersist != nil ||
				(selectedChallenge.DNS != nil && (!allowCoreDNS || !integrations.SupportsCoreDNSProvider(selectedChallenge.DNS.Provider))))
		if selectedChallenge != nil && selectedChallenge.HTTP == nil && !implicitUnsupported && !explicitUnsupported {
			if selectedChallenge.DNS == nil {
				add(appendPath(base, "challenge"), "Managed certificates must reference a supported HTTP-01 or DNS-01 challenge.")
			}
		}
		seen := make(map[string]struct{}, len(certificate.Domains))
		duplicates := make(map[string]struct{})
		wildcard := false
		for _, domain := range certificate.Domains {
			canonical, isWildcard, valid := canonicalDNSName(domain)
			if !valid {
				add(appendPath(base, "domains"), "Certificate DNS names must be canonical ASCII host names with an optional leftmost wildcard.")
				continue
			}
			if _, duplicate := seen[canonical]; duplicate {
				if _, alreadyReported := duplicates[canonical]; !alreadyReported {
					add(appendPath(base, "domains"), "Certificate DNS names must not contain duplicates.")
					duplicates[canonical] = struct{}{}
				}
			}
			seen[canonical] = struct{}{}
			wildcard = wildcard || isWildcard
		}
		if wildcard {
			challenge := configuration.Challenges[certificate.Challenge]
			if challenge != nil && challenge.HTTP != nil {
				add(appendPath(base, "challenge"), "Wildcard certificates require DNS-01 and cannot use the HTTP-01 integration.")
			}
		}
		if certificate.Renew != nil {
			if certificate.Renew.Days < 0 || certificate.Renew.Days > 365 {
				add(appendPath(appendPath(base, "renew"), "days"), "Renewal days must be between zero and 365.")
			}
			if certificate.Renew.ARI != nil && (certificate.Renew.ARI.WaitToRenewDuration < 0 || certificate.Renew.ARI.WaitToRenewDuration > maximumARIWait) {
				add(appendPath(appendPath(appendPath(base, "renew"), "ari"), "waitToRenewDuration"), "Maximum ARI wait is outside the supported zero-to-ten-minute range.")
			}
		}
	}
	return issues
}

func anyNativePathPresent(document *yaml.Node, prefix []string, keys ...string) bool {
	for _, key := range keys {
		if _, present := nodeAtPath(document, appendPath(prefix, key)); present {
			return true
		}
	}
	return false
}

func validateCoreDNSChallenge(
	document *yaml.Node,
	name string,
	dns *nativeDNSChallenge,
	creation bool,
	add func([]string, string),
) {
	base := []string{"challenges", name, "dns"}
	if _, present := nodeAtPath(document, appendPath(base, "provider")); !present {
		add(appendPath(base, "provider"), "Managed DNS-01 requires an explicit supported provider code.")
	}
	if _, present := nodeAtPath(document, appendPath(base, "envFile")); !present || dns.EnvFile == "" {
		add(appendPath(base, "envFile"), "Managed DNS-01 requires one explicit provider credential file.")
	}
	if creation {
		if _, present := nodeAtPath(document, appendPath(base, "dnsTimeout")); !present {
			add(appendPath(base, "dnsTimeout"), "New managed DNS-01 challenges require an explicit resolver timeout.")
		}
		for _, path := range [][]string{
			appendPath(appendPath(base, "propagation"), "disableAuthoritativeNameservers"),
			appendPath(appendPath(base, "propagation"), "disableRecursiveNameservers"),
			appendPath(appendPath(base, "propagation"), "wait"),
		} {
			if _, present := nodeAtPath(document, path); !present {
				add(path, "New managed DNS-01 challenges require explicit propagation behavior.")
			}
		}
	}
	if dns.DNSTimeout < 0 || dns.DNSTimeout > 600 {
		add(appendPath(base, "dnsTimeout"), "DNS resolver timeout must be zero through 600 seconds.")
	}
	for _, resolver := range dns.Resolvers {
		if !validDNSResolver(resolver) {
			add(appendPath(base, "resolvers"), "Recursive resolvers must be canonical DNS names or IP addresses with an optional port.")
			break
		}
	}
	if dns.Propagation != nil {
		if dns.Propagation.Wait < 0 || dns.Propagation.Wait > maximumDNSWait {
			add(appendPath(appendPath(base, "propagation"), "wait"), "Fixed DNS propagation wait is outside the supported zero-to-ten-minute range.")
		}
		if dns.Propagation.Wait > 0 && (dns.Propagation.DisableAuthoritativeNameservers || dns.Propagation.DisableRecursiveNameservers) {
			add(appendPath(base, "propagation"), "A fixed propagation wait cannot be mixed with nameserver-check overrides.")
		}
	}
}

func validDNSResolver(value string) bool {
	if value == "" || len(value) > 256 || strings.TrimSpace(value) != value || strings.Contains(value, "/") {
		return false
	}
	host := value
	if parsedHost, port, err := net.SplitHostPort(value); err == nil {
		host = parsedHost
		parsedPort, portErr := strconv.Atoi(port)
		if portErr != nil || parsedPort < 1 || parsedPort > 65535 {
			return false
		}
	} else if strings.Count(value, ":") > 1 {
		host = strings.Trim(value, "[]")
	}
	if net.ParseIP(host) != nil {
		return true
	}
	_, _, valid := canonicalDNSName(strings.ToLower(host))
	return valid
}

// validateCoreTransition applies registration prerequisites only when a
// candidate introduces an account identity or changes its effective ACME
// directory. Existing registered accounts do not need to retain registration
// inputs forever.
func validateCoreTransition(baseDocument, candidateDocument *yaml.Node, eabReplacements map[string]bool, limit int) []Issue {
	var base, candidate nativeConfiguration
	if baseDocument.Content[0].Decode(&base) != nil || candidateDocument.Content[0].Decode(&candidate) != nil {
		return nil
	}
	applyNativeDefaults(&base)
	applyNativeDefaults(&candidate)
	issues := make([]Issue, 0)
	add := func(path []string, summary string) {
		if len(issues) >= limit {
			return
		}
		line, column := position(candidateDocument, path)
		issues = append(issues, Issue{Class: IssueConstraint, Path: pointer(path), Line: line, Column: column, Summary: summary, BlocksExecution: true})
	}
	for _, name := range sortedKeys(candidate.Accounts) {
		account := candidate.Accounts[name]
		if account == nil {
			continue
		}
		prior, existed := base.Accounts[name]
		priorURL := ""
		if existed && prior != nil {
			priorURL = canonicalCAServerURLs[prior.Server]
		}
		currentURL := canonicalCAServerURLs[account.Server]
		if currentURL == "" || existed && priorURL == currentURL {
			continue
		}
		basePath := []string{"accounts", name}
		if !account.AcceptsTermsOfService {
			add(appendPath(basePath, "acceptsTermsOfService"), "A new ACME account or server transition must explicitly accept the selected CA terms of service.")
		}
		kind := acceptedCAServers[account.Server]
		if kind == caLetsEncrypt && !validAccountEmail(account.Email) {
			add(appendPath(basePath, "email"), "A new Let's Encrypt account requires an account email.")
		}
		requiresEAB := kind == caGoogleTrust || kind == caSSLCom || kind == caGoDaddy
		if requiresEAB && account.ExternalAccountBinding == nil {
			add(appendPath(basePath, "eab"), "A new account for the selected CA requires External Account Binding credentials.")
		}
		if (requiresEAB || account.ExternalAccountBinding != nil) && !eabReplacements[name] {
			add(appendPath(basePath, "eab"), "A new account or server transition using EAB requires current KID and write-only HMAC inputs in this reviewed request.")
		}
		if kind == caZeroSSL && account.ExternalAccountBinding == nil && !validAccountEmail(account.Email) {
			add(appendPath(basePath, "email"), "A new ZeroSSL account requires an email when explicit EAB is absent.")
		}
		if existed && priorURL != "" && priorURL != currentURL && sameDirectoryHost(priorURL, currentURL) {
			add(appendPath(basePath, "server"), "This server transition shares native account storage with the prior endpoint; create a distinct account name instead.")
		}
	}
	return issues
}

func sameDirectoryHost(left, right string) bool {
	leftURL, leftErr := url.Parse(left)
	rightURL, rightErr := url.Parse(right)
	return leftErr == nil && rightErr == nil && leftURL.Hostname() != "" && leftURL.Hostname() == rightURL.Hostname()
}

func validAccountEmail(value string) bool {
	if value == "" || len(value) > 254 || strings.TrimSpace(value) != value {
		return false
	}
	address, err := mail.ParseAddress(value)
	return err == nil && address.Address == value && address.Name == "" && strings.Contains(value, "@")
}

func validManagedEntityName(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for index, character := range value {
		if index == 0 && !asciiAlphaNumeric(character) {
			return false
		}
		if !asciiAlphaNumeric(character) && character != '.' && character != '_' && character != '@' && character != '-' {
			return false
		}
	}
	return true
}

func asciiAlphaNumeric(character rune) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
}

func validEABHMAC(value string) bool {
	if value == "" {
		return false
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return len(decoded) != 0
	}
	decoded, err := base64.URLEncoding.DecodeString(value)
	return err == nil && len(decoded) != 0
}

func validHTTPAddress(value string) bool {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return false
	}
	return host == "" || net.ParseIP(host) != nil
}

func validProxyHeader(value string) bool {
	if value == "" || len(value) > 64 || textproto.CanonicalMIMEHeaderKey(value) != value {
		return false
	}
	for _, character := range value {
		if asciiAlphaNumeric(character) || strings.ContainsRune("!#$%&'*+-.^_`|~", character) {
			continue
		}
		return false
	}
	return true
}

func canonicalDNSName(value string) (string, bool, bool) {
	if value == "" || value != strings.ToLower(value) || strings.TrimSpace(value) != value || len(value) > 253 {
		return "", false, false
	}
	wildcard := strings.HasPrefix(value, "*.")
	name := value
	if wildcard {
		name = strings.TrimPrefix(value, "*.")
	}
	if name == "" || strings.Contains(name, "*") || net.ParseIP(name) != nil || strings.HasSuffix(name, ".") {
		return "", wildcard, false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return "", wildcard, false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", wildcard, false
		}
		for _, character := range label {
			if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
				return "", wildcard, false
			}
		}
	}
	return value, wildcard, true
}
