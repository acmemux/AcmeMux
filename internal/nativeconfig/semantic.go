package nativeconfig

import (
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	defaultAccountID = "noemail@example.com"
	defaultDirectory = "https://acme-v02.api.letsencrypt.org/directory"
)

type nativeConfiguration struct {
	Storage      string                        `yaml:"storage,omitempty"`
	NetworkStack string                        `yaml:"networkStack,omitempty"`
	UserAgent    string                        `yaml:"userAgent,omitempty"`
	Servers      map[string]*nativeServer      `yaml:"servers,omitempty"`
	Accounts     map[string]*nativeAccount     `yaml:"accounts,omitempty"`
	Challenges   map[string]*nativeChallenge   `yaml:"challenges,omitempty"`
	Certificates map[string]*nativeCertificate `yaml:"certificates,omitempty"`
	Hooks        *nativeHooks                  `yaml:"hooks,omitempty"`
	Log          *nativeLog                    `yaml:"log,omitempty"`
}

type nativeServer struct {
	URL                 string `yaml:"url,omitempty"`
	TLSSkipVerify       bool   `yaml:"tlsSkipVerify,omitempty"`
	OverallRequestLimit int    `yaml:"overallRequestLimit,omitempty"`
	HTTPTimeout         int    `yaml:"httpTimeout,omitempty"`
	CertTimeout         int    `yaml:"certTimeout,omitempty"`
}

type nativeAccount struct {
	ID                     string                 `yaml:"-"`
	Server                 string                 `yaml:"server,omitempty"`
	Email                  string                 `yaml:"email,omitempty"`
	KeyType                string                 `yaml:"keyType,omitempty"`
	AcceptsTermsOfService  bool                   `yaml:"acceptsTermsOfService,omitempty"`
	ExternalAccountBinding *nativeExternalBinding `yaml:"eab,omitempty"`
}

type nativeExternalBinding struct {
	KID     string `yaml:"kid,omitempty"`
	HMACKey string `yaml:"hmacKey,omitempty"`
}

type nativeChallenge struct {
	ID         string                     `yaml:"-"`
	HTTP       *nativeHTTPChallenge       `yaml:"http,omitempty"`
	TLS        *nativeTLSChallenge        `yaml:"tls,omitempty"`
	DNS        *nativeDNSChallenge        `yaml:"dns,omitempty"`
	DNSPersist *nativeDNSPersistChallenge `yaml:"dnsPersist,omitempty"`
}

type nativeHTTPChallenge struct {
	Address        string        `yaml:"address,omitempty"`
	Delay          time.Duration `yaml:"delay,omitempty"`
	ProxyHeader    string        `yaml:"proxyHeader,omitempty"`
	Webroot        string        `yaml:"webroot,omitempty"`
	MemcachedHosts []string      `yaml:"memcachedHosts,omitempty"`
	S3Bucket       string        `yaml:"s3Bucket,omitempty"`
}

type nativeTLSChallenge struct {
	Address string        `yaml:"address,omitempty"`
	Delay   time.Duration `yaml:"delay,omitempty"`
}

type nativeDNSChallenge struct {
	Provider    string             `yaml:"provider,omitempty"`
	Propagation *nativePropagation `yaml:"propagation,omitempty"`
	DNSTimeout  int                `yaml:"dnsTimeout,omitempty"`
	Resolvers   []string           `yaml:"resolvers,omitempty"`
	EnvFile     string             `yaml:"envFile,omitempty"`
}

type nativeDNSPersistChallenge struct {
	IssuerDomainName string             `yaml:"issuerDomainName,omitempty"`
	PersistUntil     time.Time          `yaml:"persistUntil,omitempty"`
	Propagation      *nativePropagation `yaml:"propagation,omitempty"`
	DNSTimeout       int                `yaml:"dnsTimeout,omitempty"`
	Resolvers        []string           `yaml:"resolvers,omitempty"`
}

type nativePropagation struct {
	DisableAuthoritativeNameservers bool          `yaml:"disableAuthoritativeNameservers,omitempty"`
	DisableRecursiveNameservers     bool          `yaml:"disableRecursiveNameservers,omitempty"`
	Wait                            time.Duration `yaml:"wait,omitempty"`
}

type nativeCertificate struct {
	ID                             string       `yaml:"-"`
	Domains                        []string     `yaml:"domains,omitempty"`
	CSR                            string       `yaml:"csr,omitempty"`
	KeyType                        string       `yaml:"keyType,omitempty"`
	Challenge                      string       `yaml:"challenge,omitempty"`
	Account                        string       `yaml:"account,omitempty"`
	EnableCommonName               bool         `yaml:"enableCommonName,omitempty"`
	PreferredChain                 string       `yaml:"preferredChain,omitempty"`
	Profile                        string       `yaml:"profile,omitempty"`
	NotBefore                      time.Time    `yaml:"notBefore,omitempty"`
	NotAfter                       time.Time    `yaml:"notAfter,omitempty"`
	NoBundle                       bool         `yaml:"noBundle,omitempty"`
	MustStaple                     bool         `yaml:"mustStaple,omitempty"`
	AlwaysDeactivateAuthorizations bool         `yaml:"alwaysDeactivateAuthorizations,omitempty"`
	Renew                          *nativeRenew `yaml:"renew,omitempty"`
	PFX                            *nativePFX   `yaml:"pfx,omitempty"`
}

type nativeRenew struct {
	ARI                *nativeARI `yaml:"ari,omitempty"`
	Days               int        `yaml:"days,omitempty"`
	ReuseKey           bool       `yaml:"reuseKey,omitempty"`
	DisableRandomSleep bool       `yaml:"disableRandomSleep,omitempty"`
}

type nativeARI struct {
	Disable             bool          `yaml:"disable,omitempty"`
	WaitToRenewDuration time.Duration `yaml:"waitToRenewDuration,omitempty"`
}

type nativePFX struct {
	Password string `yaml:"password,omitempty"`
	Format   string `yaml:"format,omitempty"`
}

type nativeHooks struct {
	Pre    *nativeHook `yaml:"pre,omitempty"`
	Deploy *nativeHook `yaml:"deploy,omitempty"`
	Post   *nativeHook `yaml:"post,omitempty"`
}

type nativeHook struct {
	Command string        `yaml:"command,omitempty"`
	Timeout time.Duration `yaml:"timeout,omitempty"`
}

type nativeLog struct {
	Level  string `yaml:"level,omitempty"`
	Format string `yaml:"format,omitempty"`
}

func validateSemantics(document *yaml.Node, limit int) []Issue {
	var configuration nativeConfiguration
	if err := document.Content[0].Decode(&configuration); err != nil {
		return []Issue{{
			Class: IssueSemantic, Path: "/", Summary: "Configuration cannot be decoded by the admitted lego source model.",
			BlocksReplacement: true, BlocksExecution: true,
		}}
	}
	applyNativeDefaults(&configuration)
	issues := make([]Issue, 0)
	add := func(path []string, summary string) {
		if len(issues) >= limit {
			return
		}
		line, column := position(document, path)
		issues = append(issues, Issue{
			Class: IssueSemantic, Path: pointer(path), Line: line, Column: column, Summary: summary,
			BlocksReplacement: true, BlocksExecution: true,
		})
	}

	if configuration.Log != nil && configuration.Log.Format != "" &&
		configuration.Log.Format != "text" && configuration.Log.Format != "json" && configuration.Log.Format != "colored" {
		add([]string{"log", "format"}, "Log format is not supported by the admitted lego source model.")
	}

	if len(configuration.Challenges) == 0 {
		add([]string{"challenges"}, "At least one challenge configuration is required.")
	}
	for _, name := range sortedKeys(configuration.Challenges) {
		challenge := configuration.Challenges[name]
		base := []string{"challenges", name}
		if strings.TrimSpace(name) == "" {
			add(base, "Challenge name must not be empty.")
		}
		if challenge == nil {
			add(base, "Challenge configuration must be an object.")
			continue
		}
		if challenge.HTTP == nil && challenge.TLS == nil && challenge.DNS == nil && challenge.DNSPersist == nil {
			add(base, "At least one challenge type must be defined.")
		}
		if challenge.DNS != nil {
			if challenge.DNS.Provider == "" {
				add(appendPath(base, "dns"), "DNS challenge provider is required.")
			}
			validatePropagation(document, appendPath(appendPath(base, "dns"), "propagation"), challenge.DNS.Propagation, add)
		}
		if challenge.DNSPersist != nil {
			validatePropagation(document, appendPath(appendPath(base, "dnsPersist"), "propagation"), challenge.DNSPersist.Propagation, add)
		}
	}

	if len(configuration.Certificates) == 0 {
		add([]string{"certificates"}, "At least one certificate configuration is required.")
	}
	for _, name := range sortedKeys(configuration.Certificates) {
		certificate := configuration.Certificates[name]
		base := []string{"certificates", name}
		if strings.TrimSpace(name) == "" {
			add(base, "Certificate name must not be empty.")
		}
		if certificate == nil {
			add(base, "Certificate configuration must be an object.")
			continue
		}
		if len(certificate.Domains) == 0 && certificate.CSR == "" {
			add(base, "Certificate requires at least one domain or a CSR.")
		}
		if len(certificate.Domains) > 0 && certificate.CSR != "" {
			add(base, "Certificate domains and CSR are mutually exclusive.")
		}
		if certificate.Account == "" {
			add(appendPath(base, "account"), "Certificate account is required.")
		} else if _, ok := configuration.Accounts[certificate.Account]; !ok {
			add(appendPath(base, "account"), "Certificate references an account that is not configured.")
		}
		if certificate.Challenge == "" {
			add(appendPath(base, "challenge"), "Certificate challenge is required.")
		} else if _, ok := configuration.Challenges[certificate.Challenge]; !ok {
			add(appendPath(base, "challenge"), "Certificate references a challenge that is not configured.")
		}
		if !supportedKeyType(certificate.KeyType) {
			add(appendPath(base, "keyType"), "Certificate key type is not supported by the admitted lego source model.")
		}
		if certificate.PFX != nil && !supportedPFX(certificate.PFX.Format) {
			add(appendPath(appendPath(base, "pfx"), "format"), "Certificate PFX format is not supported by the admitted lego source model.")
		}
	}

	for _, name := range sortedKeys(configuration.Servers) {
		if strings.TrimSpace(name) == "" {
			add([]string{"servers", name}, "Server name must not be empty.")
		}
	}

	if len(configuration.Accounts) == 0 {
		add([]string{"accounts"}, "At least one account configuration is required.")
	}
	for _, name := range sortedKeys(configuration.Accounts) {
		account := configuration.Accounts[name]
		base := []string{"accounts", name}
		if strings.TrimSpace(name) == "" {
			add(base, "Account name must not be empty.")
		}
		if account == nil {
			add(base, "Account configuration must be an object.")
			continue
		}
		if !supportedKeyType(account.KeyType) {
			add(appendPath(base, "keyType"), "Account key type is not supported by the admitted lego source model.")
		}
		if account.ExternalAccountBinding != nil &&
			(account.ExternalAccountBinding.KID == "" || account.ExternalAccountBinding.HMACKey == "") {
			add(appendPath(base, "eab"), "External Account Binding requires both KID and HMAC key.")
		}
	}
	return issues
}

func applyNativeDefaults(configuration *nativeConfiguration) {
	if configuration.Storage == "" {
		configuration.Storage = ".lego"
	}
	if configuration.Servers == nil {
		configuration.Servers = make(map[string]*nativeServer)
	}
	if configuration.Accounts == nil {
		configuration.Accounts = make(map[string]*nativeAccount)
	}
	if configuration.Challenges == nil {
		configuration.Challenges = make(map[string]*nativeChallenge)
	}
	if configuration.Certificates == nil {
		configuration.Certificates = make(map[string]*nativeCertificate)
	}
	for _, server := range configuration.Servers {
		if server != nil && server.OverallRequestLimit <= 0 {
			server.OverallRequestLimit = 18
		}
	}
	for id, account := range configuration.Accounts {
		if account == nil {
			continue
		}
		account.ID = id
		if account.KeyType == "" {
			account.KeyType = "EC256"
		}
		if account.Server == "" {
			account.Server = defaultDirectory
		}
	}
	for id, challenge := range configuration.Challenges {
		if challenge == nil {
			continue
		}
		challenge.ID = id
		if challenge.TLS != nil && challenge.TLS.Address == "" {
			challenge.TLS.Address = ":443"
		}
		if challenge.HTTP != nil && challenge.HTTP.Address == "" {
			challenge.HTTP.Address = ":80"
		}
	}
	defaultAccount := nativeDefaultAccount(configuration)
	for id, certificate := range configuration.Certificates {
		if certificate == nil {
			continue
		}
		certificate.ID = id
		if certificate.Account == "" {
			certificate.Account = defaultAccount
		}
		if certificate.Account == defaultAccountID {
			if _, ok := configuration.Accounts[defaultAccountID]; !ok {
				configuration.Accounts[defaultAccountID] = &nativeAccount{Server: defaultDirectory, KeyType: "EC256"}
			}
		}
		if certificate.KeyType == "" {
			certificate.KeyType = "EC256"
			if account, ok := configuration.Accounts[certificate.Account]; ok && account != nil && account.KeyType != "" {
				certificate.KeyType = account.KeyType
			}
		}
		if certificate.Renew == nil {
			certificate.Renew = &nativeRenew{}
		}
		if certificate.Renew.ARI == nil {
			certificate.Renew.ARI = &nativeARI{}
		}
		switch certificate.Challenge {
		case "http-01":
			if _, ok := configuration.Challenges["http-01"]; !ok {
				configuration.Challenges["http-01"] = &nativeChallenge{HTTP: &nativeHTTPChallenge{Address: ":80"}}
			}
		case "tls-alpn-01":
			if _, ok := configuration.Challenges["tls-alpn-01"]; !ok {
				configuration.Challenges["tls-alpn-01"] = &nativeChallenge{TLS: &nativeTLSChallenge{Address: ":443"}}
			}
		case "dns-persist-01":
			if _, ok := configuration.Challenges["dns-persist-01"]; !ok {
				configuration.Challenges["dns-persist-01"] = &nativeChallenge{DNSPersist: &nativeDNSPersistChallenge{}}
			}
		case "":
			if len(configuration.Challenges) == 1 {
				for challenge := range configuration.Challenges {
					certificate.Challenge = challenge
				}
			}
		}
	}
	if configuration.Hooks != nil {
		for _, hook := range []*nativeHook{configuration.Hooks.Pre, configuration.Hooks.Deploy, configuration.Hooks.Post} {
			if hook != nil && hook.Command != "" && hook.Timeout == 0 {
				hook.Timeout = 2 * time.Minute
			}
		}
	}
}

func nativeDefaultAccount(configuration *nativeConfiguration) string {
	switch len(configuration.Accounts) {
	case 0:
		return defaultAccountID
	case 1:
		for account := range configuration.Accounts {
			return account
		}
	}
	return ""
}

func validatePropagation(_ *yaml.Node, path []string, propagation *nativePropagation, add func([]string, string)) {
	if propagation == nil || propagation.Wait == 0 {
		return
	}
	if propagation.Wait < 0 {
		add(appendPath(path, "wait"), "Propagation wait must be positive.")
	}
	if propagation.DisableAuthoritativeNameservers {
		add(path, "Propagation wait and authoritative-nameserver disabling are mutually exclusive.")
	}
	if propagation.DisableRecursiveNameservers {
		add(path, "Propagation wait and recursive-nameserver disabling are mutually exclusive.")
	}
}

func supportedKeyType(value string) bool {
	switch value {
	case "EC256", "EC384", "RSA2048", "RSA3072", "RSA4096", "RSA8192":
		return true
	default:
		return false
	}
}

func supportedPFX(value string) bool {
	return value == "DES" || value == "RC2" || value == "SHA256" || value == "PBMAC1"
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
