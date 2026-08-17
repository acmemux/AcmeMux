package integrations

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/acmemux/AcmeMux/internal/compatibility"
)

const (
	CloudDNSManifestID ManifestID = "native-cloud-dns-providers-v1"

	FieldAzureEnvironment               FieldID = "provider.azuredns.environment"
	FieldAzureSubscriptionID            FieldID = "provider.azuredns.subscription_id"
	FieldAzureResourceGroup             FieldID = "provider.azuredns.resource_group"
	FieldAzureZoneName                  FieldID = "provider.azuredns.zone_name"
	FieldAzurePrivateZone               FieldID = "provider.azuredns.private_zone"
	FieldAzureAuthMethod                FieldID = "provider.azuredns.auth_method"
	FieldAzureTenantID                  FieldID = "provider.azuredns.tenant_id"
	FieldAzureClientID                  FieldID = "provider.azuredns.client_id"
	FieldAzureClientSecret              FieldID = "provider.azuredns.client_secret"
	FieldAzureClientCertificatePath     FieldID = "provider.azuredns.client_certificate_path"
	FieldAzureClientCertificatePassword FieldID = "provider.azuredns.client_certificate_password"
	FieldAzureFederatedTokenFile        FieldID = "provider.azuredns.federated_token_file"
	FieldAzureMSITimeout                FieldID = "provider.azuredns.msi_timeout"
	FieldAzureOIDCToken                 FieldID = "provider.azuredns.oidc_token"
	FieldAzureOIDCTokenFile             FieldID = "provider.azuredns.oidc_token_file"
	FieldAzureOIDCRequestURL            FieldID = "provider.azuredns.oidc_request_url"
	FieldAzureOIDCRequestToken          FieldID = "provider.azuredns.oidc_request_token"
	FieldAzureServiceConnectionID       FieldID = "provider.azuredns.service_connection_id"
	FieldAzureSystemAccessToken         FieldID = "provider.azuredns.system_access_token"
	FieldAzureSystemOIDCRequestURI      FieldID = "provider.azuredns.system_oidc_request_uri"
	FieldAzureCLIPath                   FieldID = "provider.azuredns.cli_path"
	FieldAzureCLIConfigDirectory        FieldID = "provider.azuredns.cli_config_directory"
	FieldAzureIMDSEndpoint              FieldID = "provider.azuredns.imds_endpoint"
	FieldAzureIdentityEndpoint          FieldID = "provider.azuredns.identity_endpoint"
	FieldAzureTTL                       FieldID = "provider.azuredns.ttl"
	FieldAzurePropagationTimeout        FieldID = "provider.azuredns.propagation_timeout"
	FieldAzurePollingInterval           FieldID = "provider.azuredns.polling_interval"

	FieldAWSAccessKeyID              FieldID = "provider.route53.access_key_id"
	FieldAWSSecretAccessKey          FieldID = "provider.route53.secret_access_key"
	FieldAWSSessionToken             FieldID = "provider.route53.session_token"
	FieldAWSRegion                   FieldID = "provider.route53.region"
	FieldAWSHostedZoneID             FieldID = "provider.route53.hosted_zone_id"
	FieldAWSProfile                  FieldID = "provider.route53.profile"
	FieldAWSSharedCredentialsFile    FieldID = "provider.route53.shared_credentials_file"
	FieldAWSSDKLoadConfig            FieldID = "provider.route53.sdk_load_config"
	FieldAWSEC2MetadataDisabled      FieldID = "provider.route53.ec2_metadata_disabled"
	FieldAWSAssumeRoleARN            FieldID = "provider.route53.assume_role_arn"
	FieldAWSExternalID               FieldID = "provider.route53.external_id"
	FieldAWSPrivateZone              FieldID = "provider.route53.private_zone"
	FieldAWSMaxRetries               FieldID = "provider.route53.max_retries"
	FieldAWSWaitForRecordSetsChanged FieldID = "provider.route53.wait_for_record_sets_changed"
	FieldAWSTTL                      FieldID = "provider.route53.ttl"
	FieldAWSPropagationTimeout       FieldID = "provider.route53.propagation_timeout"
	FieldAWSPollingInterval          FieldID = "provider.route53.polling_interval"
)

var (
	cloudDNSOnce      sync.Once
	cloudDNSManifest  Manifest
	awsProfilePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$`)
	awsRegionPattern  = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]?$`)
)

func buildCloudDNSManifest() Manifest {
	core := buildCoreDNSManifestForProviders(SupportedDNSProviders())
	dns := []SelectorSegment{YAMLKey("challenges"), YAMLBinding(BindingChallenge), YAMLKey("dns")}
	envFile := appendSelector(dns, "envFile")
	fields := []FieldSpec{
		dotenvField(FieldAzureEnvironment, "Azure cloud", SensitivityPublic, envFile, "AZURE_ENVIRONMENT", 32),
		dotenvField(FieldAzureSubscriptionID, "Azure subscription ID", SensitivityPublic, envFile, "AZURE_SUBSCRIPTION_ID", 128),
		dotenvField(FieldAzureResourceGroup, "Azure resource group", SensitivityPublic, envFile, "AZURE_RESOURCE_GROUP", 256),
		dotenvField(FieldAzureZoneName, "Azure DNS zone", SensitivityPublic, envFile, "AZURE_ZONE_NAME", 253),
		dotenvField(FieldAzurePrivateZone, "Azure private zone", SensitivityPublic, envFile, "AZURE_PRIVATE_ZONE", 5),
		dotenvField(FieldAzureAuthMethod, "Azure authentication method", SensitivityPublic, envFile, "AZURE_AUTH_METHOD", 16),
		dotenvField(FieldAzureTenantID, "Azure tenant ID", SensitivityPublic, envFile, "AZURE_TENANT_ID", 128),
		dotenvField(FieldAzureClientID, "Azure client ID", SensitivityPublic, envFile, "AZURE_CLIENT_ID", 128),
		dotenvField(FieldAzureClientSecret, "Azure client secret", SensitivitySecret, envFile, "AZURE_CLIENT_SECRET", 8192),
		dotenvField(FieldAzureClientCertificatePath, "Azure client certificate", SensitivityPublic, envFile, "AZURE_CLIENT_CERTIFICATE_PATH", 4095),
		dotenvField(FieldAzureClientCertificatePassword, "Azure client certificate password", SensitivitySecret, envFile, "AZURE_CLIENT_CERTIFICATE_PASSWORD", 4096),
		dotenvField(FieldAzureFederatedTokenFile, "Azure workload token file", SensitivityPublic, envFile, "AZURE_FEDERATED_TOKEN_FILE", 4095),
		dotenvField(FieldAzureMSITimeout, "Azure managed identity timeout", SensitivityPublic, envFile, "AZURE_AUTH_MSI_TIMEOUT", 10),
		dotenvField(FieldAzureOIDCToken, "Azure OIDC assertion", SensitivitySecret, envFile, "AZURE_OIDC_TOKEN", 65536),
		dotenvField(FieldAzureOIDCTokenFile, "Azure OIDC assertion file", SensitivityPublic, envFile, "AZURE_OIDC_TOKEN_FILE_PATH", 4095),
		dotenvField(FieldAzureOIDCRequestURL, "Azure OIDC request URL", SensitivityPublic, envFile, "AZURE_OIDC_REQUEST_URL", 2048),
		dotenvField(FieldAzureOIDCRequestToken, "Azure OIDC request token", SensitivitySecret, envFile, "AZURE_OIDC_REQUEST_TOKEN", 8192),
		dotenvField(FieldAzureServiceConnectionID, "Azure service connection ID", SensitivityPublic, envFile, "AZURE_SERVICE_CONNECTION_ID", 256),
		dotenvField(FieldAzureSystemAccessToken, "Azure pipeline system token", SensitivitySecret, envFile, "AZURE_SYSTEM_ACCESS_TOKEN", 8192),
		dotenvField(FieldAzureSystemOIDCRequestURI, "Azure pipeline OIDC endpoint", SensitivityPublic, envFile, "SYSTEM_OIDCREQUESTURI", 2048),
		dotenvField(FieldAzureCLIPath, "Azure CLI helper directory", SensitivityPublic, envFile, "PATH", 4095),
		dotenvField(FieldAzureCLIConfigDirectory, "Azure CLI configuration directory", SensitivityPublic, envFile, "AZURE_CONFIG_DIR", 4095),
		dotenvField(FieldAzureIMDSEndpoint, "Azure Arc IMDS endpoint", SensitivityPublic, envFile, "IMDS_ENDPOINT", 2048),
		dotenvField(FieldAzureIdentityEndpoint, "Azure Arc identity endpoint", SensitivityPublic, envFile, "IDENTITY_ENDPOINT", 2048),
		dotenvField(FieldAzureTTL, "Azure TXT TTL", SensitivityPublic, envFile, "AZURE_TTL", 10),
		dotenvField(FieldAzurePropagationTimeout, "Azure propagation timeout", SensitivityPublic, envFile, "AZURE_PROPAGATION_TIMEOUT", 10),
		dotenvField(FieldAzurePollingInterval, "Azure polling interval", SensitivityPublic, envFile, "AZURE_POLLING_INTERVAL", 10),

		dotenvField(FieldAWSAccessKeyID, "AWS access key ID", SensitivitySecret, envFile, "AWS_ACCESS_KEY_ID", 4096),
		dotenvField(FieldAWSSecretAccessKey, "AWS secret access key", SensitivitySecret, envFile, "AWS_SECRET_ACCESS_KEY", 4096),
		dotenvField(FieldAWSSessionToken, "AWS session token", SensitivitySecret, envFile, "AWS_SESSION_TOKEN", 16384),
		dotenvField(FieldAWSRegion, "AWS region", SensitivityPublic, envFile, "AWS_REGION", 64),
		dotenvField(FieldAWSHostedZoneID, "Route 53 hosted zone ID", SensitivityPublic, envFile, "AWS_HOSTED_ZONE_ID", 128),
		dotenvField(FieldAWSProfile, "AWS shared profile", SensitivityPublic, envFile, "AWS_PROFILE", 128),
		dotenvField(FieldAWSSharedCredentialsFile, "AWS shared credentials file", SensitivityPublic, envFile, "AWS_SHARED_CREDENTIALS_FILE", 4095),
		dotenvField(FieldAWSSDKLoadConfig, "AWS shared configuration loading", SensitivityPublic, envFile, "AWS_SDK_LOAD_CONFIG", 5),
		dotenvField(FieldAWSEC2MetadataDisabled, "AWS instance metadata disabled", SensitivityPublic, envFile, "AWS_EC2_METADATA_DISABLED", 5),
		dotenvField(FieldAWSAssumeRoleARN, "AWS assume-role ARN", SensitivityPublic, envFile, "AWS_ASSUME_ROLE_ARN", 2048),
		dotenvField(FieldAWSExternalID, "AWS assume-role external ID", SensitivitySecret, envFile, "AWS_EXTERNAL_ID", 4096),
		dotenvField(FieldAWSPrivateZone, "Route 53 private zone", SensitivityPublic, envFile, "AWS_PRIVATE_ZONE", 5),
		dotenvField(FieldAWSMaxRetries, "AWS maximum retries", SensitivityPublic, envFile, "AWS_MAX_RETRIES", 3),
		dotenvField(FieldAWSWaitForRecordSetsChanged, "Wait for Route 53 INSYNC", SensitivityPublic, envFile, "AWS_WAIT_FOR_RECORD_SETS_CHANGED", 5),
		dotenvField(FieldAWSTTL, "Route 53 TXT TTL", SensitivityPublic, envFile, "AWS_TTL", 10),
		dotenvField(FieldAWSPropagationTimeout, "Route 53 propagation timeout", SensitivityPublic, envFile, "AWS_PROPAGATION_TIMEOUT", 10),
		dotenvField(FieldAWSPollingInterval, "Route 53 polling interval", SensitivityPublic, envFile, "AWS_POLLING_INTERVAL", 10),
	}
	manifest, err := core.Extend(CloudDNSManifestID, fields...)
	if err != nil {
		panic("invalid cloud DNS integration manifest: " + err.Error())
	}
	return manifest
}

func CloudDNSManifest(runtimeID compatibility.ManifestID) (Manifest, bool) {
	cloudDNSOnce.Do(func() { cloudDNSManifest = buildCloudDNSManifest() })
	if !cloudDNSManifest.SupportsRuntime(runtimeID) {
		return Manifest{}, false
	}
	return cloudDNSManifest, true
}

func init() {
	for _, field := range []FieldID{
		FieldAzureEnvironment, FieldAzureSubscriptionID, FieldAzureResourceGroup, FieldAzureZoneName, FieldAzurePrivateZone,
		FieldAzureAuthMethod, FieldAzureTenantID, FieldAzureClientID, FieldAzureClientSecret, FieldAzureClientCertificatePath,
		FieldAzureClientCertificatePassword, FieldAzureFederatedTokenFile, FieldAzureMSITimeout, FieldAzureOIDCToken,
		FieldAzureOIDCTokenFile, FieldAzureOIDCRequestURL, FieldAzureOIDCRequestToken, FieldAzureServiceConnectionID,
		FieldAzureSystemAccessToken, FieldAzureSystemOIDCRequestURI, FieldAzureCLIPath, FieldAzureCLIConfigDirectory,
		FieldAzureIMDSEndpoint, FieldAzureIdentityEndpoint, FieldAzureTTL, FieldAzurePropagationTimeout, FieldAzurePollingInterval,
	} {
		providerFieldCodes[field] = "azuredns"
	}
	for _, field := range []FieldID{
		FieldAWSAccessKeyID, FieldAWSSecretAccessKey, FieldAWSSessionToken, FieldAWSRegion, FieldAWSHostedZoneID,
		FieldAWSProfile, FieldAWSSharedCredentialsFile, FieldAWSSDKLoadConfig, FieldAWSEC2MetadataDisabled,
		FieldAWSAssumeRoleARN, FieldAWSExternalID, FieldAWSPrivateZone, FieldAWSMaxRetries,
		FieldAWSWaitForRecordSetsChanged, FieldAWSTTL, FieldAWSPropagationTimeout, FieldAWSPollingInterval,
	} {
		providerFieldCodes[field] = "route53"
	}
}

func ValidateCloudDNSDotenvValue(id FieldID, value []byte) error {
	text := string(value)
	switch id {
	case FieldAzureEnvironment:
		if text != "public" && text != "usgovernment" && text != "china" {
			return fmt.Errorf("azure cloud is not supported")
		}
	case FieldAzureAuthMethod:
		if text != "env" && text != "wli" && text != "msi" && text != "cli" && text != "oidc" && text != "pipeline" {
			return fmt.Errorf("azure authentication method is not supported")
		}
	case FieldAzurePrivateZone, FieldAWSPrivateZone, FieldAWSWaitForRecordSetsChanged, FieldAWSSDKLoadConfig, FieldAWSEC2MetadataDisabled:
		if text != "true" && text != "false" {
			return fmt.Errorf("cloud boolean must be true or false")
		}
	case FieldAzureClientCertificatePath, FieldAzureFederatedTokenFile, FieldAzureOIDCTokenFile, FieldAzureCLIPath,
		FieldAzureCLIConfigDirectory, FieldAWSSharedCredentialsFile:
		if !filepath.IsAbs(text) || filepath.Clean(text) != text {
			return fmt.Errorf("cloud path must be canonical and absolute")
		}
	case FieldAzureOIDCRequestURL, FieldAzureSystemOIDCRequestURI:
		if err := validateCloudEndpoint(text, false); err != nil {
			return err
		}
	case FieldAzureIMDSEndpoint, FieldAzureIdentityEndpoint:
		if err := validateCloudEndpoint(text, true); err != nil {
			return err
		}
	case FieldAWSProfile:
		if !awsProfilePattern.MatchString(text) {
			return fmt.Errorf("AWS profile name is invalid")
		}
	case FieldAWSRegion:
		if !awsRegionPattern.MatchString(text) {
			return fmt.Errorf("AWS region is invalid")
		}
	case FieldAWSAssumeRoleARN:
		if !strings.HasPrefix(text, "arn:") || !strings.Contains(text, ":iam::") || !strings.Contains(text, ":role/") {
			return fmt.Errorf("AWS role ARN is invalid")
		}
	case FieldAzureTTL, FieldAzurePropagationTimeout, FieldAzurePollingInterval, FieldAzureMSITimeout,
		FieldAWSTTL, FieldAWSPropagationTimeout, FieldAWSPollingInterval:
		return validateDecimalRange(text, 1, 86400)
	case FieldAWSMaxRetries:
		return validateDecimalRange(text, 0, 20)
	}
	return nil
}

func validateCloudEndpoint(text string, loopbackOnly bool) error {
	parsed, err := url.Parse(text)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("cloud endpoint is invalid")
	}
	ip := net.ParseIP(parsed.Hostname())
	loopback := ip != nil && ip.IsLoopback()
	if loopbackOnly {
		if parsed.Scheme != "http" || !loopback {
			return fmt.Errorf("metadata endpoint must use loopback HTTP")
		}
		return nil
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopback) {
		return fmt.Errorf("cloud endpoint must use HTTPS or loopback HTTP")
	}
	return nil
}

func CloudDNSCredentialIssues(provider string, present map[FieldID]bool, values map[FieldID]string) []FieldID {
	need := func(fields ...FieldID) bool {
		for _, field := range fields {
			if !present[field] {
				return false
			}
		}
		return true
	}
	absent := func(fields ...FieldID) bool {
		for _, field := range fields {
			if present[field] {
				return false
			}
		}
		return true
	}
	switch provider {
	case "azuredns":
		base := need(FieldAzureAuthMethod, FieldAzureSubscriptionID, FieldAzureResourceGroup, FieldAzureEnvironment, FieldAzurePrivateZone)
		method := values[FieldAzureAuthMethod]
		valid := false
		switch method {
		case "env":
			secret := need(FieldAzureTenantID, FieldAzureClientID, FieldAzureClientSecret) && absent(FieldAzureClientCertificatePath, FieldAzureFederatedTokenFile)
			certificate := need(FieldAzureTenantID, FieldAzureClientID, FieldAzureClientCertificatePath) && absent(FieldAzureClientSecret, FieldAzureFederatedTokenFile)
			valid = secret || certificate
		case "wli":
			valid = need(FieldAzureTenantID, FieldAzureClientID, FieldAzureFederatedTokenFile) && absent(FieldAzureClientSecret, FieldAzureClientCertificatePath)
		case "msi":
			arcPair := present[FieldAzureIMDSEndpoint] == present[FieldAzureIdentityEndpoint]
			valid = arcPair && absent(FieldAzureClientSecret, FieldAzureClientCertificatePath, FieldAzureFederatedTokenFile,
				FieldAzureOIDCToken, FieldAzureOIDCTokenFile, FieldAzureOIDCRequestURL, FieldAzureOIDCRequestToken)
		case "cli":
			valid = need(FieldAzureCLIPath, FieldAzureCLIConfigDirectory) && absent(FieldAzureClientSecret, FieldAzureClientCertificatePath,
				FieldAzureFederatedTokenFile, FieldAzureOIDCToken, FieldAzureOIDCTokenFile, FieldAzureOIDCRequestURL, FieldAzureOIDCRequestToken)
		case "oidc":
			inline := present[FieldAzureOIDCToken]
			file := present[FieldAzureOIDCTokenFile]
			request := present[FieldAzureOIDCRequestURL] && present[FieldAzureOIDCRequestToken]
			valid = need(FieldAzureTenantID, FieldAzureClientID) && boolCount(inline, file, request) == 1
		case "pipeline":
			valid = need(FieldAzureTenantID, FieldAzureClientID, FieldAzureServiceConnectionID, FieldAzureSystemAccessToken, FieldAzureSystemOIDCRequestURI)
		}
		if base && valid {
			return nil
		}
		return []FieldID{FieldAzureAuthMethod, FieldAzureSubscriptionID, FieldAzureResourceGroup}
	case "route53":
		if !need(FieldAWSRegion, FieldAWSEC2MetadataDisabled, FieldAWSSDKLoadConfig) {
			return []FieldID{FieldAWSRegion, FieldAWSEC2MetadataDisabled}
		}
		static := need(FieldAWSAccessKeyID, FieldAWSSecretAccessKey) && absent(FieldAWSProfile, FieldAWSSharedCredentialsFile) && values[FieldAWSEC2MetadataDisabled] == "true"
		shared := need(FieldAWSProfile, FieldAWSSharedCredentialsFile) && absent(FieldAWSAccessKeyID, FieldAWSSecretAccessKey, FieldAWSSessionToken) && values[FieldAWSEC2MetadataDisabled] == "true" && values[FieldAWSSDKLoadConfig] == "false"
		instance := absent(FieldAWSAccessKeyID, FieldAWSSecretAccessKey, FieldAWSSessionToken, FieldAWSProfile, FieldAWSSharedCredentialsFile) && values[FieldAWSEC2MetadataDisabled] == "false" && values[FieldAWSSDKLoadConfig] == "false"
		if boolCount(static, shared, instance) != 1 || (present[FieldAWSExternalID] && !present[FieldAWSAssumeRoleARN]) {
			return []FieldID{FieldAWSAccessKeyID, FieldAWSProfile, FieldAWSEC2MetadataDisabled}
		}
		return nil
	}
	return nil
}

func boolCount(values ...bool) int {
	count := 0
	for _, value := range values {
		if value {
			count++
		}
	}
	return count
}
