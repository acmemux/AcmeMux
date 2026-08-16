import type {
  ConfigurationBinding,
  ConfigurationChange,
  ConfigurationValue,
  ProjectedField,
} from "../api/configuration";
import type { SecretDraft } from "../components/WriteOnlySecretField";

export const managedFieldIds = {
  storage: "workspace.storage",
  accountServer: "account.server",
  accountEmail: "account.email",
  accountKeyType: "account.key_type",
  accountTerms: "account.accepts_terms_of_service",
  accountEabKid: "account.eab.kid",
  accountEabHmac: "account.eab.hmac_key",
  certificateDomains: "certificate.domains",
  certificateKeyType: "certificate.key_type",
  certificateAccount: "certificate.account",
  certificateChallenge: "certificate.challenge",
  certificateRenewDays: "certificate.renew.days",
  certificateRenewReuseKey: "certificate.renew.reuse_key",
  certificateRenewDisableRandomSleep: "certificate.renew.disable_random_sleep",
  certificateRenewAriDisable: "certificate.renew.ari.disable",
  certificateRenewAriWait: "certificate.renew.ari.wait_to_renew_duration",
  challengeAddress: "challenge.http.address",
  challengeDelay: "challenge.http.delay",
  challengeProxyHeader: "challenge.http.proxy_header",
  challengeWebroot: "challenge.http.webroot",
  challengeDnsProvider: "challenge.dns.provider",
  challengeDnsTimeout: "challenge.dns.dns_timeout",
  challengeDnsResolvers: "challenge.dns.resolvers",
  challengeDnsEnvFile: "challenge.dns.env_file",
  challengeDnsDisableAuthoritative:
    "challenge.dns.propagation.disable_authoritative_nameservers",
  challengeDnsDisableRecursive:
    "challenge.dns.propagation.disable_recursive_nameservers",
  challengeDnsPropagationWait: "challenge.dns.propagation.wait",
  cloudflareEmail: "provider.cloudflare.email",
  cloudflareApiKey: "provider.cloudflare.api_key",
  cloudflareDnsToken: "provider.cloudflare.dns_api_token",
  cloudflareZoneToken: "provider.cloudflare.zone_api_token",
  cloudflareEmailAlias: "provider.cloudflare.email_alias",
  cloudflareApiKeyAlias: "provider.cloudflare.api_key_alias",
  cloudflareDnsTokenAlias: "provider.cloudflare.dns_api_token_alias",
  cloudflareZoneTokenAlias: "provider.cloudflare.zone_api_token_alias",
  cloudflareBaseUrl: "provider.cloudflare.base_url",
  cloudflareTtl: "provider.cloudflare.ttl",
  cloudflarePropagationTimeout: "provider.cloudflare.propagation_timeout",
  cloudflarePollingInterval: "provider.cloudflare.polling_interval",
  cloudflareHttpTimeout: "provider.cloudflare.http_timeout",
  digitalOceanToken: "provider.digitalocean.auth_token",
  digitalOceanApiUrl: "provider.digitalocean.api_url",
  digitalOceanTtl: "provider.digitalocean.ttl",
  digitalOceanPropagationTimeout: "provider.digitalocean.propagation_timeout",
  digitalOceanPollingInterval: "provider.digitalocean.polling_interval",
  digitalOceanHttpTimeout: "provider.digitalocean.http_timeout",
  duckDnsToken: "provider.duckdns.token",
  duckDnsPropagationTimeout: "provider.duckdns.propagation_timeout",
  duckDnsPollingInterval: "provider.duckdns.polling_interval",
  duckDnsHttpTimeout: "provider.duckdns.http_timeout",
  duckDnsSequenceInterval: "provider.duckdns.sequence_interval",
  azureEnvironment: "provider.azuredns.environment",
  azureSubscriptionId: "provider.azuredns.subscription_id",
  azureResourceGroup: "provider.azuredns.resource_group",
  azureZoneName: "provider.azuredns.zone_name",
  azurePrivateZone: "provider.azuredns.private_zone",
  azureAuthMethod: "provider.azuredns.auth_method",
  azureTenantId: "provider.azuredns.tenant_id",
  azureClientId: "provider.azuredns.client_id",
  azureClientSecret: "provider.azuredns.client_secret",
  azureClientCertificatePath: "provider.azuredns.client_certificate_path",
  azureClientCertificatePassword:
    "provider.azuredns.client_certificate_password",
  azureFederatedTokenFile: "provider.azuredns.federated_token_file",
  azureMsiTimeout: "provider.azuredns.msi_timeout",
  azureOidcToken: "provider.azuredns.oidc_token",
  azureOidcTokenFile: "provider.azuredns.oidc_token_file",
  azureOidcRequestUrl: "provider.azuredns.oidc_request_url",
  azureOidcRequestToken: "provider.azuredns.oidc_request_token",
  azureServiceConnectionId: "provider.azuredns.service_connection_id",
  azureSystemAccessToken: "provider.azuredns.system_access_token",
  azureSystemOidcRequestUri: "provider.azuredns.system_oidc_request_uri",
  azureCliPath: "provider.azuredns.cli_path",
  azureCliConfigDirectory: "provider.azuredns.cli_config_directory",
  azureImdsEndpoint: "provider.azuredns.imds_endpoint",
  azureIdentityEndpoint: "provider.azuredns.identity_endpoint",
  azureTtl: "provider.azuredns.ttl",
  azurePropagationTimeout: "provider.azuredns.propagation_timeout",
  azurePollingInterval: "provider.azuredns.polling_interval",
  awsAccessKeyId: "provider.route53.access_key_id",
  awsSecretAccessKey: "provider.route53.secret_access_key",
  awsSessionToken: "provider.route53.session_token",
  awsRegion: "provider.route53.region",
  awsHostedZoneId: "provider.route53.hosted_zone_id",
  awsProfile: "provider.route53.profile",
  awsSharedCredentialsFile: "provider.route53.shared_credentials_file",
  awsSdkLoadConfig: "provider.route53.sdk_load_config",
  awsEc2MetadataDisabled: "provider.route53.ec2_metadata_disabled",
  awsAssumeRoleArn: "provider.route53.assume_role_arn",
  awsExternalId: "provider.route53.external_id",
  awsPrivateZone: "provider.route53.private_zone",
  awsMaxRetries: "provider.route53.max_retries",
  awsWaitForChanges: "provider.route53.wait_for_record_sets_changed",
  awsTtl: "provider.route53.ttl",
  awsPropagationTimeout: "provider.route53.propagation_timeout",
  awsPollingInterval: "provider.route53.polling_interval",
} as const;

export type CAOption = {
  value: string;
  label: string;
  environment: "production" | "staging";
  eab: "none" | "optional" | "required";
  prerequisite: string;
  aliases: readonly string[];
};

export const caOptions: readonly CAOption[] = [
  {
    value: "letsencrypt",
    label: "Let's Encrypt production",
    environment: "production",
    eab: "none",
    prerequisite: "Public issuance limits apply.",
    aliases: ["letsencrypt", "https://acme-v02.api.letsencrypt.org/directory"],
  },
  {
    value: "letsencrypt-staging",
    label: "Let's Encrypt staging",
    environment: "staging",
    eab: "none",
    prerequisite: "Certificates are not publicly trusted.",
    aliases: [
      "letsencrypt-staging",
      "https://acme-staging-v02.api.letsencrypt.org/directory",
    ],
  },
  {
    value: "zerossl",
    label: "ZeroSSL production",
    environment: "production",
    eab: "optional",
    prerequisite: "Use account email assistance or explicit EAB credentials.",
    aliases: ["zerossl", "https://acme.zerossl.com/v2/DV90"],
  },
  {
    value: "googletrust",
    label: "Google Trust Services production",
    environment: "production",
    eab: "required",
    prerequisite: "Google Trust Services EAB credentials are required.",
    aliases: ["googletrust", "https://dv.acme-v02.api.pki.goog/directory"],
  },
  {
    value: "googletrust-staging",
    label: "Google Trust Services staging",
    environment: "staging",
    eab: "required",
    prerequisite:
      "Staging EAB credentials are separate from production credentials.",
    aliases: [
      "googletrust-staging",
      "https://dv.acme-v02.test-api.pki.goog/directory",
    ],
  },
  {
    value: "sslcomrsa",
    label: "SSL.com RSA production",
    environment: "production",
    eab: "required",
    prerequisite: "SSL.com RSA EAB credentials are required.",
    aliases: ["sslcomrsa", "https://acme.ssl.com/sslcom-dv-rsa"],
  },
  {
    value: "sslcomecc",
    label: "SSL.com ECDSA production",
    environment: "production",
    eab: "required",
    prerequisite: "SSL.com ECDSA EAB credentials are required.",
    aliases: ["sslcomecc", "https://acme.ssl.com/sslcom-dv-ecc"],
  },
  {
    value: "https://acme.godaddy.com/v1/acme/directory",
    label: "GoDaddy CA production",
    environment: "production",
    eab: "required",
    prerequisite:
      "An entitled GoDaddy ACME account and account-issued EAB are required.",
    aliases: ["https://acme.godaddy.com/v1/acme/directory"],
  },
] as const;

export const keyTypeOptions = [
  "EC256",
  "EC384",
  "RSA2048",
  "RSA4096",
  "RSA8192",
] as const;

export type SupportedKeyType = (typeof keyTypeOptions)[number];

export type AccountDraft = {
  name: string;
  isNew: boolean;
  originalServer: string | null;
  originalAcceptsTerms: boolean;
  server: string;
  email: string;
  keyType: SupportedKeyType | "";
  acceptsTerms: boolean;
  eabKid: string;
  eabHmac: SecretDraft;
  eabPresent: boolean;
};

export type DNSProvider =
  "azuredns" | "cloudflare" | "digitalocean" | "duckdns" | "route53";
export type CloudAuthMode =
  | "azure_client_secret"
  | "azure_client_certificate"
  | "azure_workload"
  | "azure_managed"
  | "azure_cli"
  | "azure_oidc_inline"
  | "azure_oidc_file"
  | "azure_oidc_request"
  | "azure_pipeline"
  | "aws_static"
  | "aws_shared_profile"
  | "aws_instance_role";

export type ChallengeDraft = {
  name: string;
  isNew: boolean;
  predefined: boolean;
  kind: "http" | "dns";
  mode: "listener" | "webroot";
  address: string;
  delay: string;
  proxyHeader: string;
  webroot: string;
  provider: DNSProvider;
  originalProvider: DNSProvider;
  envFile: string;
  dnsTimeout: number;
  resolvers: string[];
  disableAuthoritative: boolean;
  disableRecursive: boolean;
  propagationWait: string;
  cloudflareAuthMode: "token" | "legacy";
  originalCloudflareAuthMode: "token" | "legacy";
  cloudflareEmail: string;
  originalCloudflareEmail: string;
  cloudflareApiKey: SecretDraft;
  cloudflareApiKeyPresent: boolean;
  cloudflareDnsToken: SecretDraft;
  cloudflareDnsTokenPresent: boolean;
  cloudflareZoneToken: SecretDraft;
  cloudflareZoneTokenPresent: boolean;
  digitalOceanToken: SecretDraft;
  digitalOceanTokenPresent: boolean;
  duckDnsToken: SecretDraft;
  duckDnsTokenPresent: boolean;
  providerSettings: Record<string, string>;
  cloudAuthMode: CloudAuthMode;
  originalCloudAuthMode: CloudAuthMode;
  cloudSecrets: Record<string, SecretDraft>;
  cloudSecretPresence: Record<string, boolean>;
};

export type CertificateDraft = {
  name: string;
  isNew: boolean;
  domains: string[];
  account: string;
  challenge: string;
  challengeUnsupported: boolean;
  keyType: SupportedKeyType | "";
  renewDays: number;
  reuseKey: boolean;
  disableRandomSleep: boolean;
  disableARI: boolean;
  ariWait: string;
};

export type NativeConfigurationDraft = {
  creation: boolean;
  storage: string;
  accounts: AccountDraft[];
  challenges: ChallengeDraft[];
  certificates: CertificateDraft[];
  unsupportedFields: UnsupportedDraftField[];
};

export type UnsupportedDraftField = {
  fieldId: string;
  bindings: ConfigurationBinding[];
  kind: ProjectedField["kind"];
  label: string;
};

export type DraftIssue = {
  fieldId: string;
  message: string;
};

export const maximumConfigurationChanges = 128;

export function validateChangeBudget(
  changes: ConfigurationChange[],
): DraftIssue[] {
  if (changes.length <= maximumConfigurationChanges) return [];
  return [
    {
      fieldId: "managed-configuration-heading",
      message: `This draft prepares ${changes.length.toLocaleString("en-US")} native field changes; one reviewed request can contain at most ${maximumConfigurationChanges.toLocaleString("en-US")}. Reduce this draft before preview.`,
    },
  ];
}

function bindingsFor(
  kind: "account" | "certificate" | "challenge",
  name: string,
) {
  return [{ id: kind, value: name }];
}

function fieldIdentity(
  fieldId: string,
  bindings: ConfigurationBinding[],
): string {
  return JSON.stringify([
    fieldId,
    bindings.map(({ id, value }) => [id, value]),
  ]);
}

export function acknowledgeUnsupportedField(
  draft: NativeConfigurationDraft,
  fieldId: string,
  bindings: ConfigurationBinding[],
): NativeConfigurationDraft {
  const identity = fieldIdentity(fieldId, bindings);
  return {
    ...draft,
    unsupportedFields: draft.unsupportedFields.filter(
      (field) => fieldIdentity(field.fieldId, field.bindings) !== identity,
    ),
  };
}

export function fieldNeedsExplicitRepair(
  draft: NativeConfigurationDraft,
  fieldId: string,
  bindings: ConfigurationBinding[],
): boolean {
  const identity = fieldIdentity(fieldId, bindings);
  return draft.unsupportedFields.some(
    (field) => fieldIdentity(field.fieldId, field.bindings) === identity,
  );
}

function bindingValue(field: ProjectedField, id: string): string | undefined {
  return field.bindings.find((binding) => binding.id === id)?.value;
}

function identityMatches(
  field: ProjectedField,
  fieldId: string,
  bindings: ConfigurationBinding[],
): boolean {
  return (
    field.fieldId === fieldId &&
    JSON.stringify(field.bindings) === JSON.stringify(bindings)
  );
}

function fieldFor(
  projection: ProjectedField[],
  fieldId: string,
  bindings: ConfigurationBinding[],
): ProjectedField | undefined {
  return projection.find((field) => identityMatches(field, fieldId, bindings));
}

function publicValue(
  projection: ProjectedField[],
  fieldId: string,
  bindings: ConfigurationBinding[],
): ConfigurationValue | undefined {
  const field = fieldFor(projection, fieldId, bindings);
  if (!field || !field.configured || field.kind === "secret") return undefined;
  return field.value;
}

function stringValue(
  projection: ProjectedField[],
  fieldId: string,
  bindings: ConfigurationBinding[],
  fallback: string,
): string {
  const value = publicValue(projection, fieldId, bindings);
  return typeof value === "string" ? value : fallback;
}

function booleanValue(
  projection: ProjectedField[],
  fieldId: string,
  bindings: ConfigurationBinding[],
  fallback = false,
): boolean {
  const value = publicValue(projection, fieldId, bindings);
  return typeof value === "boolean" ? value : fallback;
}

function integerValue(
  projection: ProjectedField[],
  fieldId: string,
  bindings: ConfigurationBinding[],
  fallback = 0,
): number {
  const value = publicValue(projection, fieldId, bindings);
  return typeof value === "number" ? value : fallback;
}

function listValue(
  projection: ProjectedField[],
  fieldId: string,
  bindings: ConfigurationBinding[],
): string[] {
  const value = publicValue(projection, fieldId, bindings);
  return Array.isArray(value) ? [...value] : [];
}

export function resolveCA(value: string): CAOption | undefined {
  return caOptions.find((option) => option.aliases.includes(value));
}

function uniqueNames(
  projection: ProjectedField[],
  binding: "account" | "certificate" | "challenge",
): string[] {
  const names = projection
    .map((field) => bindingValue(field, binding))
    .filter((value): value is string => value !== undefined);
  if (binding === "account") {
    for (const field of projection) {
      if (field.fieldId !== managedFieldIds.certificateAccount) continue;
      const value =
        field.configured && field.kind === "string" ? field.value : undefined;
      if (value) names.push(value);
    }
  }
  if (binding === "challenge") {
    for (const field of projection) {
      if (field.fieldId !== managedFieldIds.certificateChallenge) continue;
      const value =
        field.configured && field.kind === "string" ? field.value : undefined;
      if (value && names.includes(value)) {
        names.push(value);
      }
    }
  }
  return [...new Set(names)].sort((left, right) => left.localeCompare(right));
}

function acceptedKeyType(value: string): SupportedKeyType | "" {
  return keyTypeOptions.includes(value as SupportedKeyType)
    ? (value as SupportedKeyType)
    : "";
}

function secretPresent(
  projection: ProjectedField[],
  fieldIds: readonly string[],
  bindings: ConfigurationBinding[],
): boolean {
  return fieldIds.some((fieldId) => {
    const field = fieldFor(projection, fieldId, bindings);
    return Boolean(field?.presenceKnown && field.present);
  });
}

export function newHTTPChallenge(name: string): ChallengeDraft {
  return {
    name,
    isNew: true,
    predefined: false,
    kind: "http",
    mode: "listener",
    address: ":8080",
    delay: "0s",
    proxyHeader: "Host",
    webroot: "",
    ...emptyDNSDraft(),
  };
}

export function newDNSChallenge(name: string): ChallengeDraft {
  return {
    name,
    isNew: true,
    predefined: false,
    kind: "dns",
    mode: "listener",
    address: ":8080",
    delay: "0s",
    proxyHeader: "Host",
    webroot: "",
    ...emptyDNSDraft(),
  };
}

function emptyDNSDraft() {
  return {
    provider: "cloudflare" as DNSProvider,
    originalProvider: "cloudflare" as DNSProvider,
    envFile: ".cloudflare.env",
    dnsTimeout: 30,
    resolvers: [] as string[],
    disableAuthoritative: false,
    disableRecursive: false,
    propagationWait: "0s",
    cloudflareAuthMode: "token" as const,
    originalCloudflareAuthMode: "token" as const,
    cloudflareEmail: "",
    originalCloudflareEmail: "",
    cloudflareApiKey: { action: "keep" } as SecretDraft,
    cloudflareApiKeyPresent: false,
    cloudflareDnsToken: { action: "keep" } as SecretDraft,
    cloudflareDnsTokenPresent: false,
    cloudflareZoneToken: { action: "keep" } as SecretDraft,
    cloudflareZoneTokenPresent: false,
    digitalOceanToken: { action: "keep" } as SecretDraft,
    digitalOceanTokenPresent: false,
    duckDnsToken: { action: "keep" } as SecretDraft,
    duckDnsTokenPresent: false,
    providerSettings: {} as Record<string, string>,
    cloudAuthMode: "azure_client_secret" as CloudAuthMode,
    originalCloudAuthMode: "azure_client_secret" as CloudAuthMode,
    cloudSecrets: {} as Record<string, SecretDraft>,
    cloudSecretPresence: {} as Record<string, boolean>,
  };
}

const providerSettingFieldIds = [
  managedFieldIds.cloudflareBaseUrl,
  managedFieldIds.cloudflareTtl,
  managedFieldIds.cloudflarePropagationTimeout,
  managedFieldIds.cloudflarePollingInterval,
  managedFieldIds.cloudflareHttpTimeout,
  managedFieldIds.digitalOceanApiUrl,
  managedFieldIds.digitalOceanTtl,
  managedFieldIds.digitalOceanPropagationTimeout,
  managedFieldIds.digitalOceanPollingInterval,
  managedFieldIds.digitalOceanHttpTimeout,
  managedFieldIds.duckDnsPropagationTimeout,
  managedFieldIds.duckDnsPollingInterval,
  managedFieldIds.duckDnsHttpTimeout,
  managedFieldIds.duckDnsSequenceInterval,
  managedFieldIds.azureEnvironment,
  managedFieldIds.azureSubscriptionId,
  managedFieldIds.azureResourceGroup,
  managedFieldIds.azureZoneName,
  managedFieldIds.azurePrivateZone,
  managedFieldIds.azureAuthMethod,
  managedFieldIds.azureTenantId,
  managedFieldIds.azureClientId,
  managedFieldIds.azureClientCertificatePath,
  managedFieldIds.azureFederatedTokenFile,
  managedFieldIds.azureMsiTimeout,
  managedFieldIds.azureOidcTokenFile,
  managedFieldIds.azureOidcRequestUrl,
  managedFieldIds.azureServiceConnectionId,
  managedFieldIds.azureSystemOidcRequestUri,
  managedFieldIds.azureCliPath,
  managedFieldIds.azureCliConfigDirectory,
  managedFieldIds.azureImdsEndpoint,
  managedFieldIds.azureIdentityEndpoint,
  managedFieldIds.azureTtl,
  managedFieldIds.azurePropagationTimeout,
  managedFieldIds.azurePollingInterval,
  managedFieldIds.awsRegion,
  managedFieldIds.awsHostedZoneId,
  managedFieldIds.awsProfile,
  managedFieldIds.awsSharedCredentialsFile,
  managedFieldIds.awsSdkLoadConfig,
  managedFieldIds.awsEc2MetadataDisabled,
  managedFieldIds.awsAssumeRoleArn,
  managedFieldIds.awsPrivateZone,
  managedFieldIds.awsMaxRetries,
  managedFieldIds.awsWaitForChanges,
  managedFieldIds.awsTtl,
  managedFieldIds.awsPropagationTimeout,
  managedFieldIds.awsPollingInterval,
] as const;

export const cloudSecretFieldIds = [
  managedFieldIds.azureClientSecret,
  managedFieldIds.azureClientCertificatePassword,
  managedFieldIds.azureOidcToken,
  managedFieldIds.azureOidcRequestToken,
  managedFieldIds.azureSystemAccessToken,
  managedFieldIds.awsAccessKeyId,
  managedFieldIds.awsSecretAccessKey,
  managedFieldIds.awsSessionToken,
  managedFieldIds.awsExternalId,
] as const;

const cloudAlwaysPublicFields: Record<
  "azuredns" | "route53",
  readonly string[]
> = {
  azuredns: [
    managedFieldIds.azureEnvironment,
    managedFieldIds.azureSubscriptionId,
    managedFieldIds.azureResourceGroup,
    managedFieldIds.azureZoneName,
    managedFieldIds.azurePrivateZone,
    managedFieldIds.azureTtl,
    managedFieldIds.azurePropagationTimeout,
    managedFieldIds.azurePollingInterval,
  ],
  route53: [
    managedFieldIds.awsRegion,
    managedFieldIds.awsHostedZoneId,
    managedFieldIds.awsSdkLoadConfig,
    managedFieldIds.awsEc2MetadataDisabled,
    managedFieldIds.awsAssumeRoleArn,
    managedFieldIds.awsPrivateZone,
    managedFieldIds.awsMaxRetries,
    managedFieldIds.awsWaitForChanges,
    managedFieldIds.awsTtl,
    managedFieldIds.awsPropagationTimeout,
    managedFieldIds.awsPollingInterval,
  ],
};

const cloudModePublicFields: Record<CloudAuthMode, readonly string[]> = {
  azure_client_secret: [
    managedFieldIds.azureAuthMethod,
    managedFieldIds.azureTenantId,
    managedFieldIds.azureClientId,
  ],
  azure_client_certificate: [
    managedFieldIds.azureAuthMethod,
    managedFieldIds.azureTenantId,
    managedFieldIds.azureClientId,
    managedFieldIds.azureClientCertificatePath,
  ],
  azure_workload: [
    managedFieldIds.azureAuthMethod,
    managedFieldIds.azureTenantId,
    managedFieldIds.azureClientId,
    managedFieldIds.azureFederatedTokenFile,
  ],
  azure_managed: [
    managedFieldIds.azureAuthMethod,
    managedFieldIds.azureClientId,
    managedFieldIds.azureMsiTimeout,
    managedFieldIds.azureImdsEndpoint,
    managedFieldIds.azureIdentityEndpoint,
  ],
  azure_cli: [
    managedFieldIds.azureAuthMethod,
    managedFieldIds.azureTenantId,
    managedFieldIds.azureCliPath,
    managedFieldIds.azureCliConfigDirectory,
  ],
  azure_oidc_inline: [
    managedFieldIds.azureAuthMethod,
    managedFieldIds.azureTenantId,
    managedFieldIds.azureClientId,
  ],
  azure_oidc_file: [
    managedFieldIds.azureAuthMethod,
    managedFieldIds.azureTenantId,
    managedFieldIds.azureClientId,
    managedFieldIds.azureOidcTokenFile,
  ],
  azure_oidc_request: [
    managedFieldIds.azureAuthMethod,
    managedFieldIds.azureTenantId,
    managedFieldIds.azureClientId,
    managedFieldIds.azureOidcRequestUrl,
  ],
  azure_pipeline: [
    managedFieldIds.azureAuthMethod,
    managedFieldIds.azureTenantId,
    managedFieldIds.azureClientId,
    managedFieldIds.azureServiceConnectionId,
    managedFieldIds.azureSystemOidcRequestUri,
  ],
  aws_static: [],
  aws_shared_profile: [
    managedFieldIds.awsProfile,
    managedFieldIds.awsSharedCredentialsFile,
  ],
  aws_instance_role: [],
};

const cloudModeSecretFields: Record<CloudAuthMode, readonly string[]> = {
  azure_client_secret: [managedFieldIds.azureClientSecret],
  azure_client_certificate: [managedFieldIds.azureClientCertificatePassword],
  azure_workload: [],
  azure_managed: [],
  azure_cli: [],
  azure_oidc_inline: [managedFieldIds.azureOidcToken],
  azure_oidc_file: [],
  azure_oidc_request: [managedFieldIds.azureOidcRequestToken],
  azure_pipeline: [managedFieldIds.azureSystemAccessToken],
  aws_static: [
    managedFieldIds.awsAccessKeyId,
    managedFieldIds.awsSecretAccessKey,
    managedFieldIds.awsSessionToken,
    managedFieldIds.awsExternalId,
  ],
  aws_shared_profile: [managedFieldIds.awsExternalId],
  aws_instance_role: [managedFieldIds.awsExternalId],
};

const cloudRequiredPublicFields: Record<CloudAuthMode, readonly string[]> = {
  azure_client_secret: [
    managedFieldIds.azureTenantId,
    managedFieldIds.azureClientId,
  ],
  azure_client_certificate: [
    managedFieldIds.azureTenantId,
    managedFieldIds.azureClientId,
    managedFieldIds.azureClientCertificatePath,
  ],
  azure_workload: [
    managedFieldIds.azureTenantId,
    managedFieldIds.azureClientId,
    managedFieldIds.azureFederatedTokenFile,
  ],
  azure_managed: [],
  azure_cli: [
    managedFieldIds.azureCliPath,
    managedFieldIds.azureCliConfigDirectory,
  ],
  azure_oidc_inline: [
    managedFieldIds.azureTenantId,
    managedFieldIds.azureClientId,
  ],
  azure_oidc_file: [
    managedFieldIds.azureTenantId,
    managedFieldIds.azureClientId,
    managedFieldIds.azureOidcTokenFile,
  ],
  azure_oidc_request: [
    managedFieldIds.azureTenantId,
    managedFieldIds.azureClientId,
    managedFieldIds.azureOidcRequestUrl,
  ],
  azure_pipeline: [
    managedFieldIds.azureTenantId,
    managedFieldIds.azureClientId,
    managedFieldIds.azureServiceConnectionId,
    managedFieldIds.azureSystemOidcRequestUri,
  ],
  aws_static: [],
  aws_shared_profile: [
    managedFieldIds.awsProfile,
    managedFieldIds.awsSharedCredentialsFile,
  ],
  aws_instance_role: [],
};

const cloudRequiredSecretFields: Partial<
  Record<CloudAuthMode, readonly string[]>
> = {
  azure_client_secret: [managedFieldIds.azureClientSecret],
  azure_oidc_inline: [managedFieldIds.azureOidcToken],
  azure_oidc_request: [managedFieldIds.azureOidcRequestToken],
  azure_pipeline: [managedFieldIds.azureSystemAccessToken],
  aws_static: [
    managedFieldIds.awsAccessKeyId,
    managedFieldIds.awsSecretAccessKey,
  ],
};

function providerSettingsFromProjection(
  projection: ProjectedField[],
  bindings: ConfigurationBinding[],
): Record<string, string> {
  return Object.fromEntries(
    providerSettingFieldIds.map((fieldId) => [
      fieldId,
      stringValue(projection, fieldId, bindings, ""),
    ]),
  );
}

export function initialConfigurationDraft(
  projection: ProjectedField[],
  creation = false,
): NativeConfigurationDraft {
  if (creation) {
    return {
      creation: true,
      storage: ".lego",
      accounts: [
        {
          name: "primary",
          isNew: true,
          originalServer: null,
          originalAcceptsTerms: false,
          server: "letsencrypt",
          email: "",
          keyType: "EC256",
          acceptsTerms: false,
          eabKid: "",
          eabHmac: { action: "keep" },
          eabPresent: false,
        },
      ],
      challenges: [{ ...newHTTPChallenge("http-home"), address: ":80" }],
      certificates: [
        {
          name: "home",
          isNew: true,
          domains: [],
          account: "primary",
          challenge: "http-home",
          challengeUnsupported: false,
          keyType: "EC256",
          renewDays: 0,
          reuseKey: false,
          disableRandomSleep: false,
          disableARI: false,
          ariWait: "0s",
        },
      ],
      unsupportedFields: [],
    };
  }

  const managedIds = new Set<string>(Object.values(managedFieldIds));
  const unsupportedFields = projection
    .filter(
      (field) =>
        managedIds.has(field.fieldId) && field.present && !field.configured,
    )
    .map<UnsupportedDraftField>((field) => ({
      fieldId: field.fieldId,
      bindings: field.bindings.map((binding) => ({ ...binding })),
      kind: field.kind,
      label: field.label,
    }));

  const accountNames = uniqueNames(projection, "account");
  const challengeNames = uniqueNames(projection, "challenge");
  const certificateNames = uniqueNames(projection, "certificate");
  if (accountNames.length === 0 && certificateNames.length > 0) {
    accountNames.push("noemail@example.com");
  }
  const hasProjectedCertificateChallenge = projection.some(
    (field) =>
      field.fieldId === managedFieldIds.certificateChallenge &&
      field.configured &&
      field.kind === "string" &&
      field.value !== "",
  );
  if (
    challengeNames.length === 0 &&
    certificateNames.length > 0 &&
    !hasProjectedCertificateChallenge
  ) {
    challengeNames.push("http-01");
  }
  const accounts = accountNames.map<AccountDraft>((name) => {
    const bindings = bindingsFor("account", name);
    const serverField = fieldFor(
      projection,
      managedFieldIds.accountServer,
      bindings,
    );
    const keyTypeField = fieldFor(
      projection,
      managedFieldIds.accountKeyType,
      bindings,
    );
    const nativeServer = stringValue(
      projection,
      managedFieldIds.accountServer,
      bindings,
      "letsencrypt",
    );
    const resolvedServer = resolveCA(nativeServer);
    const unsupportedServer =
      (serverField?.present && !serverField.configured) ||
      (serverField?.configured === true && resolvedServer === undefined);
    const hmac = fieldFor(projection, managedFieldIds.accountEabHmac, bindings);
    const acceptsTerms = booleanValue(
      projection,
      managedFieldIds.accountTerms,
      bindings,
    );
    return {
      name,
      isNew: false,
      originalServer: unsupportedServer
        ? ""
        : (resolvedServer?.value ?? "letsencrypt"),
      server: unsupportedServer ? "" : (resolvedServer?.value ?? "letsencrypt"),
      originalAcceptsTerms: acceptsTerms,
      email: stringValue(
        projection,
        managedFieldIds.accountEmail,
        bindings,
        "",
      ),
      keyType:
        keyTypeField?.present && !keyTypeField.configured
          ? ""
          : acceptedKeyType(
              stringValue(
                projection,
                managedFieldIds.accountKeyType,
                bindings,
                "EC256",
              ),
            ),
      acceptsTerms,
      eabKid: stringValue(
        projection,
        managedFieldIds.accountEabKid,
        bindings,
        "",
      ),
      eabHmac: { action: "keep" },
      eabPresent: Boolean(hmac?.presenceKnown && hmac.present),
    };
  });
  const challenges = challengeNames.map<ChallengeDraft>((name) => {
    const bindings = bindingsFor("challenge", name);
    const nativeProvider = stringValue(
      projection,
      managedFieldIds.challengeDnsProvider,
      bindings,
      "",
    );
    const provider = (
      ["azuredns", "cloudflare", "digitalocean", "duckdns", "route53"] as const
    ).includes(nativeProvider as DNSProvider)
      ? (nativeProvider as DNSProvider)
      : "cloudflare";
    const webroot = stringValue(
      projection,
      managedFieldIds.challengeWebroot,
      bindings,
      "",
    );
    const predefined =
      name === "http-01" &&
      !projection.some(
        (field) => bindingValue(field, "challenge") === name && field.present,
      );
    const dnsDraft = emptyDNSDraft();
    const canonicalEmail = stringValue(
      projection,
      managedFieldIds.cloudflareEmail,
      bindings,
      "",
    );
    const aliasEmail = stringValue(
      projection,
      managedFieldIds.cloudflareEmailAlias,
      bindings,
      "",
    );
    const cloudflareEmail = canonicalEmail || aliasEmail;
    const cloudflareApiKeyPresent = secretPresent(
      projection,
      [managedFieldIds.cloudflareApiKey, managedFieldIds.cloudflareApiKeyAlias],
      bindings,
    );
    const cloudflareDnsTokenPresent = secretPresent(
      projection,
      [
        managedFieldIds.cloudflareDnsToken,
        managedFieldIds.cloudflareDnsTokenAlias,
      ],
      bindings,
    );
    const cloudflareZoneTokenPresent = secretPresent(
      projection,
      [
        managedFieldIds.cloudflareZoneToken,
        managedFieldIds.cloudflareZoneTokenAlias,
      ],
      bindings,
    );
    const cloudflareAuthMode =
      cloudflareEmail || cloudflareApiKeyPresent ? "legacy" : "token";
    let cloudAuthMode: CloudAuthMode = "azure_client_secret";
    const azureMethod = stringValue(
      projection,
      managedFieldIds.azureAuthMethod,
      bindings,
      "env",
    );
    if (provider === "azuredns") {
      if (azureMethod === "wli") cloudAuthMode = "azure_workload";
      else if (azureMethod === "msi") cloudAuthMode = "azure_managed";
      else if (azureMethod === "cli") cloudAuthMode = "azure_cli";
      else if (azureMethod === "pipeline") cloudAuthMode = "azure_pipeline";
      else if (azureMethod === "oidc") {
        cloudAuthMode = stringValue(
          projection,
          managedFieldIds.azureOidcTokenFile,
          bindings,
          "",
        )
          ? "azure_oidc_file"
          : stringValue(
                projection,
                managedFieldIds.azureOidcRequestUrl,
                bindings,
                "",
              )
            ? "azure_oidc_request"
            : "azure_oidc_inline";
      } else if (
        stringValue(
          projection,
          managedFieldIds.azureClientCertificatePath,
          bindings,
          "",
        )
      ) {
        cloudAuthMode = "azure_client_certificate";
      }
    } else if (provider === "route53") {
      cloudAuthMode = stringValue(
        projection,
        managedFieldIds.awsProfile,
        bindings,
        "",
      )
        ? "aws_shared_profile"
        : secretPresent(projection, [managedFieldIds.awsAccessKeyId], bindings)
          ? "aws_static"
          : "aws_instance_role";
    }
    return {
      name,
      isNew: false,
      predefined,
      kind: nativeProvider ? "dns" : "http",
      mode: webroot ? "webroot" : "listener",
      address: stringValue(
        projection,
        managedFieldIds.challengeAddress,
        bindings,
        ":80",
      ),
      delay: stringValue(
        projection,
        managedFieldIds.challengeDelay,
        bindings,
        "0s",
      ),
      proxyHeader: stringValue(
        projection,
        managedFieldIds.challengeProxyHeader,
        bindings,
        "Host",
      ),
      webroot,
      ...dnsDraft,
      provider,
      originalProvider: provider,
      envFile: stringValue(
        projection,
        managedFieldIds.challengeDnsEnvFile,
        bindings,
        `.${provider}.env`,
      ),
      dnsTimeout: integerValue(
        projection,
        managedFieldIds.challengeDnsTimeout,
        bindings,
        30,
      ),
      resolvers: listValue(
        projection,
        managedFieldIds.challengeDnsResolvers,
        bindings,
      ),
      disableAuthoritative: booleanValue(
        projection,
        managedFieldIds.challengeDnsDisableAuthoritative,
        bindings,
      ),
      disableRecursive: booleanValue(
        projection,
        managedFieldIds.challengeDnsDisableRecursive,
        bindings,
      ),
      propagationWait: stringValue(
        projection,
        managedFieldIds.challengeDnsPropagationWait,
        bindings,
        "0s",
      ),
      cloudflareAuthMode,
      originalCloudflareAuthMode: cloudflareAuthMode,
      cloudflareEmail,
      originalCloudflareEmail: cloudflareEmail,
      cloudflareApiKeyPresent,
      cloudflareDnsTokenPresent,
      cloudflareZoneTokenPresent,
      digitalOceanTokenPresent: secretPresent(
        projection,
        [managedFieldIds.digitalOceanToken],
        bindings,
      ),
      duckDnsTokenPresent: secretPresent(
        projection,
        [managedFieldIds.duckDnsToken],
        bindings,
      ),
      providerSettings: providerSettingsFromProjection(projection, bindings),
      cloudAuthMode,
      originalCloudAuthMode: cloudAuthMode,
      cloudSecrets: Object.fromEntries(
        cloudSecretFieldIds.map((fieldId) => [
          fieldId,
          { action: "keep" } as SecretDraft,
        ]),
      ),
      cloudSecretPresence: Object.fromEntries(
        cloudSecretFieldIds.map((fieldId) => [
          fieldId,
          secretPresent(projection, [fieldId], bindings),
        ]),
      ),
    };
  });
  const certificates = certificateNames.map<CertificateDraft>((name) => {
    const bindings = bindingsFor("certificate", name);
    const keyTypeField = fieldFor(
      projection,
      managedFieldIds.certificateKeyType,
      bindings,
    );
    const defaultAccount = accounts.length === 1 ? accounts[0]!.name : "";
    const defaultChallenge = challenges.length === 1 ? challenges[0]!.name : "";
    const accountField = fieldFor(
      projection,
      managedFieldIds.certificateAccount,
      bindings,
    );
    const challengeField = fieldFor(
      projection,
      managedFieldIds.certificateChallenge,
      bindings,
    );
    const account = stringValue(
      projection,
      managedFieldIds.certificateAccount,
      bindings,
      defaultAccount,
    );
    const challenge = stringValue(
      projection,
      managedFieldIds.certificateChallenge,
      bindings,
      defaultChallenge,
    );
    const inheritedKey =
      accounts.find((item) => item.name === account)?.keyType ?? "EC256";
    return {
      name,
      isNew: false,
      domains: listValue(
        projection,
        managedFieldIds.certificateDomains,
        bindings,
      ),
      account: accountField?.present && !accountField.configured ? "" : account,
      challenge:
        challengeField?.present && !challengeField.configured ? "" : challenge,
      challengeUnsupported:
        challenge !== "" && !challenges.some((item) => item.name === challenge),
      keyType:
        keyTypeField?.present && !keyTypeField.configured
          ? ""
          : acceptedKeyType(
              stringValue(
                projection,
                managedFieldIds.certificateKeyType,
                bindings,
                inheritedKey || "EC256",
              ),
            ),
      renewDays: integerValue(
        projection,
        managedFieldIds.certificateRenewDays,
        bindings,
      ),
      reuseKey: booleanValue(
        projection,
        managedFieldIds.certificateRenewReuseKey,
        bindings,
      ),
      disableRandomSleep: booleanValue(
        projection,
        managedFieldIds.certificateRenewDisableRandomSleep,
        bindings,
      ),
      disableARI: booleanValue(
        projection,
        managedFieldIds.certificateRenewAriDisable,
        bindings,
      ),
      ariWait: stringValue(
        projection,
        managedFieldIds.certificateRenewAriWait,
        bindings,
        "0s",
      ),
    };
  });
  return {
    creation: false,
    storage: stringValue(projection, managedFieldIds.storage, [], ".lego"),
    accounts,
    challenges,
    certificates,
    unsupportedFields,
  };
}

export function unsupportedFieldControlId(
  draft: NativeConfigurationDraft,
  field: UnsupportedDraftField,
): string {
  if (field.fieldId === managedFieldIds.storage) {
    return "configuration-storage";
  }
  const accountName = field.bindings.find(
    (binding) => binding.id === "account",
  )?.value;
  if (accountName !== undefined) {
    const index = draft.accounts.findIndex(
      (account) => account.name === accountName,
    );
    const suffix: Partial<Record<string, string>> = {
      [managedFieldIds.accountServer]: "server",
      [managedFieldIds.accountEmail]: "email",
      [managedFieldIds.accountKeyType]: "key-type",
      [managedFieldIds.accountTerms]: "terms",
      [managedFieldIds.accountEabKid]: "eab-kid",
      [managedFieldIds.accountEabHmac]: "eab-hmac",
    };
    if (index >= 0 && suffix[field.fieldId]) {
      return `account-${index}-${suffix[field.fieldId]}`;
    }
  }
  const challengeName = field.bindings.find(
    (binding) => binding.id === "challenge",
  )?.value;
  if (challengeName !== undefined) {
    const index = draft.challenges.findIndex(
      (challenge) => challenge.name === challengeName,
    );
    const suffix: Partial<Record<string, string>> = {
      [managedFieldIds.challengeAddress]: "address",
      [managedFieldIds.challengeDelay]: "delay",
      [managedFieldIds.challengeProxyHeader]: "proxy-header",
      [managedFieldIds.challengeWebroot]: "webroot",
    };
    if (index >= 0 && suffix[field.fieldId]) {
      return `challenge-${index}-${suffix[field.fieldId]}`;
    }
  }
  const certificateName = field.bindings.find(
    (binding) => binding.id === "certificate",
  )?.value;
  if (certificateName !== undefined) {
    const index = draft.certificates.findIndex(
      (certificate) => certificate.name === certificateName,
    );
    const suffix: Partial<Record<string, string>> = {
      [managedFieldIds.certificateDomains]: "domains",
      [managedFieldIds.certificateAccount]: "account",
      [managedFieldIds.certificateChallenge]: "challenge",
      [managedFieldIds.certificateKeyType]: "key-type",
      [managedFieldIds.certificateRenewDays]: "renew-days",
      [managedFieldIds.certificateRenewReuseKey]: "renew-reuse-key",
      [managedFieldIds.certificateRenewDisableRandomSleep]:
        "renew-disable-random-sleep",
      [managedFieldIds.certificateRenewAriDisable]: "renew-disable-ari",
      [managedFieldIds.certificateRenewAriWait]: "ari-wait",
    };
    if (index >= 0 && suffix[field.fieldId]) {
      return `certificate-${index}-${suffix[field.fieldId]}`;
    }
  }
  return "managed-configuration-heading";
}

export function canAcknowledgeUnsupportedField(
  draft: NativeConfigurationDraft,
  field: UnsupportedDraftField,
): boolean {
  const accountName = field.bindings.find(
    (binding) => binding.id === "account",
  )?.value;
  const account = draft.accounts.find((item) => item.name === accountName);
  if (account) {
    if (field.fieldId === managedFieldIds.accountServer) {
      return resolveCA(account.server) !== undefined;
    }
    if (field.fieldId === managedFieldIds.accountKeyType) {
      return keyTypeOptions.includes(account.keyType as SupportedKeyType);
    }
    if (field.fieldId === managedFieldIds.accountEabHmac) {
      return account.eabHmac.action !== "keep";
    }
  }
  const certificateName = field.bindings.find(
    (binding) => binding.id === "certificate",
  )?.value;
  const certificate = draft.certificates.find(
    (item) => item.name === certificateName,
  );
  if (certificate) {
    if (field.fieldId === managedFieldIds.certificateDomains) {
      return certificate.domains.length > 0;
    }
    if (field.fieldId === managedFieldIds.certificateAccount) {
      return certificate.account !== "";
    }
    if (field.fieldId === managedFieldIds.certificateChallenge) {
      return certificate.challenge !== "";
    }
    if (field.fieldId === managedFieldIds.certificateKeyType) {
      return keyTypeOptions.includes(certificate.keyType as SupportedKeyType);
    }
  }
  return true;
}

function equalValue(left: ConfigurationValue, right: ConfigurationValue) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function emitValue(
  changes: ConfigurationChange[],
  projection: ProjectedField[],
  fieldId: string,
  bindings: ConfigurationBinding[],
  value: ConfigurationValue,
  implicit: ConfigurationValue | undefined,
  force: boolean,
) {
  const existing = fieldFor(projection, fieldId, bindings);
  const current =
    existing && existing.configured && existing.kind !== "secret"
      ? existing.value
      : undefined;
  if (
    current !== undefined &&
    equalValue(current, value) &&
    (!force || existing?.present === true)
  ) {
    return;
  }
  if (
    !force &&
    current === undefined &&
    existing?.present !== true &&
    implicit !== undefined &&
    equalValue(implicit, value)
  ) {
    return;
  }
  changes.push({ fieldId, bindings, operation: "set", value });
}

function emitOptional(
  changes: ConfigurationChange[],
  projection: ProjectedField[],
  fieldId: string,
  bindings: ConfigurationBinding[],
  value: ConfigurationValue,
  empty: ConfigurationValue,
) {
  const existing = fieldFor(projection, fieldId, bindings);
  const current =
    existing && existing.configured && existing.kind !== "secret"
      ? existing.value
      : undefined;
  if (current !== undefined && equalValue(current, value)) {
    return;
  }
  if (equalValue(value, empty)) {
    if (existing?.present) {
      changes.push({ fieldId, bindings, operation: "remove" });
    }
    return;
  }
  emitValue(changes, projection, fieldId, bindings, value, empty, false);
}

function emitOptionalOrRequired(
  changes: ConfigurationChange[],
  projection: ProjectedField[],
  fieldId: string,
  bindings: ConfigurationBinding[],
  value: ConfigurationValue,
  empty: ConfigurationValue,
  required: boolean,
) {
  if (required) {
    emitValue(changes, projection, fieldId, bindings, value, empty, true);
    return;
  }
  emitOptional(changes, projection, fieldId, bindings, value, empty);
}

function emitRemovalIfPresent(
  changes: ConfigurationChange[],
  projection: ProjectedField[],
  fieldId: string,
  bindings: ConfigurationBinding[],
) {
  if (fieldFor(projection, fieldId, bindings)?.present) {
    changes.push({ fieldId, bindings, operation: "remove" });
  }
}

function emitSecretDraft(
  changes: ConfigurationChange[],
  projection: ProjectedField[],
  primaryFieldId: string,
  aliasFieldIds: readonly string[],
  bindings: ConfigurationBinding[],
  draft: SecretDraft,
  present: boolean,
) {
  const all = [primaryFieldId, ...aliasFieldIds];
  if (draft.action === "replace") {
    changes.push({
      fieldId: primaryFieldId,
      bindings,
      operation: "set",
      value: draft.secret,
    });
    for (const fieldId of aliasFieldIds) {
      emitRemovalIfPresent(changes, projection, fieldId, bindings);
    }
  } else if (draft.action === "remove" && present) {
    for (const fieldId of all) {
      emitRemovalIfPresent(changes, projection, fieldId, bindings);
    }
  }
}

export function changesFromDraft(
  draft: NativeConfigurationDraft,
  projection: ProjectedField[],
  creation: boolean,
): ConfigurationChange[] {
  const changes: ConfigurationChange[] = [];
  emitValue(
    changes,
    projection,
    managedFieldIds.storage,
    [],
    draft.storage,
    ".lego",
    creation,
  );
  for (const account of draft.accounts) {
    const bindings = bindingsFor("account", account.name);
    const force = creation || account.isNew;
    const registrationTransition =
      account.isNew || account.server !== account.originalServer;
    const serverField = fieldFor(
      projection,
      managedFieldIds.accountServer,
      bindings,
    );
    const existingServer = publicValue(
      projection,
      managedFieldIds.accountServer,
      bindings,
    );
    const sameAcceptedServer =
      serverField?.present === true &&
      typeof existingServer === "string" &&
      resolveCA(existingServer)?.value === account.server;
    if (serverField?.present !== true) {
      changes.push({
        fieldId: managedFieldIds.accountServer,
        bindings,
        operation: "set",
        value: account.server,
      });
    } else if (!sameAcceptedServer) {
      emitValue(
        changes,
        projection,
        managedFieldIds.accountServer,
        bindings,
        account.server,
        "letsencrypt",
        force,
      );
    }
    emitOptional(
      changes,
      projection,
      managedFieldIds.accountEmail,
      bindings,
      account.email,
      "",
    );
    emitValue(
      changes,
      projection,
      managedFieldIds.accountKeyType,
      bindings,
      account.keyType,
      "EC256",
      force,
    );
    if (registrationTransition) {
      changes.push({
        fieldId: managedFieldIds.accountTerms,
        bindings,
        operation: "set",
        value: account.acceptsTerms,
      });
    } else {
      emitValue(
        changes,
        projection,
        managedFieldIds.accountTerms,
        bindings,
        account.acceptsTerms,
        false,
        force,
      );
    }
    if (registrationTransition && account.eabKid !== "") {
      changes.push({
        fieldId: managedFieldIds.accountEabKid,
        bindings,
        operation: "set",
        value: account.eabKid,
      });
    } else {
      emitOptional(
        changes,
        projection,
        managedFieldIds.accountEabKid,
        bindings,
        account.eabKid,
        "",
      );
    }
    if (account.eabHmac.action === "replace") {
      changes.push({
        fieldId: managedFieldIds.accountEabHmac,
        bindings,
        operation: "set",
        value: account.eabHmac.secret,
      });
    } else if (account.eabHmac.action === "remove" && account.eabPresent) {
      changes.push({
        fieldId: managedFieldIds.accountEabHmac,
        bindings,
        operation: "remove",
      });
    }
  }
  for (const challenge of draft.challenges) {
    const bindings = bindingsFor("challenge", challenge.name);
    const force = creation || challenge.isNew || challenge.predefined;
    if (challenge.kind === "dns") {
      emitValue(
        changes,
        projection,
        managedFieldIds.challengeDnsProvider,
        bindings,
        challenge.provider,
        undefined,
        force,
      );
      emitValue(
        changes,
        projection,
        managedFieldIds.challengeDnsEnvFile,
        bindings,
        challenge.envFile,
        undefined,
        force,
      );
      emitOptionalOrRequired(
        changes,
        projection,
        managedFieldIds.challengeDnsTimeout,
        bindings,
        challenge.dnsTimeout,
        0,
        force,
      );
      emitOptional(
        changes,
        projection,
        managedFieldIds.challengeDnsResolvers,
        bindings,
        challenge.resolvers,
        [],
      );
      emitOptionalOrRequired(
        changes,
        projection,
        managedFieldIds.challengeDnsDisableAuthoritative,
        bindings,
        challenge.disableAuthoritative,
        false,
        force,
      );
      emitOptionalOrRequired(
        changes,
        projection,
        managedFieldIds.challengeDnsDisableRecursive,
        bindings,
        challenge.disableRecursive,
        false,
        force,
      );
      emitOptionalOrRequired(
        changes,
        projection,
        managedFieldIds.challengeDnsPropagationWait,
        bindings,
        challenge.propagationWait,
        "0s",
        force,
      );
      for (const fieldId of providerSettingFieldIds) {
        if (!fieldId.includes(`provider.${challenge.provider}`)) continue;
        if (
          challenge.provider === "azuredns" ||
          challenge.provider === "route53"
        ) {
          const allowed = new Set([
            ...cloudAlwaysPublicFields[challenge.provider],
            ...cloudModePublicFields[challenge.cloudAuthMode],
          ]);
          if (!allowed.has(fieldId))
            emitRemovalIfPresent(changes, projection, fieldId, bindings);
          else
            emitOptional(
              changes,
              projection,
              fieldId,
              bindings,
              challenge.providerSettings[fieldId] ?? "",
              "",
            );
        } else {
          emitOptional(
            changes,
            projection,
            fieldId,
            bindings,
            challenge.providerSettings[fieldId] ?? "",
            "",
          );
        }
      }
      if (challenge.provider === "cloudflare") {
        if (
          challenge.cloudflareAuthMode !== challenge.originalCloudflareAuthMode
        ) {
          const obsolete =
            challenge.cloudflareAuthMode === "legacy"
              ? [
                  managedFieldIds.cloudflareDnsToken,
                  managedFieldIds.cloudflareDnsTokenAlias,
                  managedFieldIds.cloudflareZoneToken,
                  managedFieldIds.cloudflareZoneTokenAlias,
                ]
              : [
                  managedFieldIds.cloudflareEmail,
                  managedFieldIds.cloudflareEmailAlias,
                  managedFieldIds.cloudflareApiKey,
                  managedFieldIds.cloudflareApiKeyAlias,
                ];
          for (const fieldId of obsolete) {
            emitRemovalIfPresent(changes, projection, fieldId, bindings);
          }
        }
        if (
          challenge.cloudflareAuthMode === "legacy" &&
          (challenge.isNew ||
            challenge.cloudflareEmail !== challenge.originalCloudflareEmail ||
            challenge.cloudflareAuthMode !==
              challenge.originalCloudflareAuthMode)
        ) {
          emitOptional(
            changes,
            projection,
            managedFieldIds.cloudflareEmail,
            bindings,
            challenge.cloudflareEmail,
            "",
          );
          emitRemovalIfPresent(
            changes,
            projection,
            managedFieldIds.cloudflareEmailAlias,
            bindings,
          );
        }
        emitSecretDraft(
          changes,
          projection,
          managedFieldIds.cloudflareApiKey,
          [managedFieldIds.cloudflareApiKeyAlias],
          bindings,
          challenge.cloudflareApiKey,
          challenge.cloudflareApiKeyPresent,
        );
        emitSecretDraft(
          changes,
          projection,
          managedFieldIds.cloudflareDnsToken,
          [managedFieldIds.cloudflareDnsTokenAlias],
          bindings,
          challenge.cloudflareDnsToken,
          challenge.cloudflareDnsTokenPresent,
        );
        emitSecretDraft(
          changes,
          projection,
          managedFieldIds.cloudflareZoneToken,
          [managedFieldIds.cloudflareZoneTokenAlias],
          bindings,
          challenge.cloudflareZoneToken,
          challenge.cloudflareZoneTokenPresent,
        );
      } else if (challenge.provider === "digitalocean") {
        emitSecretDraft(
          changes,
          projection,
          managedFieldIds.digitalOceanToken,
          [],
          bindings,
          challenge.digitalOceanToken,
          challenge.digitalOceanTokenPresent,
        );
      } else if (challenge.provider === "duckdns") {
        emitSecretDraft(
          changes,
          projection,
          managedFieldIds.duckDnsToken,
          [],
          bindings,
          challenge.duckDnsToken,
          challenge.duckDnsTokenPresent,
        );
      } else {
        const allowed = new Set(cloudModeSecretFields[challenge.cloudAuthMode]);
        for (const fieldId of cloudSecretFieldIds) {
          if (!fieldId.includes(`provider.${challenge.provider}`)) continue;
          if (!allowed.has(fieldId))
            emitRemovalIfPresent(changes, projection, fieldId, bindings);
          else
            emitSecretDraft(
              changes,
              projection,
              fieldId,
              [],
              bindings,
              challenge.cloudSecrets[fieldId] ?? { action: "keep" },
              challenge.cloudSecretPresence[fieldId] ?? false,
            );
        }
      }
      continue;
    }
    emitOptionalOrRequired(
      changes,
      projection,
      managedFieldIds.challengeDelay,
      bindings,
      challenge.delay,
      "0s",
      force,
    );
    if (challenge.mode === "listener") {
      emitValue(
        changes,
        projection,
        managedFieldIds.challengeAddress,
        bindings,
        challenge.address,
        ":80",
        force ||
          fieldFor(projection, managedFieldIds.challengeAddress, bindings)
            ?.present !== true ||
          fieldFor(projection, managedFieldIds.challengeWebroot, bindings)
            ?.present === true,
      );
      emitOptional(
        changes,
        projection,
        managedFieldIds.challengeProxyHeader,
        bindings,
        challenge.proxyHeader,
        "Host",
      );
      emitRemovalIfPresent(
        changes,
        projection,
        managedFieldIds.challengeWebroot,
        bindings,
      );
    } else {
      emitValue(
        changes,
        projection,
        managedFieldIds.challengeWebroot,
        bindings,
        challenge.webroot,
        "",
        force,
      );
      emitRemovalIfPresent(
        changes,
        projection,
        managedFieldIds.challengeAddress,
        bindings,
      );
      emitRemovalIfPresent(
        changes,
        projection,
        managedFieldIds.challengeProxyHeader,
        bindings,
      );
    }
  }
  for (const certificate of draft.certificates) {
    const bindings = bindingsFor("certificate", certificate.name);
    const force = creation || certificate.isNew;
    emitValue(
      changes,
      projection,
      managedFieldIds.certificateDomains,
      bindings,
      certificate.domains,
      undefined,
      force,
    );
    if (
      fieldFor(projection, managedFieldIds.certificateAccount, bindings)
        ?.present !== true
    ) {
      changes.push({
        fieldId: managedFieldIds.certificateAccount,
        bindings,
        operation: "set",
        value: certificate.account,
      });
    } else {
      emitValue(
        changes,
        projection,
        managedFieldIds.certificateAccount,
        bindings,
        certificate.account,
        draft.accounts.length === 1 ? draft.accounts[0]!.name : undefined,
        force,
      );
    }
    const challengeField = fieldFor(
      projection,
      managedFieldIds.certificateChallenge,
      bindings,
    );
    if (certificate.challengeUnsupported) {
      emitValue(
        changes,
        projection,
        managedFieldIds.certificateChallenge,
        bindings,
        certificate.challenge,
        certificate.challenge,
        false,
      );
    } else if (challengeField?.present !== true) {
      changes.push({
        fieldId: managedFieldIds.certificateChallenge,
        bindings,
        operation: "set",
        value: certificate.challenge,
      });
    } else {
      emitValue(
        changes,
        projection,
        managedFieldIds.certificateChallenge,
        bindings,
        certificate.challenge,
        draft.challenges.length === 1 ? draft.challenges[0]!.name : undefined,
        force,
      );
    }
    const inheritedKey =
      draft.accounts.find((account) => account.name === certificate.account)
        ?.keyType ?? "EC256";
    emitValue(
      changes,
      projection,
      managedFieldIds.certificateKeyType,
      bindings,
      certificate.keyType,
      inheritedKey,
      force,
    );
    emitOptionalOrRequired(
      changes,
      projection,
      managedFieldIds.certificateRenewDays,
      bindings,
      certificate.renewDays,
      0,
      force,
    );
    emitOptionalOrRequired(
      changes,
      projection,
      managedFieldIds.certificateRenewReuseKey,
      bindings,
      certificate.reuseKey,
      false,
      force,
    );
    emitOptionalOrRequired(
      changes,
      projection,
      managedFieldIds.certificateRenewDisableRandomSleep,
      bindings,
      certificate.disableRandomSleep,
      false,
      force,
    );
    emitOptionalOrRequired(
      changes,
      projection,
      managedFieldIds.certificateRenewAriDisable,
      bindings,
      certificate.disableARI,
      false,
      force,
    );
    emitOptionalOrRequired(
      changes,
      projection,
      managedFieldIds.certificateRenewAriWait,
      bindings,
      certificate.ariWait,
      "0s",
      force,
    );
  }
  return changes;
}

const entityNamePattern = /^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$/;
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const domainLabel = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
const domainPattern = new RegExp(`^(?:${domainLabel}\\.)+${domainLabel}$`);

function byteLength(value: string): number {
  return new TextEncoder().encode(value).length;
}

function validIPv4(value: string): boolean {
  const parts = value.split(".");
  return (
    parts.length === 4 &&
    parts.every(
      (part) =>
        /^\d{1,3}$/.test(part) &&
        (part === "0" || !part.startsWith("0")) &&
        Number(part) <= 255,
    )
  );
}

function validIPv6(value: string): boolean {
  if (!/^[0-9A-Fa-f:.]+$/.test(value)) return false;
  try {
    return new URL(`http://[${value}]/`).hostname.startsWith("[");
  } catch {
    return false;
  }
}

function validListenerAddress(value: string): boolean {
  if (byteLength(value) > 256) return false;
  const match =
    /^(?:(\d{1,3}(?:\.\d{1,3}){3})|\[([0-9A-Fa-f:.]+)\])?:(\d{1,5})$/.exec(
      value,
    );
  if (!match) return false;
  if (match[1] !== undefined && !validIPv4(match[1])) return false;
  if (match[2] !== undefined && !validIPv6(match[2])) return false;
  const port = Number(match[3]);
  return port >= 1 && port <= 65535;
}

function durationMilliseconds(value: string): number | null {
  let source = value;
  let sign = 1;
  if (source.startsWith("+") || source.startsWith("-")) {
    if (source[0] === "-") sign = -1;
    source = source.slice(1);
  }
  if (source.length === 0) return null;
  if (source === "0") return sign * 0;
  const matcher = /((?:\d+(?:\.\d*)?|\.\d+))(ns|us|µs|μs|ms|s|m|h)/g;
  const scales: Record<string, number> = {
    ns: 0.000001,
    us: 0.001,
    µs: 0.001,
    μs: 0.001,
    ms: 1,
    s: 1000,
    m: 60_000,
    h: 3_600_000,
  };
  let matched = "";
  let total = 0;
  for (const item of source.matchAll(matcher)) {
    matched += item[0];
    total += Number(item[1]) * scales[item[2]!]!;
  }
  return matched === source && Number.isFinite(total) ? sign * total : null;
}

function safeNativePath(value: string): boolean {
  return (
    value.length > 0 &&
    byteLength(value) <= 4095 &&
    !Array.from(value).some((character) => {
      const point = character.codePointAt(0) ?? 0;
      return point < 0x20 || point === 0x7f;
    })
  );
}

function validBase64URL(value: string): boolean {
  if (!/^[A-Za-z0-9_-]+={0,2}$/.test(value)) return false;
  const padding = value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0;
  const rawLength = value.length - padding;
  if (padding > 0 && value.length % 4 !== 0) return false;
  if (padding === 1 && rawLength % 4 !== 3) return false;
  if (padding === 2 && rawLength % 4 !== 2) return false;
  return rawLength % 4 !== 1;
}

function canonicalMIMEHeader(value: string): string {
  let upper = true;
  let result = "";
  for (const character of value) {
    if (upper && character >= "a" && character <= "z") {
      result += character.toUpperCase();
    } else if (!upper && character >= "A" && character <= "Z") {
      result += character.toLowerCase();
    } else {
      result += character;
    }
    upper = character === "-";
  }
  return result;
}

function validProxyHeader(value: string): boolean {
  return (
    value === "" ||
    (byteLength(value) <= 64 &&
      /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(value) &&
      canonicalMIMEHeader(value) === value)
  );
}

function duplicateNames(items: { name: string }[]): Set<string> {
  const seen = new Set<string>();
  const duplicates = new Set<string>();
  for (const item of items) {
    if (seen.has(item.name)) duplicates.add(item.name);
    seen.add(item.name);
  }
  return duplicates;
}

export function validateDraft(draft: NativeConfigurationDraft): DraftIssue[] {
  const issues: DraftIssue[] = draft.unsupportedFields.map((field) => ({
    fieldId: unsupportedFieldControlId(draft, field),
    message:
      "An unsupported native value is retained and hidden. Explicitly choose the supported replacement before preview.",
  }));
  if (!safeNativePath(draft.storage)) {
    issues.push({
      fieldId: "configuration-storage",
      message: "Enter a native storage path no longer than 4095 bytes.",
    });
  }
  const groups = [
    ["account", draft.accounts],
    ["challenge", draft.challenges],
    ["certificate", draft.certificates],
  ] as const;
  for (const [kind, items] of groups) {
    if (
      draft.creation &&
      items.length === 0 &&
      !(
        kind === "challenge" &&
        draft.certificates.length > 0 &&
        draft.certificates.every(
          (certificate) => certificate.challengeUnsupported,
        )
      )
    ) {
      issues.push({
        fieldId: `${kind}-add`,
        message: `Add at least one ${kind}.`,
      });
    }
    const duplicates = duplicateNames(items);
    items.forEach((item, index) => {
      if (!entityNamePattern.test(item.name)) {
        issues.push({
          fieldId: `${kind}-${index}-name`,
          message: `${kind[0]!.toUpperCase()}${kind.slice(1)} names use 1-64 letters, numbers, dots, underscores, @ signs, or hyphens.`,
        });
      } else if (duplicates.has(item.name)) {
        issues.push({
          fieldId: `${kind}-${index}-name`,
          message: `${item.name} is duplicated.`,
        });
      }
    });
  }
  draft.accounts.forEach((account, index) => {
    const ca = resolveCA(account.server);
    if (!ca) {
      issues.push({
        fieldId: `account-${index}-server`,
        message: "Choose one supported CA endpoint.",
      });
      return;
    }
    if (!keyTypeOptions.includes(account.keyType as SupportedKeyType)) {
      issues.push({
        fieldId: `account-${index}-key-type`,
        message:
          "The hidden native account key type is unsupported. Choose a supported replacement.",
      });
    }
    if (
      !account.isNew &&
      ((account.originalServer === "sslcomrsa" &&
        account.server === "sslcomecc") ||
        (account.originalServer === "sslcomecc" &&
          account.server === "sslcomrsa"))
    ) {
      issues.push({
        fieldId: `account-${index}-server`,
        message:
          "SSL.com RSA and ECDSA share native account storage. Add a new account for the other endpoint, then reassign certificates.",
      });
    }
    if (
      account.email &&
      (byteLength(account.email) > 254 ||
        account.email.trim() !== account.email ||
        !emailPattern.test(account.email))
    ) {
      issues.push({
        fieldId: `account-${index}-email`,
        message: "Enter a valid account email address.",
      });
    }
    const prerequisitesRequired =
      account.isNew || account.server !== account.originalServer;
    if (
      prerequisitesRequired &&
      (ca.value === "letsencrypt" || ca.value === "letsencrypt-staging") &&
      !account.email
    ) {
      issues.push({
        fieldId: `account-${index}-email`,
        message:
          "Let's Encrypt account registration requires an email address.",
      });
    }
    if (prerequisitesRequired && !account.acceptsTerms) {
      issues.push({
        fieldId: `account-${index}-terms`,
        message: "Acknowledge the CA terms before saving.",
      });
    }
    const retainedHmacAvailable =
      (account.eabHmac.action === "keep" && account.eabPresent) ||
      (account.eabHmac.action === "replace" &&
        account.eabHmac.secret.length > 0);
    const hmacAvailable = prerequisitesRequired
      ? account.eabHmac.action === "replace" &&
        account.eabHmac.secret.length > 0
      : retainedHmacAvailable;
    const eabStarted = account.eabKid.length > 0 || hmacAvailable;
    if (account.eabKid && byteLength(account.eabKid) > 4096) {
      issues.push({
        fieldId: `account-${index}-eab-kid`,
        message: "The EAB key identifier must be no longer than 4096 bytes.",
      });
    }
    if (
      ca.eab === "none" &&
      (account.eabKid.length > 0 || retainedHmacAvailable)
    ) {
      issues.push({
        fieldId: `account-${index}-eab-kid`,
        message:
          "Let's Encrypt does not accept EAB input. Clear the key identifier and remove the hidden HMAC value.",
      });
    } else if ((prerequisitesRequired && ca.eab === "required") || eabStarted) {
      if (!account.eabKid) {
        issues.push({
          fieldId: `account-${index}-eab-kid`,
          message: "Enter the EAB key identifier.",
        });
      }
      if (!hmacAvailable || account.eabHmac.action === "remove") {
        issues.push({
          fieldId: `account-${index}-eab-hmac-replacement`,
          message: "Provide the write-only EAB HMAC value.",
        });
      }
    }
    if (
      account.eabHmac.action === "replace" &&
      (account.eabHmac.secret.length > 8192 ||
        !validBase64URL(account.eabHmac.secret))
    ) {
      issues.push({
        fieldId: "account-" + String(index) + "-eab-hmac-replacement",
        message:
          "The write-only EAB HMAC must be nonempty base64url with valid optional padding.",
      });
    }
    if (
      prerequisitesRequired &&
      ca.value === "zerossl" &&
      !account.email &&
      !eabStarted
    ) {
      issues.push({
        fieldId: `account-${index}-email`,
        message: "ZeroSSL needs an account email or explicit EAB credentials.",
      });
    }
  });
  draft.challenges.forEach((challenge, index) => {
    if (challenge.kind === "dns") {
      if (!safeNativePath(challenge.envFile)) {
        issues.push({
          fieldId: `challenge-${index}-env-file`,
          message:
            "Credential file must be a bounded native path resolved from the working directory.",
        });
      }
      if (
        !Number.isSafeInteger(challenge.dnsTimeout) ||
        challenge.dnsTimeout < 0 ||
        challenge.dnsTimeout > 600
      ) {
        issues.push({
          fieldId: `challenge-${index}-dns-timeout`,
          message: "DNS resolver timeout must be 0 through 600 seconds.",
        });
      }
      const wait = durationMilliseconds(challenge.propagationWait);
      if (
        wait === null ||
        wait < 0 ||
        wait > 10 * 60_000 ||
        (wait > 0 &&
          (challenge.disableAuthoritative || challenge.disableRecursive))
      ) {
        issues.push({
          fieldId: `challenge-${index}-propagation-wait`,
          message:
            "Use a zero-to-10m wait, and do not mix a fixed wait with disabled nameserver checks.",
        });
      }
      if (
        challenge.resolvers.length > 8 ||
        challenge.resolvers.some(
          (resolver) =>
            resolver.length === 0 ||
            new TextEncoder().encode(resolver).length > 256 ||
            /[\s/]/.test(resolver),
        )
      ) {
        issues.push({
          fieldId: `challenge-${index}-resolvers`,
          message:
            "Use at most eight DNS resolver hosts or IP addresses with optional ports.",
        });
      }
      const secretAvailable = (draft: SecretDraft, present: boolean) =>
        (draft.action === "keep" && present) ||
        (draft.action === "replace" && draft.secret.length > 0);
      if (challenge.provider === "cloudflare") {
        if (challenge.cloudflareAuthMode === "legacy") {
          if (!emailPattern.test(challenge.cloudflareEmail)) {
            issues.push({
              fieldId: `challenge-${index}-cloudflare-email`,
              message: "Enter the Cloudflare account email.",
            });
          }
          if (
            !secretAvailable(
              challenge.cloudflareApiKey,
              challenge.cloudflareApiKeyPresent,
            )
          ) {
            issues.push({
              fieldId: `challenge-${index}-cloudflare-api-key-replacement`,
              message: "Provide the write-only Cloudflare global API key.",
            });
          }
        } else if (
          !secretAvailable(
            challenge.cloudflareDnsToken,
            challenge.cloudflareDnsTokenPresent,
          )
        ) {
          issues.push({
            fieldId: `challenge-${index}-cloudflare-dns-token-replacement`,
            message: "Provide a Cloudflare token with DNS:Edit permission.",
          });
        }
      } else if (
        challenge.provider === "digitalocean" &&
        !secretAvailable(
          challenge.digitalOceanToken,
          challenge.digitalOceanTokenPresent,
        )
      ) {
        issues.push({
          fieldId: `challenge-${index}-digitalocean-token-replacement`,
          message: "Provide the write-only DigitalOcean API token.",
        });
      } else if (
        challenge.provider === "duckdns" &&
        !secretAvailable(challenge.duckDnsToken, challenge.duckDnsTokenPresent)
      ) {
        issues.push({
          fieldId: `challenge-${index}-duckdns-token-replacement`,
          message: "Provide the write-only DuckDNS account token.",
        });
      }
      if (
        challenge.provider === "azuredns" ||
        challenge.provider === "route53"
      ) {
        const requiredAlways =
          challenge.provider === "azuredns"
            ? [
                managedFieldIds.azureEnvironment,
                managedFieldIds.azureSubscriptionId,
                managedFieldIds.azureResourceGroup,
                managedFieldIds.azurePrivateZone,
                managedFieldIds.azureAuthMethod,
              ]
            : [
                managedFieldIds.awsRegion,
                managedFieldIds.awsSdkLoadConfig,
                managedFieldIds.awsEc2MetadataDisabled,
              ];
        for (const fieldId of [
          ...requiredAlways,
          ...cloudRequiredPublicFields[challenge.cloudAuthMode],
        ]) {
          if (!(challenge.providerSettings[fieldId] ?? "")) {
            issues.push({
              fieldId: `challenge-${index}-${fieldId.replaceAll(".", "-")}`,
              message:
                "This field is required for the selected cloud authentication mode.",
            });
          }
        }
        for (const fieldId of cloudRequiredSecretFields[
          challenge.cloudAuthMode
        ] ?? []) {
          if (
            !secretAvailable(
              challenge.cloudSecrets[fieldId] ?? { action: "keep" },
              challenge.cloudSecretPresence[fieldId] ?? false,
            )
          ) {
            issues.push({
              fieldId: `challenge-${index}-${fieldId.replaceAll(".", "-")}-replacement`,
              message:
                "Provide this write-only credential for the selected cloud authentication mode.",
            });
          }
        }
        const absolutePathFields = [
          managedFieldIds.azureClientCertificatePath,
          managedFieldIds.azureFederatedTokenFile,
          managedFieldIds.azureOidcTokenFile,
          managedFieldIds.azureCliPath,
          managedFieldIds.azureCliConfigDirectory,
          managedFieldIds.awsSharedCredentialsFile,
        ];
        for (const fieldId of absolutePathFields) {
          const value = challenge.providerSettings[fieldId];
          if (value && !value.startsWith("/"))
            issues.push({
              fieldId: `challenge-${index}-${fieldId.replaceAll(".", "-")}`,
              message:
                "Cloud credential and helper paths must be canonical absolute paths.",
            });
        }
      }
      for (const [fieldId, value] of Object.entries(
        challenge.providerSettings,
      )) {
        if (!value) continue;
        if (
          challenge.provider === "azuredns" ||
          challenge.provider === "route53"
        )
          continue;
        const numeric =
          !fieldId.endsWith("base_url") && !fieldId.endsWith("api_url");
        if (
          numeric &&
          (!/^\d+$/.test(value) || Number(value) < 1 || Number(value) > 86400)
        ) {
          issues.push({
            fieldId: `challenge-${index}-${fieldId.replaceAll(".", "-")}`,
            message:
              "Provider timing and TTL overrides use bounded whole seconds.",
          });
        }
        if (
          !numeric &&
          !/^https:\/\/[^\s/?#]+/.test(value) &&
          !/^http:\/\/(127\.0\.0\.1|\[::1\])(?::\d+)?(?:\/|$)/.test(value)
        ) {
          issues.push({
            fieldId: `challenge-${index}-${fieldId.replaceAll(".", "-")}`,
            message:
              "Provider endpoint overrides require HTTPS or loopback HTTP.",
          });
        }
      }
      return;
    }
    if (
      challenge.mode === "listener" &&
      !validListenerAddress(challenge.address)
    ) {
      issues.push({
        fieldId: `challenge-${index}-address`,
        message:
          "Use an empty, literal IPv4, or bracketed IPv6 host with a port, such as :8080 or 127.0.0.1:8080.",
      });
    }
    if (
      challenge.mode === "listener" &&
      !validProxyHeader(challenge.proxyHeader)
    ) {
      issues.push({
        fieldId: `challenge-${index}-proxy-header`,
        message:
          "Use an optional canonical HTTP field name such as Host, Forwarded, or X-Forwarded-Host.",
      });
    }
    const delay = durationMilliseconds(challenge.delay);
    if (
      byteLength(challenge.delay) > 64 ||
      delay === null ||
      delay < 0 ||
      delay > 10 * 60_000
    ) {
      issues.push({
        fieldId: `challenge-${index}-delay`,
        message:
          "Use a nonnegative Go duration no longer than 10m, such as 0s, 500ms, or 1m30s.",
      });
    }
    if (challenge.mode === "webroot" && !safeNativePath(challenge.webroot)) {
      issues.push({
        fieldId: `challenge-${index}-webroot`,
        message:
          "Webroot must be a bounded native path; relative values resolve from the working directory before the server safety audit.",
      });
    }
  });
  draft.certificates.forEach((certificate, index) => {
    if (!keyTypeOptions.includes(certificate.keyType as SupportedKeyType)) {
      issues.push({
        fieldId: `certificate-${index}-key-type`,
        message:
          "The hidden native certificate key type is unsupported. Choose a supported replacement.",
      });
    }
    if (certificate.domains.length === 0) {
      issues.push({
        fieldId: `certificate-${index}-domains`,
        message: "Enter at least one DNS name.",
      });
    } else if (certificate.domains.length > 100) {
      issues.push({
        fieldId: `certificate-${index}-domains`,
        message: "Enter no more than 100 DNS names.",
      });
    }
    const seen = new Set<string>();
    for (const domain of certificate.domains) {
      const candidate = domain.startsWith("*.") ? domain.slice(2) : domain;
      if (
        !domainPattern.test(candidate) ||
        candidate !== candidate.toLowerCase() ||
        byteLength(domain) > 253 ||
        validIPv4(candidate)
      ) {
        issues.push({
          fieldId: `certificate-${index}-domains`,
          message: `${domain || "An empty entry"} is not a lowercase DNS A-label name.`,
        });
      }
      if (seen.has(domain)) {
        issues.push({
          fieldId: `certificate-${index}-domains`,
          message: `${domain} appears more than once.`,
        });
      }
      seen.add(domain);
      if (
        domain.startsWith("*.") &&
        draft.challenges.some(
          (challenge) =>
            challenge.name === certificate.challenge &&
            challenge.kind === "http",
        )
      ) {
        issues.push({
          fieldId: `certificate-${index}-domains`,
          message:
            "HTTP-01 cannot validate wildcard DNS names. Use a supported DNS-01 integration instead.",
        });
      }
    }
    if (
      !draft.accounts.some((account) => account.name === certificate.account)
    ) {
      issues.push({
        fieldId: `certificate-${index}-account`,
        message: "Choose an account defined above.",
      });
    }
    if (
      !certificate.challengeUnsupported &&
      !draft.challenges.some(
        (challenge) => challenge.name === certificate.challenge,
      )
    ) {
      issues.push({
        fieldId: `certificate-${index}-challenge`,
        message:
          "Choose a supported HTTP-01 or DNS-01 challenge defined above.",
      });
    }
    if (
      !Number.isSafeInteger(certificate.renewDays) ||
      certificate.renewDays < 0 ||
      certificate.renewDays > 365
    ) {
      issues.push({
        fieldId: `certificate-${index}-renew-days`,
        message: "Renewal days must be 0 through 365.",
      });
    }
    const ariWait = durationMilliseconds(certificate.ariWait);
    if (
      byteLength(certificate.ariWait) > 64 ||
      ariWait === null ||
      ariWait < 0 ||
      ariWait > 10 * 60_000
    ) {
      issues.push({
        fieldId: `certificate-${index}-ari-wait`,
        message:
          "Use a nonnegative Go duration no longer than 10m, such as 0s, 30s, or 5m.",
      });
    }
  });
  return issues;
}

export function nextEntityName(prefix: string, existing: { name: string }[]) {
  const names = new Set(existing.map((item) => item.name));
  if (!names.has(prefix)) return prefix;
  for (let suffix = 2; suffix <= 999; suffix += 1) {
    if (!names.has(`${prefix}-${suffix}`)) return `${prefix}-${suffix}`;
  }
  return `${prefix}-new`;
}
