import type { ReactNode } from "react";

import { ActionButton } from "../components/ActionButton";
import { FeedbackPanel } from "../components/FeedbackPanel";
import { StatusBadge } from "../components/StatusBadge";
import { WriteOnlySecretField } from "../components/WriteOnlySecretField";
import {
  acknowledgeUnsupportedField,
  caOptions,
  cloudSecretFieldIds,
  keyTypeOptions,
  managedFieldIds,
  newDNSChallenge,
  newHTTPChallenge,
  nextEntityName,
  resolveCA,
  type DraftIssue,
  type NativeConfigurationDraft,
} from "./nativeConfigurationModel";

type MutateDraft = (
  update: (current: NativeConfigurationDraft) => NativeConfigurationDraft,
) => void;

type EditorSectionProps = {
  creation: boolean;
  disabled: boolean;
  draft: NativeConfigurationDraft;
  issues: DraftIssue[];
  mutate: MutateDraft;
};

export function issueFor(issues: DraftIssue[], id: string) {
  return issues.find((issue) => issue.fieldId === id)?.message;
}

export function inputDescription(issues: DraftIssue[], id: string) {
  return issueFor(issues, id)
    ? id + "-description " + id + "-error"
    : id + "-description";
}

export function ConfigurationField({
  children,
  description,
  error,
  id,
  label,
}: {
  children: ReactNode;
  description: string;
  error?: string;
  id: string;
  label: string;
}) {
  return (
    <div className="am-configuration-editor__field">
      <label htmlFor={id}>{label}</label>
      {children}
      <span id={id + "-description"}>{description}</span>
      {error ? (
        <span id={id + "-error"} role="alert">
          {error}
        </span>
      ) : null}
    </div>
  );
}

export function AccountsEditor({
  creation,
  disabled,
  draft,
  issues,
  mutate,
}: EditorSectionProps) {
  function updateAccount(
    index: number,
    update: Partial<NativeConfigurationDraft["accounts"][number]>,
  ) {
    mutate((current) => {
      const previous = current.accounts[index]!;
      const next = { ...previous, ...update };
      let result: NativeConfigurationDraft = {
        ...current,
        accounts: current.accounts.map((account, itemIndex) =>
          itemIndex === index ? next : account,
        ),
        certificates:
          update.name === undefined
            ? current.certificates
            : current.certificates.map((certificate) =>
                certificate.account === previous.name
                  ? { ...certificate, account: update.name! }
                  : certificate,
              ),
      };
      const fieldByProperty: Partial<Record<keyof typeof update, string>> = {
        server: managedFieldIds.accountServer,
        email: managedFieldIds.accountEmail,
        keyType: managedFieldIds.accountKeyType,
        acceptsTerms: managedFieldIds.accountTerms,
        eabKid: managedFieldIds.accountEabKid,
        eabHmac: managedFieldIds.accountEabHmac,
      };
      for (const property of Object.keys(update) as Array<
        keyof typeof update
      >) {
        const fieldId = fieldByProperty[property];
        if (fieldId) {
          result = acknowledgeUnsupportedField(result, fieldId, [
            { id: "account", value: previous.name },
          ]);
        }
      }
      return result;
    });
  }

  return (
    <section
      aria-labelledby="configuration-accounts-heading"
      className="am-configuration-editor__entities"
    >
      <div className="am-configuration-editor__section-heading">
        <div>
          <p className="am-kicker">Accounts and CA endpoints</p>
          <h4 id="configuration-accounts-heading">ACME accounts</h4>
        </div>
        <ActionButton
          isDisabled={disabled || draft.accounts.length >= (creation ? 6 : 16)}
          onPress={() =>
            mutate((current) => ({
              ...current,
              accounts: [
                ...current.accounts,
                {
                  name: nextEntityName("account", current.accounts),
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
            }))
          }
          variant="secondary"
        >
          Add account
        </ActionButton>
      </div>
      <p className="am-configuration-editor__limit">
        {creation
          ? "Up to 6 accounts can be added in one bounded creation draft."
          : "Existing accounts remain native map entries; additions are bounded and reviewable."}{" "}
        Larger adopted projections remain visible and repairable.
      </p>
      {draft.accounts.map((account, index) => {
        const ca = resolveCA(account.server);
        const showEAB =
          ca?.eab !== "none" ||
          account.eabKid !== "" ||
          account.eabPresent ||
          account.eabHmac.action !== "keep";
        const hmacAvailable =
          (account.eabHmac.action === "keep" && account.eabPresent) ||
          (account.eabHmac.action === "replace" &&
            account.eabHmac.secret.length > 0);
        const currentPrerequisitesMissing =
          !account.acceptsTerms ||
          ((ca?.value === "letsencrypt" ||
            ca?.value === "letsencrypt-staging") &&
            !account.email) ||
          (ca?.value === "zerossl" &&
            !account.email &&
            (!account.eabKid || !hmacAvailable)) ||
          (ca?.eab === "required" && (!account.eabKid || !hmacAvailable));
        const existingRegistrationAssumed =
          !account.isNew &&
          account.server === account.originalServer &&
          currentPrerequisitesMissing;
        const nameId = "account-" + String(index) + "-name";
        const serverId = "account-" + String(index) + "-server";
        const emailId = "account-" + String(index) + "-email";
        const keyTypeId = "account-" + String(index) + "-key-type";
        const termsId = "account-" + String(index) + "-terms";
        const kidId = "account-" + String(index) + "-eab-kid";
        const hmacId = "account-" + String(index) + "-eab-hmac";
        return (
          <fieldset
            className="am-configuration-editor__entity"
            key={(account.isNew ? "new:" : "existing:") + account.name}
          >
            <legend>
              Account {index + 1}: <code>{account.name}</code>
            </legend>
            {account.isNew ? (
              <ConfigurationField
                description="A stable native map name, not an endpoint or filesystem path."
                error={issueFor(issues, nameId)}
                id={nameId}
                label="Account name"
              >
                <input
                  aria-describedby={inputDescription(issues, nameId)}
                  aria-invalid={Boolean(issueFor(issues, nameId))}
                  disabled={disabled}
                  id={nameId}
                  maxLength={64}
                  onChange={(event) =>
                    updateAccount(index, { name: event.currentTarget.value })
                  }
                  value={account.name}
                />
              </ConfigurationField>
            ) : null}
            <div className="am-configuration-editor__grid">
              <ConfigurationField
                description="Only accepted presets are available; arbitrary directory URLs cannot be submitted."
                error={issueFor(issues, serverId)}
                id={serverId}
                label="Certificate authority"
              >
                <select
                  aria-describedby={inputDescription(issues, serverId)}
                  aria-invalid={Boolean(issueFor(issues, serverId))}
                  disabled={disabled}
                  id={serverId}
                  onChange={(event) => {
                    const server = event.currentTarget.value;
                    updateAccount(index, {
                      server,
                      acceptsTerms:
                        server === account.originalServer
                          ? account.originalAcceptsTerms
                          : false,
                    });
                  }}
                  value={account.server}
                >
                  {!ca ? (
                    <option value={account.server}>
                      Unsupported native endpoint
                    </option>
                  ) : null}
                  {caOptions.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </ConfigurationField>
              <ConfigurationField
                description="Used for ACME account identity and ZeroSSL email-assisted registration."
                error={issueFor(issues, emailId)}
                id={emailId}
                label="Account email"
              >
                <input
                  aria-describedby={inputDescription(issues, emailId)}
                  aria-invalid={Boolean(issueFor(issues, emailId))}
                  autoCapitalize="none"
                  autoComplete="email"
                  disabled={disabled}
                  id={emailId}
                  maxLength={254}
                  onChange={(event) =>
                    updateAccount(index, { email: event.currentTarget.value })
                  }
                  spellCheck={false}
                  type="email"
                  value={account.email}
                />
              </ConfigurationField>
              <ConfigurationField
                description={
                  account.isNew
                    ? "The native account-key algorithm. Certificate keys are selected separately."
                    : "Changing this value does not rotate the existing stored account key. Use a new account name for a new account-key identity."
                }
                error={issueFor(issues, keyTypeId)}
                id={keyTypeId}
                label="Account key type"
              >
                <select
                  aria-describedby={inputDescription(issues, keyTypeId)}
                  aria-invalid={Boolean(issueFor(issues, keyTypeId))}
                  disabled={disabled}
                  id={keyTypeId}
                  onChange={(event) =>
                    updateAccount(index, {
                      keyType: event.currentTarget
                        .value as NativeConfigurationDraft["accounts"][number]["keyType"],
                    })
                  }
                  value={account.keyType}
                >
                  {account.keyType === "" ? (
                    <option value="">Unsupported native value retained</option>
                  ) : null}
                  {keyTypeOptions.map((keyType) => (
                    <option key={keyType} value={keyType}>
                      {keyType}
                    </option>
                  ))}
                </select>
              </ConfigurationField>
            </div>
            {ca ? (
              <div
                className={
                  "am-configuration-editor__consequence" +
                  (ca.environment === "staging" ? " is-staging" : "")
                }
              >
                <StatusBadge
                  tone={ca.environment === "staging" ? "warning" : "info"}
                >
                  {ca.environment}
                </StatusBadge>
                <p>{ca.prerequisite}</p>
              </div>
            ) : null}
            {existingRegistrationAssumed ? (
              <FeedbackPanel
                tone="warning"
                title="Existing native registration assumed"
              >
                <p>
                  Registration-time terms or EAB input is not retained in this
                  projection. Unrelated edits may keep this account unchanged,
                  but changing its CA requires current prerequisites.
                </p>
              </FeedbackPanel>
            ) : null}
            <label className="am-configuration-editor__check">
              <input
                aria-describedby={inputDescription(issues, termsId)}
                aria-invalid={Boolean(issueFor(issues, termsId))}
                checked={account.acceptsTerms}
                disabled={disabled}
                id={termsId}
                onChange={(event) =>
                  updateAccount(index, {
                    acceptsTerms: event.currentTarget.checked,
                  })
                }
                type="checkbox"
              />
              <span>
                I acknowledge this CA's subscriber agreement and authorize
                native account registration.
                <small id={termsId + "-description"}>
                  AcmeMux records only the native acknowledgement field.
                </small>
                {issueFor(issues, termsId) ? (
                  <small id={termsId + "-error"} role="alert">
                    {issueFor(issues, termsId)}
                  </small>
                ) : null}
              </span>
            </label>
            {showEAB ? (
              <div className="am-configuration-editor__eab">
                <ConfigurationField
                  description="The account-issued External Account Binding identifier is stored in native YAML."
                  error={issueFor(issues, kidId)}
                  id={kidId}
                  label="EAB key identifier"
                >
                  <input
                    aria-describedby={inputDescription(issues, kidId)}
                    aria-invalid={Boolean(issueFor(issues, kidId))}
                    autoCapitalize="none"
                    autoComplete="off"
                    disabled={disabled}
                    id={kidId}
                    maxLength={4096}
                    onChange={(event) =>
                      updateAccount(index, {
                        eabKid: event.currentTarget.value,
                      })
                    }
                    spellCheck={false}
                    value={account.eabKid}
                  />
                </ConfigurationField>
                <WriteOnlySecretField
                  description="The HMAC is write-only and is omitted from every projection, review value, and diagnostic."
                  draft={account.eabHmac}
                  error={issueFor(issues, hmacId + "-replacement")}
                  id={hmacId}
                  isDisabled={disabled}
                  label="EAB HMAC key"
                  maxLength={8192}
                  onChange={(eabHmac) => updateAccount(index, { eabHmac })}
                  presence={account.eabPresent ? "present" : "absent"}
                />
              </div>
            ) : null}
            {account.isNew && draft.accounts.length > 1 ? (
              <ActionButton
                isDisabled={disabled}
                onPress={() =>
                  mutate((current) => ({
                    ...current,
                    accounts: current.accounts.filter(
                      (_, itemIndex) => itemIndex !== index,
                    ),
                  }))
                }
                variant="quiet"
              >
                Remove new account
              </ActionButton>
            ) : null}
          </fieldset>
        );
      })}
    </section>
  );
}

export function ChallengesEditor({
  creation,
  disabled,
  draft,
  issues,
  mutate,
}: EditorSectionProps) {
  function updateChallenge(
    index: number,
    update: Partial<NativeConfigurationDraft["challenges"][number]>,
  ) {
    mutate((current) => {
      const previous = current.challenges[index]!;
      const next = { ...previous, ...update };
      let result: NativeConfigurationDraft = {
        ...current,
        challenges: current.challenges.map((challenge, itemIndex) =>
          itemIndex === index ? next : challenge,
        ),
        certificates:
          update.name === undefined
            ? current.certificates
            : current.certificates.map((certificate) =>
                certificate.challenge === previous.name
                  ? { ...certificate, challenge: update.name! }
                  : certificate,
              ),
      };
      const fieldByProperty: Partial<Record<keyof typeof update, string>> = {
        address: managedFieldIds.challengeAddress,
        delay: managedFieldIds.challengeDelay,
        proxyHeader: managedFieldIds.challengeProxyHeader,
        webroot: managedFieldIds.challengeWebroot,
      };
      for (const property of Object.keys(update) as Array<
        keyof typeof update
      >) {
        const fieldId = fieldByProperty[property];
        if (fieldId) {
          result = acknowledgeUnsupportedField(result, fieldId, [
            { id: "challenge", value: previous.name },
          ]);
        }
      }
      if (update.mode === "listener") {
        result = acknowledgeUnsupportedField(
          result,
          managedFieldIds.challengeWebroot,
          [{ id: "challenge", value: previous.name }],
        );
      } else if (update.mode === "webroot") {
        for (const fieldId of [
          managedFieldIds.challengeAddress,
          managedFieldIds.challengeProxyHeader,
        ]) {
          result = acknowledgeUnsupportedField(result, fieldId, [
            { id: "challenge", value: previous.name },
          ]);
        }
      }
      return result;
    });
  }

  return (
    <section
      aria-labelledby="configuration-challenges-heading"
      className="am-configuration-editor__entities"
    >
      <div className="am-configuration-editor__section-heading">
        <div>
          <p className="am-kicker">Challenge delivery</p>
          <h4 id="configuration-challenges-heading">Challenge integrations</h4>
        </div>
        <div className="am-configuration-editor__actions">
          <ActionButton
            isDisabled={
              disabled || draft.challenges.length >= (creation ? 6 : 16)
            }
            onPress={() =>
              mutate((current) => ({
                ...current,
                challenges: [
                  ...current.challenges,
                  newHTTPChallenge(nextEntityName("http", current.challenges)),
                ],
              }))
            }
            variant="secondary"
          >
            Add HTTP-01
          </ActionButton>
          <ActionButton
            isDisabled={
              disabled || draft.challenges.length >= (creation ? 6 : 16)
            }
            onPress={() =>
              mutate((current) => ({
                ...current,
                challenges: [
                  ...current.challenges,
                  newDNSChallenge(nextEntityName("dns", current.challenges)),
                ],
              }))
            }
            variant="secondary"
          >
            Add DNS-01
          </ActionButton>
        </div>
      </div>
      <p className="am-configuration-editor__limit">
        {creation
          ? "Up to 6 HTTP-01 or curated DNS-01 challenges can be added in one bounded creation draft."
          : "Challenge additions remain bounded by the reviewed native change budget."}
      </p>
      {draft.challenges.map((challenge, index) => {
        const prefix = "challenge-" + String(index);
        const nameId = prefix + "-name";
        const addressId = prefix + "-address";
        const delayId = prefix + "-delay";
        const proxyId = prefix + "-proxy-header";
        const webrootId = prefix + "-webroot";
        if (challenge.kind === "dns") {
          return (
            <DNSChallengeEditor
              challenge={challenge}
              disabled={disabled}
              draft={draft}
              index={index}
              issues={issues}
              key={(challenge.isNew ? "new:" : "existing:") + challenge.name}
              mutate={mutate}
              updateChallenge={updateChallenge}
            />
          );
        }
        const port = Number(
          challenge.address.slice(challenge.address.lastIndexOf(":") + 1),
        );
        return (
          <fieldset
            className="am-configuration-editor__entity"
            key={(challenge.isNew ? "new:" : "existing:") + challenge.name}
          >
            <legend>
              HTTP-01 {index + 1}: <code>{challenge.name}</code>
            </legend>
            {challenge.predefined ? (
              <FeedbackPanel tone="info" title="Upstream predefined HTTP-01">
                <p>
                  The certificate references lego's predefined{" "}
                  <code>http-01</code> challenge. Review the explicit listener
                  values below; preview will materialize this named native
                  challenge so managed execution no longer depends on hidden
                  defaults.
                </p>
              </FeedbackPanel>
            ) : null}
            <>
              {!challenge.predefined && challenge.isNew ? (
                <ConfigurationField
                  description="A stable native map name referenced by certificates."
                  error={issueFor(issues, nameId)}
                  id={nameId}
                  label="Challenge name"
                >
                  <input
                    aria-describedby={inputDescription(issues, nameId)}
                    aria-invalid={Boolean(issueFor(issues, nameId))}
                    disabled={disabled}
                    id={nameId}
                    maxLength={64}
                    onChange={(event) =>
                      updateChallenge(index, {
                        name: event.currentTarget.value,
                      })
                    }
                    value={challenge.name}
                  />
                </ConfigurationField>
              ) : null}
              {!challenge.predefined ? (
                <div className="am-configuration-editor__segmented">
                  <label>
                    <input
                      checked={challenge.mode === "listener"}
                      disabled={disabled}
                      name={prefix + "-mode"}
                      onChange={() =>
                        updateChallenge(index, { mode: "listener" })
                      }
                      type="radio"
                    />
                    Built-in listener
                  </label>
                  <label>
                    <input
                      checked={challenge.mode === "webroot"}
                      disabled={disabled}
                      name={prefix + "-mode"}
                      onChange={() =>
                        updateChallenge(index, { mode: "webroot" })
                      }
                      type="radio"
                    />
                    Existing webroot
                  </label>
                </div>
              ) : null}
              <div className="am-configuration-editor__grid">
                {challenge.mode === "listener" ? (
                  <>
                    <ConfigurationField
                      description="A forwarded public port 80 may target an unprivileged local listener."
                      error={issueFor(issues, addressId)}
                      id={addressId}
                      label="Listener address"
                    >
                      <input
                        aria-describedby={inputDescription(issues, addressId)}
                        aria-invalid={Boolean(issueFor(issues, addressId))}
                        autoCapitalize="none"
                        disabled={disabled}
                        id={addressId}
                        maxLength={256}
                        onChange={(event) =>
                          updateChallenge(index, {
                            address: event.currentTarget.value,
                          })
                        }
                        spellCheck={false}
                        value={challenge.address}
                      />
                    </ConfigurationField>
                    <ConfigurationField
                      description="Header used to recover the requested domain behind a trusted reverse proxy."
                      error={issueFor(issues, proxyId)}
                      id={proxyId}
                      label="Proxy host header"
                    >
                      <input
                        aria-describedby={inputDescription(issues, proxyId)}
                        aria-invalid={Boolean(issueFor(issues, proxyId))}
                        autoCapitalize="none"
                        disabled={disabled}
                        id={proxyId}
                        maxLength={64}
                        onChange={(event) =>
                          updateChallenge(index, {
                            proxyHeader: event.currentTarget.value,
                          })
                        }
                        spellCheck={false}
                        value={challenge.proxyHeader}
                      />
                    </ConfigurationField>
                  </>
                ) : (
                  <ConfigurationField
                    description="Absolute paths are used directly. Relative paths resolve from the native working directory before safety and write-access checks."
                    error={issueFor(issues, webrootId)}
                    id={webrootId}
                    label="Webroot directory"
                  >
                    <input
                      aria-describedby={inputDescription(issues, webrootId)}
                      aria-invalid={Boolean(issueFor(issues, webrootId))}
                      autoCapitalize="none"
                      disabled={disabled}
                      id={webrootId}
                      maxLength={4095}
                      onChange={(event) =>
                        updateChallenge(index, {
                          webroot: event.currentTarget.value,
                        })
                      }
                      spellCheck={false}
                      value={challenge.webroot}
                    />
                  </ConfigurationField>
                )}
                <ConfigurationField
                  description="Optional delay before upstream challenge validation."
                  error={issueFor(issues, delayId)}
                  id={delayId}
                  label="Validation delay"
                >
                  <input
                    aria-describedby={inputDescription(issues, delayId)}
                    aria-invalid={Boolean(issueFor(issues, delayId))}
                    disabled={disabled}
                    id={delayId}
                    maxLength={64}
                    onChange={(event) =>
                      updateChallenge(index, {
                        delay: event.currentTarget.value,
                      })
                    }
                    value={challenge.delay}
                  />
                </ConfigurationField>
              </div>
              <div className="am-configuration-editor__consequence">
                <StatusBadge
                  tone={
                    challenge.mode === "webroot" || port >= 1024
                      ? "info"
                      : "warning"
                  }
                >
                  {challenge.mode === "webroot"
                    ? "Filesystem prerequisite"
                    : port >= 1024
                      ? "Forward port 80"
                      : "Low-port privilege"}
                </StatusBadge>
                <p>
                  {challenge.mode === "webroot"
                    ? "The directory must be publicly served at the domain root. AcmeMux does not alter the web server."
                    : port >= 1024
                      ? "Public TCP port 80 must be forwarded to local port " +
                        (port || "shown above") +
                        "."
                      : "Binding port 80 may require an administrator-provisioned capability on the trusted lego executable. AcmeMux never elevates."}
                </p>
              </div>
            </>
            {challenge.isNew && draft.challenges.length > 1 ? (
              <ActionButton
                isDisabled={disabled}
                onPress={() =>
                  mutate((current) => ({
                    ...current,
                    challenges: current.challenges.filter(
                      (_, itemIndex) => itemIndex !== index,
                    ),
                  }))
                }
                variant="quiet"
              >
                Remove new challenge
              </ActionButton>
            ) : null}
          </fieldset>
        );
      })}
    </section>
  );
}

const dnsProviderOptions = [
  { value: "azuredns", label: "Azure DNS" },
  { value: "cloudflare", label: "Cloudflare" },
  { value: "digitalocean", label: "DigitalOcean" },
  { value: "duckdns", label: "DuckDNS" },
  { value: "route53", label: "Amazon Route 53" },
] as const;

const providerSettings = {
  cloudflare: [
    [managedFieldIds.cloudflareTtl, "TXT TTL", "120"],
    [
      managedFieldIds.cloudflarePropagationTimeout,
      "Propagation timeout",
      "120",
    ],
    [managedFieldIds.cloudflarePollingInterval, "Polling interval", "2"],
    [managedFieldIds.cloudflareHttpTimeout, "HTTP timeout", "30"],
    [
      managedFieldIds.cloudflareBaseUrl,
      "API base URL",
      "https://api.cloudflare.com/client/v4",
    ],
  ],
  digitalocean: [
    [managedFieldIds.digitalOceanTtl, "TXT TTL", "30"],
    [
      managedFieldIds.digitalOceanPropagationTimeout,
      "Propagation timeout",
      "60",
    ],
    [managedFieldIds.digitalOceanPollingInterval, "Polling interval", "5"],
    [managedFieldIds.digitalOceanHttpTimeout, "HTTP timeout", "30"],
    [
      managedFieldIds.digitalOceanApiUrl,
      "API URL",
      "https://api.digitalocean.com",
    ],
  ],
  duckdns: [
    [managedFieldIds.duckDnsPropagationTimeout, "Propagation timeout", "60"],
    [managedFieldIds.duckDnsPollingInterval, "Polling interval", "2"],
    [managedFieldIds.duckDnsHttpTimeout, "HTTP timeout", "30"],
    [
      managedFieldIds.duckDnsSequenceInterval,
      "Sequential request interval",
      "60",
    ],
  ],
  azuredns: [],
  route53: [],
} as const;

const cloudAuthOptions = {
  azuredns: [
    ["azure_client_secret", "Service principal client secret"],
    ["azure_client_certificate", "Service principal certificate"],
    ["azure_workload", "Workload identity"],
    ["azure_managed", "Managed identity"],
    ["azure_cli", "Azure CLI cache"],
    ["azure_oidc_inline", "OIDC inline assertion"],
    ["azure_oidc_file", "OIDC assertion file"],
    ["azure_oidc_request", "OIDC assertion endpoint"],
    ["azure_pipeline", "Azure Pipelines identity"],
  ],
  route53: [
    ["aws_static", "Static or temporary credentials"],
    ["aws_shared_profile", "Audited shared profile"],
    ["aws_instance_role", "EC2 instance role"],
  ],
} as const;

const cloudCommonFields = {
  azuredns: [
    [managedFieldIds.azureEnvironment, "Azure cloud", "public"],
    [
      managedFieldIds.azureSubscriptionId,
      "Subscription ID",
      "00000000-0000-0000-0000-000000000000",
    ],
    [managedFieldIds.azureResourceGroup, "Resource group", "dns-production"],
    [managedFieldIds.azureZoneName, "Zone override", "example.com"],
    [managedFieldIds.azurePrivateZone, "Private zone", "false"],
  ],
  route53: [
    [managedFieldIds.awsRegion, "AWS region", "us-east-1"],
    [
      managedFieldIds.awsHostedZoneId,
      "Hosted zone override",
      "Z11111112222222333333",
    ],
    [managedFieldIds.awsPrivateZone, "Private zone", "false"],
    [
      managedFieldIds.awsAssumeRoleArn,
      "Assume-role ARN",
      "arn:aws:iam::123456789012:role/acmemux-dns",
    ],
  ],
} as const;

const cloudModeFields: Record<
  string,
  readonly (readonly [string, string, string])[]
> = {
  azure_client_secret: [
    [
      managedFieldIds.azureTenantId,
      "Tenant ID",
      "00000000-0000-0000-0000-000000000000",
    ],
    [
      managedFieldIds.azureClientId,
      "Client ID",
      "00000000-0000-0000-0000-000000000000",
    ],
  ],
  azure_client_certificate: [
    [managedFieldIds.azureTenantId, "Tenant ID", ""],
    [managedFieldIds.azureClientId, "Client ID", ""],
    [
      managedFieldIds.azureClientCertificatePath,
      "Certificate path",
      "/etc/acmemux/azure-client.pem",
    ],
  ],
  azure_workload: [
    [managedFieldIds.azureTenantId, "Tenant ID", ""],
    [managedFieldIds.azureClientId, "Client ID", ""],
    [
      managedFieldIds.azureFederatedTokenFile,
      "Federated token file",
      "/var/run/secrets/azure/tokens/azure-identity-token",
    ],
  ],
  azure_managed: [
    [managedFieldIds.azureClientId, "Optional user-assigned client ID", ""],
    [managedFieldIds.azureMsiTimeout, "Metadata timeout seconds", "2"],
    [
      managedFieldIds.azureImdsEndpoint,
      "Optional Azure Arc IMDS endpoint",
      "http://127.0.0.1:40342",
    ],
    [
      managedFieldIds.azureIdentityEndpoint,
      "Optional Azure Arc identity endpoint",
      "http://127.0.0.1:40342/metadata/identity/oauth2/token",
    ],
  ],
  azure_cli: [
    [managedFieldIds.azureTenantId, "Optional tenant ID", ""],
    [
      managedFieldIds.azureCliPath,
      "Directory containing trusted az",
      "/usr/bin",
    ],
    [
      managedFieldIds.azureCliConfigDirectory,
      "Azure CLI cache directory",
      "/var/lib/acmemux/azure",
    ],
  ],
  azure_oidc_inline: [
    [managedFieldIds.azureTenantId, "Tenant ID", ""],
    [managedFieldIds.azureClientId, "Client ID", ""],
  ],
  azure_oidc_file: [
    [managedFieldIds.azureTenantId, "Tenant ID", ""],
    [managedFieldIds.azureClientId, "Client ID", ""],
    [
      managedFieldIds.azureOidcTokenFile,
      "OIDC assertion file",
      "/var/run/secrets/azure/oidc-token",
    ],
  ],
  azure_oidc_request: [
    [managedFieldIds.azureTenantId, "Tenant ID", ""],
    [managedFieldIds.azureClientId, "Client ID", ""],
    [
      managedFieldIds.azureOidcRequestUrl,
      "OIDC assertion endpoint",
      "https://issuer.example/token",
    ],
  ],
  azure_pipeline: [
    [managedFieldIds.azureTenantId, "Tenant ID", ""],
    [managedFieldIds.azureClientId, "Client ID", ""],
    [managedFieldIds.azureServiceConnectionId, "Service connection ID", ""],
    [
      managedFieldIds.azureSystemOidcRequestUri,
      "Pipeline OIDC endpoint",
      "https://dev.azure.com/example/_apis/distributedtask/hubs/build/plans/token",
    ],
  ],
  aws_static: [],
  aws_shared_profile: [
    [managedFieldIds.awsProfile, "Profile name", "acmemux"],
    [
      managedFieldIds.awsSharedCredentialsFile,
      "Shared credentials file",
      "/etc/acmemux/aws-credentials",
    ],
  ],
  aws_instance_role: [],
};

const cloudModeSecretLabels: Record<
  string,
  readonly (readonly [string, string])[]
> = {
  azure_client_secret: [[managedFieldIds.azureClientSecret, "Client secret"]],
  azure_client_certificate: [
    [
      managedFieldIds.azureClientCertificatePassword,
      "Certificate password (optional)",
    ],
  ],
  azure_oidc_inline: [[managedFieldIds.azureOidcToken, "OIDC assertion"]],
  azure_oidc_request: [
    [managedFieldIds.azureOidcRequestToken, "OIDC request token"],
  ],
  azure_pipeline: [
    [managedFieldIds.azureSystemAccessToken, "Pipeline system access token"],
  ],
  aws_static: [
    [managedFieldIds.awsAccessKeyId, "Access key ID"],
    [managedFieldIds.awsSecretAccessKey, "Secret access key"],
    [managedFieldIds.awsSessionToken, "Session token (optional)"],
    [managedFieldIds.awsExternalId, "Assume-role external ID (optional)"],
  ],
  aws_shared_profile: [
    [managedFieldIds.awsExternalId, "Assume-role external ID (optional)"],
  ],
  aws_instance_role: [
    [managedFieldIds.awsExternalId, "Assume-role external ID (optional)"],
  ],
};

function cloudModeDefaults(
  mode: NativeConfigurationDraft["challenges"][number]["cloudAuthMode"],
  current: Record<string, string>,
) {
  const next = { ...current };
  const azure = mode.startsWith("azure_");
  next[managedFieldIds.azureAuthMethod] =
    mode === "azure_workload"
      ? "wli"
      : mode === "azure_managed"
        ? "msi"
        : mode === "azure_cli"
          ? "cli"
          : mode.startsWith("azure_oidc")
            ? "oidc"
            : mode === "azure_pipeline"
              ? "pipeline"
              : "env";
  if (azure) {
    next[managedFieldIds.azureEnvironment] ||= "public";
    next[managedFieldIds.azurePrivateZone] ||= "false";
  } else {
    next[managedFieldIds.awsSdkLoadConfig] = "false";
    next[managedFieldIds.awsEc2MetadataDisabled] =
      mode === "aws_instance_role" ? "false" : "true";
    next[managedFieldIds.awsPrivateZone] ||= "false";
    next[managedFieldIds.awsWaitForChanges] ||= "true";
  }
  return next;
}

function DNSChallengeEditor({
  challenge,
  disabled,
  draft,
  index,
  issues,
  mutate,
  updateChallenge,
}: {
  challenge: NativeConfigurationDraft["challenges"][number];
  disabled: boolean;
  draft: NativeConfigurationDraft;
  index: number;
  issues: DraftIssue[];
  mutate: MutateDraft;
  updateChallenge: (
    index: number,
    update: Partial<NativeConfigurationDraft["challenges"][number]>,
  ) => void;
}) {
  const prefix = `challenge-${index}`;
  const secret = (
    id: string,
    label: string,
    field:
      | "cloudflareApiKey"
      | "cloudflareDnsToken"
      | "cloudflareZoneToken"
      | "digitalOceanToken"
      | "duckDnsToken",
    presentField:
      | "cloudflareApiKeyPresent"
      | "cloudflareDnsTokenPresent"
      | "cloudflareZoneTokenPresent"
      | "digitalOceanTokenPresent"
      | "duckDnsTokenPresent",
    description: string,
  ) => (
    <WriteOnlySecretField
      description={description}
      draft={challenge[field]}
      error={issueFor(issues, `${prefix}-${id}-replacement`)}
      id={`${prefix}-${id}`}
      isDisabled={disabled}
      label={label}
      maxLength={4096}
      onChange={(value) => updateChallenge(index, { [field]: value })}
      presence={challenge[presentField] ? "present" : "absent"}
    />
  );
  return (
    <fieldset className="am-configuration-editor__entity">
      <legend>
        DNS-01 {index + 1}: <code>{challenge.name}</code>
      </legend>
      {challenge.isNew ? (
        <ConfigurationField
          description="A stable native map name referenced by certificates."
          error={issueFor(issues, `${prefix}-name`)}
          id={`${prefix}-name`}
          label="Challenge name"
        >
          <input
            disabled={disabled}
            id={`${prefix}-name`}
            maxLength={64}
            onChange={(event) =>
              updateChallenge(index, { name: event.currentTarget.value })
            }
            value={challenge.name}
          />
        </ConfigurationField>
      ) : null}
      <div className="am-configuration-editor__grid">
        <ConfigurationField
          description={
            challenge.isNew
              ? "Provider code written to native YAML."
              : "Changing an adopted provider requires a new challenge so credential cleanup remains atomic."
          }
          id={`${prefix}-provider`}
          label="DNS provider"
        >
          <select
            disabled={disabled || !challenge.isNew}
            id={`${prefix}-provider`}
            onChange={(event) => {
              const provider = event.currentTarget
                .value as typeof challenge.provider;
              updateChallenge(index, {
                provider,
                originalProvider: provider,
                envFile: `.${provider}.env`,
                cloudAuthMode:
                  provider === "route53" ? "aws_static" : "azure_client_secret",
                originalCloudAuthMode:
                  provider === "route53" ? "aws_static" : "azure_client_secret",
                providerSettings:
                  provider === "azuredns"
                    ? cloudModeDefaults("azure_client_secret", {})
                    : provider === "route53"
                      ? cloudModeDefaults("aws_static", {})
                      : {},
                cloudSecrets: Object.fromEntries(
                  cloudSecretFieldIds.map((fieldId) => [
                    fieldId,
                    { action: "keep" },
                  ]),
                ),
                cloudSecretPresence: Object.fromEntries(
                  cloudSecretFieldIds.map((fieldId) => [fieldId, false]),
                ),
              });
            }}
            value={challenge.provider}
          >
            {dnsProviderOptions.map((provider) => (
              <option key={provider.value} value={provider.value}>
                {provider.label}
              </option>
            ))}
          </select>
        </ConfigurationField>
        <ConfigurationField
          description="Credentials and provider options remain only in this restrictive native dotenv file."
          error={issueFor(issues, `${prefix}-env-file`)}
          id={`${prefix}-env-file`}
          label="Credential file"
        >
          <input
            disabled={disabled || !challenge.isNew}
            id={`${prefix}-env-file`}
            maxLength={4095}
            onChange={(event) =>
              updateChallenge(index, { envFile: event.currentTarget.value })
            }
            spellCheck={false}
            value={challenge.envFile}
          />
        </ConfigurationField>
        <ConfigurationField
          description="Resolver timeout in whole seconds; zero uses upstream defaults."
          error={issueFor(issues, `${prefix}-dns-timeout`)}
          id={`${prefix}-dns-timeout`}
          label="DNS timeout"
        >
          <input
            disabled={disabled}
            id={`${prefix}-dns-timeout`}
            max={600}
            min={0}
            onChange={(event) =>
              updateChallenge(index, {
                dnsTimeout: event.currentTarget.valueAsNumber,
              })
            }
            type="number"
            value={challenge.dnsTimeout}
          />
        </ConfigurationField>
        <ConfigurationField
          description="Optional resolver host or IP per line, with an optional port."
          error={issueFor(issues, `${prefix}-resolvers`)}
          id={`${prefix}-resolvers`}
          label="Recursive resolvers"
        >
          <textarea
            disabled={disabled}
            id={`${prefix}-resolvers`}
            onChange={(event) =>
              updateChallenge(index, {
                resolvers: event.currentTarget.value
                  .split(/\r?\n/)
                  .filter(Boolean),
              })
            }
            value={challenge.resolvers.join("\n")}
          />
        </ConfigurationField>
        <ConfigurationField
          description="A fixed Go duration such as 0s or 30s. A nonzero wait replaces nameserver checks."
          error={issueFor(issues, `${prefix}-propagation-wait`)}
          id={`${prefix}-propagation-wait`}
          label="Fixed propagation wait"
        >
          <input
            disabled={disabled}
            id={`${prefix}-propagation-wait`}
            maxLength={64}
            onChange={(event) =>
              updateChallenge(index, {
                propagationWait: event.currentTarget.value,
              })
            }
            value={challenge.propagationWait}
          />
        </ConfigurationField>
      </div>
      <div className="am-configuration-editor__segmented">
        <label>
          <input
            checked={challenge.disableAuthoritative}
            disabled={disabled || challenge.propagationWait !== "0s"}
            onChange={(event) =>
              updateChallenge(index, {
                disableAuthoritative: event.currentTarget.checked,
              })
            }
            type="checkbox"
          />{" "}
          Disable authoritative checks
        </label>
        <label>
          <input
            checked={challenge.disableRecursive}
            disabled={disabled || challenge.propagationWait !== "0s"}
            onChange={(event) =>
              updateChallenge(index, {
                disableRecursive: event.currentTarget.checked,
              })
            }
            type="checkbox"
          />{" "}
          Disable recursive checks
        </label>
      </div>
      {challenge.provider === "cloudflare" ? (
        <>
          <div className="am-configuration-editor__segmented">
            <label>
              <input
                checked={challenge.cloudflareAuthMode === "token"}
                disabled={disabled}
                name={`${prefix}-cloudflare-auth`}
                onChange={() =>
                  updateChallenge(index, {
                    cloudflareAuthMode: "token",
                    cloudflareApiKey: { action: "keep" },
                  })
                }
                type="radio"
              />{" "}
              Scoped API token
            </label>
            <label>
              <input
                checked={challenge.cloudflareAuthMode === "legacy"}
                disabled={disabled}
                name={`${prefix}-cloudflare-auth`}
                onChange={() =>
                  updateChallenge(index, {
                    cloudflareAuthMode: "legacy",
                    cloudflareDnsToken: { action: "keep" },
                    cloudflareZoneToken: { action: "keep" },
                  })
                }
                type="radio"
              />{" "}
              Legacy global key
            </label>
          </div>
          {challenge.cloudflareAuthMode === "legacy" ? (
            <>
              <FeedbackPanel
                tone="warning"
                title="Legacy key grants broad account access"
              >
                <p>
                  Prefer scoped tokens. The global API key can read and change
                  substantially more than DNS records.
                </p>
              </FeedbackPanel>
              <ConfigurationField
                description="Cloudflare account email stored in the native dotenv file."
                error={issueFor(issues, `${prefix}-cloudflare-email`)}
                id={`${prefix}-cloudflare-email`}
                label="Account email"
              >
                <input
                  disabled={disabled}
                  id={`${prefix}-cloudflare-email`}
                  maxLength={254}
                  onChange={(event) =>
                    updateChallenge(index, {
                      cloudflareEmail: event.currentTarget.value,
                    })
                  }
                  value={challenge.cloudflareEmail}
                />
              </ConfigurationField>
              {secret(
                "cloudflare-api-key",
                "Global API key",
                "cloudflareApiKey",
                "cloudflareApiKeyPresent",
                "Write-only legacy credential stored only in the native dotenv file.",
              )}
            </>
          ) : (
            <>
              <FeedbackPanel
                tone="info"
                title="Least-privilege Cloudflare tokens"
              >
                <p>
                  Grant Zone / DNS / Edit to the DNS token. It may also carry
                  Zone / Zone / Read, or supply a separate read-only zone token.
                </p>
              </FeedbackPanel>
              {secret(
                "cloudflare-dns-token",
                "DNS API token",
                "cloudflareDnsToken",
                "cloudflareDnsTokenPresent",
                "Required write-only token with DNS:Edit permission.",
              )}
              {secret(
                "cloudflare-zone-token",
                "Zone API token",
                "cloudflareZoneToken",
                "cloudflareZoneTokenPresent",
                "Optional separate write-only token with Zone:Read permission.",
              )}
            </>
          )}
        </>
      ) : challenge.provider === "digitalocean" ? (
        secret(
          "digitalocean-token",
          "DigitalOcean API token",
          "digitalOceanToken",
          "digitalOceanTokenPresent",
          "Write-only token with permission to manage domain records.",
        )
      ) : challenge.provider === "duckdns" ? (
        secret(
          "duckdns-token",
          "DuckDNS account token",
          "duckDnsToken",
          "duckDnsTokenPresent",
          "Write-only DuckDNS account token.",
        )
      ) : (
        <>
          <FeedbackPanel
            tone={
              challenge.cloudAuthMode === "azure_managed" ||
              challenge.cloudAuthMode === "aws_instance_role"
                ? "warning"
                : "info"
            }
            title="Explicit cloud identity boundary"
          >
            <p>
              AcmeMux passes no inherited service environment or HOME. Only the
              selected fields, audited files, trusted helper, or explicitly
              acknowledged metadata identity are available to upstream lego.
            </p>
          </FeedbackPanel>
          <ConfigurationField
            description="Authentication alternatives are mutually exclusive; switching modes removes obsolete native variables atomically."
            id={`${prefix}-cloud-auth-mode`}
            label="Authentication mode"
          >
            <select
              disabled={disabled}
              id={`${prefix}-cloud-auth-mode`}
              onChange={(event) => {
                const cloudAuthMode = event.currentTarget
                  .value as typeof challenge.cloudAuthMode;
                updateChallenge(index, {
                  cloudAuthMode,
                  providerSettings: cloudModeDefaults(
                    cloudAuthMode,
                    challenge.providerSettings,
                  ),
                });
              }}
              value={challenge.cloudAuthMode}
            >
              {cloudAuthOptions[challenge.provider].map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </ConfigurationField>
          <div className="am-configuration-editor__grid">
            {[
              ...cloudCommonFields[challenge.provider],
              ...(cloudModeFields[challenge.cloudAuthMode] ?? []),
            ].map(([fieldId, label, placeholder]) => {
              const id = `${prefix}-${fieldId.replaceAll(".", "-")}`;
              return (
                <ConfigurationField
                  description="Exact upstream cloud setting stored in the restrictive native dotenv file."
                  error={issueFor(issues, id)}
                  id={id}
                  key={fieldId}
                  label={label}
                >
                  <input
                    disabled={disabled}
                    id={id}
                    maxLength={4095}
                    onChange={(event) =>
                      updateChallenge(index, {
                        providerSettings: {
                          ...challenge.providerSettings,
                          [fieldId]: event.currentTarget.value,
                        },
                      })
                    }
                    placeholder={placeholder}
                    spellCheck={false}
                    value={challenge.providerSettings[fieldId] ?? ""}
                  />
                </ConfigurationField>
              );
            })}
          </div>
          {(cloudModeSecretLabels[challenge.cloudAuthMode] ?? []).map(
            ([fieldId, label]) => (
              <WriteOnlySecretField
                description="Write-only cloud credential retained only in the selected native dotenv file or operation memory."
                draft={challenge.cloudSecrets[fieldId] ?? { action: "keep" }}
                error={issueFor(
                  issues,
                  `${prefix}-${fieldId.replaceAll(".", "-")}-replacement`,
                )}
                id={`${prefix}-${fieldId.replaceAll(".", "-")}`}
                isDisabled={disabled}
                key={fieldId}
                label={label}
                maxLength={65536}
                onChange={(value) =>
                  updateChallenge(index, {
                    cloudSecrets: {
                      ...challenge.cloudSecrets,
                      [fieldId]: value,
                    },
                  })
                }
                presence={
                  challenge.cloudSecretPresence[fieldId] ? "present" : "absent"
                }
              />
            ),
          )}
        </>
      )}
      <h5>Provider overrides</h5>
      <div className="am-configuration-editor__grid">
        {providerSettings[challenge.provider].map(
          ([fieldId, label, placeholder]) => {
            const id = `${prefix}-${fieldId.replaceAll(".", "-")}`;
            return (
              <ConfigurationField
                description="Optional exact upstream override; leave blank to use the documented default."
                error={issueFor(issues, id)}
                id={id}
                key={fieldId}
                label={label}
              >
                <input
                  disabled={disabled}
                  id={id}
                  onChange={(event) =>
                    updateChallenge(index, {
                      providerSettings: {
                        ...challenge.providerSettings,
                        [fieldId]: event.currentTarget.value,
                      },
                    })
                  }
                  placeholder={placeholder}
                  value={challenge.providerSettings[fieldId] ?? ""}
                />
              </ConfigurationField>
            );
          },
        )}
      </div>
      <FeedbackPanel
        tone="info"
        title={
          challenge.provider === "duckdns"
            ? "Sequential DNS updates"
            : "Native provider execution"
        }
      >
        <p>
          {challenge.provider === "duckdns"
            ? "DuckDNS exposes one TXT record per registered domain, so upstream lego resolves challenges sequentially using the configured interval."
            : "AcmeMux writes only the curated native configuration. Upstream lego performs every provider API request."}
        </p>
      </FeedbackPanel>
      {challenge.isNew && draft.challenges.length > 1 ? (
        <ActionButton
          isDisabled={disabled}
          onPress={() =>
            mutate((current) => ({
              ...current,
              challenges: current.challenges.filter(
                (_, itemIndex) => itemIndex !== index,
              ),
            }))
          }
          variant="quiet"
        >
          Remove new challenge
        </ActionButton>
      ) : null}
    </fieldset>
  );
}

export function CertificatesEditor({
  creation,
  disabled,
  draft,
  issues,
  mutate,
}: EditorSectionProps) {
  function updateCertificate(
    index: number,
    update: Partial<NativeConfigurationDraft["certificates"][number]>,
  ) {
    mutate((current) => {
      const previous = current.certificates[index]!;
      let result: NativeConfigurationDraft = {
        ...current,
        certificates: current.certificates.map((certificate, itemIndex) =>
          itemIndex === index
            ? {
                ...certificate,
                ...update,
                challengeUnsupported:
                  update.challenge === undefined
                    ? certificate.challengeUnsupported
                    : false,
              }
            : certificate,
        ),
      };
      const fieldByProperty: Partial<Record<keyof typeof update, string>> = {
        domains: managedFieldIds.certificateDomains,
        account: managedFieldIds.certificateAccount,
        challenge: managedFieldIds.certificateChallenge,
        keyType: managedFieldIds.certificateKeyType,
        renewDays: managedFieldIds.certificateRenewDays,
        reuseKey: managedFieldIds.certificateRenewReuseKey,
        disableRandomSleep: managedFieldIds.certificateRenewDisableRandomSleep,
        disableARI: managedFieldIds.certificateRenewAriDisable,
        ariWait: managedFieldIds.certificateRenewAriWait,
      };
      for (const property of Object.keys(update) as Array<
        keyof typeof update
      >) {
        const fieldId = fieldByProperty[property];
        if (fieldId) {
          result = acknowledgeUnsupportedField(result, fieldId, [
            { id: "certificate", value: previous.name },
          ]);
        }
      }
      return result;
    });
  }

  return (
    <section
      aria-labelledby="configuration-certificates-heading"
      className="am-configuration-editor__entities"
    >
      <div className="am-configuration-editor__section-heading">
        <div>
          <p className="am-kicker">Desired certificates</p>
          <h4 id="configuration-certificates-heading">
            Certificate definitions
          </h4>
        </div>
        <ActionButton
          isDisabled={
            disabled || draft.certificates.length >= (creation ? 8 : 64)
          }
          onPress={() =>
            mutate((current) => ({
              ...current,
              certificates: [
                ...current.certificates,
                {
                  name: nextEntityName("certificate", current.certificates),
                  isNew: true,
                  domains: [],
                  account: current.accounts[0]?.name ?? "",
                  challenge: current.challenges[0]?.name ?? "",
                  challengeUnsupported: false,
                  keyType: current.accounts[0]?.keyType ?? "EC256",
                  renewDays: 0,
                  reuseKey: false,
                  disableRandomSleep: false,
                  disableARI: false,
                  ariWait: "0s",
                },
              ],
            }))
          }
          variant="secondary"
        >
          Add certificate
        </ActionButton>
      </div>
      <p className="am-configuration-editor__limit">
        {creation
          ? "Up to 8 certificates can be added in one bounded creation draft."
          : "Certificate additions remain bounded by the reviewed native change budget."}
      </p>
      {draft.certificates.map((certificate, index) => {
        const prefix = "certificate-" + String(index);
        const nameId = prefix + "-name";
        const domainsId = prefix + "-domains";
        const accountId = prefix + "-account";
        const challengeId = prefix + "-challenge";
        const keyTypeId = prefix + "-key-type";
        const daysId = prefix + "-renew-days";
        const ariWaitId = prefix + "-ari-wait";
        return (
          <fieldset
            className="am-configuration-editor__entity"
            key={(certificate.isNew ? "new:" : "existing:") + certificate.name}
          >
            <legend>
              Certificate {index + 1}: <code>{certificate.name}</code>
            </legend>
            {certificate.isNew ? (
              <ConfigurationField
                description="A stable native resource name. Existing names are not implicitly renamed because upstream archive behavior is name-based."
                error={issueFor(issues, nameId)}
                id={nameId}
                label="Certificate name"
              >
                <input
                  aria-describedby={inputDescription(issues, nameId)}
                  aria-invalid={Boolean(issueFor(issues, nameId))}
                  disabled={disabled}
                  id={nameId}
                  maxLength={64}
                  onChange={(event) =>
                    updateCertificate(index, {
                      name: event.currentTarget.value,
                    })
                  }
                  value={certificate.name}
                />
              </ConfigurationField>
            ) : null}
            <ConfigurationField
              description="One lowercase DNS A-label name per line. HTTP-01 cannot issue wildcard certificates."
              error={issueFor(issues, domainsId)}
              id={domainsId}
              label="DNS names"
            >
              <textarea
                aria-describedby={inputDescription(issues, domainsId)}
                aria-invalid={Boolean(issueFor(issues, domainsId))}
                autoCapitalize="none"
                disabled={disabled}
                id={domainsId}
                onChange={(event) =>
                  updateCertificate(index, {
                    domains: event.currentTarget.value
                      .split("\n")
                      .map((domain) => domain.trim())
                      .filter(Boolean),
                  })
                }
                rows={Math.max(3, certificate.domains.length + 1)}
                spellCheck={false}
                value={certificate.domains.join("\n")}
              />
            </ConfigurationField>
            <div className="am-configuration-editor__grid">
              <ConfigurationField
                description="Native account reference used for registration and certificate requests."
                error={issueFor(issues, accountId)}
                id={accountId}
                label="Account"
              >
                <select
                  aria-describedby={inputDescription(issues, accountId)}
                  aria-invalid={Boolean(issueFor(issues, accountId))}
                  disabled={disabled}
                  id={accountId}
                  onChange={(event) =>
                    updateCertificate(index, {
                      account: event.currentTarget.value,
                    })
                  }
                  value={certificate.account}
                >
                  <option value="">Choose an account</option>
                  {draft.accounts.map((account) => (
                    <option key={account.name} value={account.name}>
                      {account.name}
                    </option>
                  ))}
                </select>
              </ConfigurationField>
              <ConfigurationField
                description="Named HTTP-01 listener or webroot used for every DNS name."
                error={issueFor(issues, challengeId)}
                id={challengeId}
                label="HTTP-01 challenge"
              >
                <select
                  aria-describedby={inputDescription(issues, challengeId)}
                  aria-invalid={Boolean(issueFor(issues, challengeId))}
                  disabled={disabled}
                  id={challengeId}
                  onChange={(event) =>
                    updateCertificate(index, {
                      challenge: event.currentTarget.value,
                    })
                  }
                  value={certificate.challenge}
                >
                  {certificate.challengeUnsupported ? (
                    <option value={certificate.challenge}>
                      Unsupported native challenge retained
                    </option>
                  ) : null}
                  <option value="">Choose an HTTP-01 challenge</option>
                  {draft.challenges.map((challenge) => (
                    <option key={challenge.name} value={challenge.name}>
                      {challenge.name}
                    </option>
                  ))}
                </select>
              </ConfigurationField>
              <ConfigurationField
                description="Certificate private-key algorithm written to native configuration."
                error={issueFor(issues, keyTypeId)}
                id={keyTypeId}
                label="Certificate key type"
              >
                <select
                  aria-describedby={inputDescription(issues, keyTypeId)}
                  aria-invalid={Boolean(issueFor(issues, keyTypeId))}
                  disabled={disabled}
                  id={keyTypeId}
                  onChange={(event) =>
                    updateCertificate(index, {
                      keyType: event.currentTarget
                        .value as NativeConfigurationDraft["certificates"][number]["keyType"],
                    })
                  }
                  value={certificate.keyType}
                >
                  {certificate.keyType === "" ? (
                    <option value="">Unsupported native value retained</option>
                  ) : null}
                  {keyTypeOptions.map((keyType) => (
                    <option key={keyType} value={keyType}>
                      {keyType}
                    </option>
                  ))}
                </select>
              </ConfigurationField>
            </div>
            {certificate.challengeUnsupported ? (
              <FeedbackPanel
                tone="warning"
                title="Unsupported native challenge retained"
              >
                <p>
                  This certificate references an implicit challenge outside the
                  managed HTTP-01 contract. Unrelated edits preserve that
                  reference and never create an HTTP mapping for it. Choose a
                  supported HTTP-01 challenge above only to replace it
                  explicitly.
                </p>
              </FeedbackPanel>
            ) : null}
            <details className="am-configuration-editor__renewal">
              <summary>Renewal behavior</summary>
              <p>
                Upstream lego remains authoritative for ARI and lifetime-based
                decisions. AcmeMux does not calculate a competing due date.
              </p>
              <div className="am-configuration-editor__grid">
                <ConfigurationField
                  description="0 leaves the lifetime threshold unset so upstream defaults and ARI can apply."
                  error={issueFor(issues, daysId)}
                  id={daysId}
                  label="Renewal threshold in days"
                >
                  <input
                    aria-describedby={inputDescription(issues, daysId)}
                    aria-invalid={Boolean(issueFor(issues, daysId))}
                    disabled={disabled}
                    id={daysId}
                    max={365}
                    min={0}
                    onChange={(event) =>
                      updateCertificate(index, {
                        renewDays: Number(event.currentTarget.value),
                      })
                    }
                    type="number"
                    value={certificate.renewDays}
                  />
                </ConfigurationField>
                <ConfigurationField
                  description="Optional upstream duration to wait within an ARI renewal window."
                  error={issueFor(issues, ariWaitId)}
                  id={ariWaitId}
                  label="ARI wait duration"
                >
                  <input
                    aria-describedby={inputDescription(issues, ariWaitId)}
                    aria-invalid={Boolean(issueFor(issues, ariWaitId))}
                    disabled={disabled || certificate.disableARI}
                    id={ariWaitId}
                    maxLength={64}
                    onChange={(event) =>
                      updateCertificate(index, {
                        ariWait: event.currentTarget.value,
                      })
                    }
                    value={certificate.ariWait}
                  />
                </ConfigurationField>
              </div>
              <div className="am-configuration-editor__checks">
                <label>
                  <input
                    checked={certificate.reuseKey}
                    disabled={disabled}
                    id={prefix + "-renew-reuse-key"}
                    onChange={(event) =>
                      updateCertificate(index, {
                        reuseKey: event.currentTarget.checked,
                      })
                    }
                    type="checkbox"
                  />
                  Reuse the existing private key during renewal
                </label>
                <label>
                  <input
                    checked={certificate.disableRandomSleep}
                    disabled={disabled}
                    id={prefix + "-renew-disable-random-sleep"}
                    onChange={(event) =>
                      updateCertificate(index, {
                        disableRandomSleep: event.currentTarget.checked,
                      })
                    }
                    type="checkbox"
                  />
                  Disable upstream randomized renewal delay
                </label>
                <label>
                  <input
                    checked={certificate.disableARI}
                    disabled={disabled}
                    id={prefix + "-renew-disable-ari"}
                    onChange={(event) =>
                      updateCertificate(index, {
                        disableARI: event.currentTarget.checked,
                      })
                    }
                    type="checkbox"
                  />
                  Disable ACME Renewal Information for this certificate
                </label>
              </div>
            </details>
            {certificate.isNew && draft.certificates.length > 1 ? (
              <ActionButton
                isDisabled={disabled}
                onPress={() =>
                  mutate((current) => ({
                    ...current,
                    certificates: current.certificates.filter(
                      (_, itemIndex) => itemIndex !== index,
                    ),
                  }))
                }
                variant="quiet"
              >
                Remove new certificate
              </ActionButton>
            ) : null}
          </fieldset>
        );
      })}
    </section>
  );
}
