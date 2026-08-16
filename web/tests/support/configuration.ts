import type { Page } from "@playwright/test";

type ConfigurationSnapshot = Record<string, unknown>;

const source = {
  baseRevisionToken: "A".repeat(43),
  configurationPath: "/srv/lego/.lego.yml",
  dotenvPaths: [],
  runtimeManifestId: "lego-v5.3.1",
};

export const readyConfiguration = {
  state: "ready",
  source,
  projection: [
    {
      fieldId: "account.accepts_terms_of_service",
      bindings: [{ id: "account", value: "primary" }],
      label: "CA terms acknowledgement",
      kind: "boolean",
      present: true,
      configured: true,
      defaulted: false,
      presenceKnown: true,
      value: true,
    },
    {
      fieldId: "account.eab.hmac_key",
      bindings: [{ id: "account", value: "primary" }],
      label: "External account binding HMAC",
      kind: "secret",
      present: false,
      configured: false,
      defaulted: false,
      presenceKnown: true,
    },
    {
      fieldId: "account.email",
      bindings: [{ id: "account", value: "primary" }],
      label: "Account email",
      kind: "string",
      present: true,
      configured: true,
      defaulted: false,
      presenceKnown: true,
      value: "admin@example.com",
    },
    {
      fieldId: "account.key_type",
      bindings: [{ id: "account", value: "primary" }],
      label: "Account key type",
      kind: "string",
      present: true,
      configured: true,
      defaulted: false,
      presenceKnown: true,
      value: "EC256",
    },
    {
      fieldId: "account.server",
      bindings: [{ id: "account", value: "primary" }],
      label: "Certificate authority",
      kind: "string",
      present: true,
      configured: true,
      defaulted: false,
      presenceKnown: true,
      value: "letsencrypt",
    },
    {
      fieldId: "certificate.account",
      bindings: [{ id: "certificate", value: "home" }],
      label: "Certificate account",
      kind: "string",
      present: true,
      configured: true,
      defaulted: false,
      presenceKnown: true,
      value: "primary",
    },
    {
      fieldId: "certificate.challenge",
      bindings: [{ id: "certificate", value: "home" }],
      label: "Certificate challenge",
      kind: "string",
      present: true,
      configured: true,
      defaulted: false,
      presenceKnown: true,
      value: "http-home",
    },
    {
      fieldId: "certificate.domains",
      bindings: [{ id: "certificate", value: "home" }],
      label: "DNS names",
      kind: "string_list",
      present: true,
      configured: true,
      defaulted: false,
      presenceKnown: true,
      value: ["home.example.com"],
    },
    {
      fieldId: "certificate.key_type",
      bindings: [{ id: "certificate", value: "home" }],
      label: "Certificate key type",
      kind: "string",
      present: true,
      configured: true,
      defaulted: false,
      presenceKnown: true,
      value: "EC256",
    },
    {
      fieldId: "certificate.renew.ari.disable",
      bindings: [{ id: "certificate", value: "home" }],
      label: "Disable ARI",
      kind: "boolean",
      present: true,
      configured: true,
      defaulted: false,
      presenceKnown: true,
      value: false,
    },
    {
      fieldId: "certificate.renew.ari.wait_to_renew_duration",
      bindings: [{ id: "certificate", value: "home" }],
      label: "ARI wait duration",
      kind: "string",
      present: true,
      configured: true,
      defaulted: false,
      presenceKnown: true,
      value: "0s",
    },
    {
      fieldId: "certificate.renew.days",
      bindings: [{ id: "certificate", value: "home" }],
      label: "Renewal threshold",
      kind: "integer",
      present: true,
      configured: true,
      defaulted: false,
      presenceKnown: true,
      value: 0,
    },
    {
      fieldId: "certificate.renew.disable_random_sleep",
      bindings: [{ id: "certificate", value: "home" }],
      label: "Disable random sleep",
      kind: "boolean",
      present: true,
      configured: true,
      defaulted: false,
      presenceKnown: true,
      value: false,
    },
    {
      fieldId: "certificate.renew.reuse_key",
      bindings: [{ id: "certificate", value: "home" }],
      label: "Reuse certificate key",
      kind: "boolean",
      present: true,
      configured: true,
      defaulted: false,
      presenceKnown: true,
      value: false,
    },
    {
      fieldId: "challenge.http.address",
      bindings: [{ id: "challenge", value: "http-home" }],
      label: "HTTP listener address",
      kind: "string",
      present: true,
      configured: true,
      defaulted: false,
      presenceKnown: true,
      value: ":8080",
    },
    {
      fieldId: "challenge.http.delay",
      bindings: [{ id: "challenge", value: "http-home" }],
      label: "HTTP validation delay",
      kind: "string",
      present: true,
      configured: true,
      defaulted: false,
      presenceKnown: true,
      value: "0s",
    },
    {
      fieldId: "challenge.http.proxy_header",
      bindings: [{ id: "challenge", value: "http-home" }],
      label: "Proxy host header",
      kind: "string",
      present: false,
      configured: false,
      defaulted: false,
      presenceKnown: true,
    },
    {
      fieldId: "workspace.storage",
      bindings: [],
      label: "Native storage directory",
      kind: "string",
      present: true,
      configured: true,
      defaulted: false,
      presenceKnown: true,
      value: "./data",
    },
  ],
  diagnostics: [],
  capabilities: { editing: true, execution: true },
} as const;

export const creationRequiredConfiguration = {
  state: "creation_required",
  source: {
    baseRevisionToken: source.baseRevisionToken,
    configurationPath: "",
    dotenvPaths: [],
    runtimeManifestId: source.runtimeManifestId,
  },
  diagnostics: [],
  capabilities: { editing: false, execution: false },
} as const;

export const unsupportedConfiguration = {
  ...readyConfiguration,
  state: "unsupported",
  projection: readyConfiguration.projection.map((field) =>
    field.fieldId === "account.server"
      ? {
          fieldId: field.fieldId,
          bindings: field.bindings,
          label: field.label,
          kind: "string",
          present: true,
          configured: false,
          defaulted: false,
          presenceKnown: true,
        }
      : field,
  ),
  diagnostics: [
    {
      code: "unsupported_provider",
      severity: "blocking",
      role: "semantic",
      message: "The provider is outside the supported integration manifest.",
      fieldId: null,
      bindings: [],
      path: "/srv/lego/.lego.yml",
      line: 24,
      column: 7,
    },
    {
      code: "unknown_field",
      severity: "blocking",
      role: "configuration",
      message: "Unknown native content remains preserved.",
      fieldId: null,
      bindings: [],
      path: "/srv/lego/.lego.yml",
      line: 42,
      column: 3,
    },
  ],
  capabilities: { editing: true, execution: false },
} as const;

export const recoveryConfiguration = {
  state: "recovery_required",
  source: {
    ...source,
    dotenvPaths: ["/srv/lego/cloudflare.env"],
  },
  recovery: {
    operation: "edit",
    phase: "replacing",
    state: "ambiguous",
    targets: [
      {
        role: "configuration",
        path: "/srv/lego/.lego.yml",
        state: "ambiguous",
      },
      {
        role: "dotenv",
        path: "/srv/lego/cloudflare.env",
        state: "unapplied",
      },
    ],
  },
  diagnostics: [
    {
      code: "recovery_required",
      severity: "blocking",
      role: "recovery",
      message: "A prior replacement requires reconciliation.",
      fieldId: null,
      bindings: [],
      path: "/srv/lego/.lego.yml",
      line: null,
      column: null,
    },
  ],
  capabilities: { editing: false, execution: false },
} as const;

type ConfigurationMockOptions = {
  initial?: ConfigurationSnapshot;
  preview?: Record<string, unknown>;
  creationPreview?: Record<string, unknown>;
  created?: ConfigurationSnapshot;
  recovered?: ConfigurationSnapshot;
  recoveryFailure?: {
    code: "service_unavailable";
    status: 503;
  };
  saved?: ConfigurationSnapshot;
};

export async function mockConfiguration(
  page: Page,
  options: ConfigurationMockOptions = {},
) {
  let selected = options.initial ?? readyConfiguration;
  const observations: {
    previews: unknown[];
    creationPreviews: unknown[];
    creations: unknown[];
    recoveries: unknown[];
    saves: unknown[];
  } = {
    previews: [],
    creationPreviews: [],
    creations: [],
    recoveries: [],
    saves: [],
  };

  await page.route("**/api/v1/configuration", async (route) => {
    const request = route.request();
    if (request.method() === "GET") {
      await route.fulfill({
        body: JSON.stringify(selected),
        contentType: "application/json",
        status: 200,
      });
      return;
    }
    if (request.method() === "PUT" && options.saved) {
      observations.saves.push(request.postDataJSON());
      selected = options.saved;
      await route.fulfill({
        body: JSON.stringify(selected),
        contentType: "application/json",
        status: 200,
      });
      return;
    }
    await route.fulfill({ status: 405 });
  });

  await page.route("**/api/v1/configuration/previews", async (route) => {
    if (route.request().method() !== "POST" || !options.preview) {
      await route.fulfill({ status: 405 });
      return;
    }
    observations.previews.push(route.request().postDataJSON());
    await route.fulfill({
      body: JSON.stringify(options.preview),
      contentType: "application/json",
      status: 200,
    });
  });

  await page.route(
    "**/api/v1/configuration/creation-previews",
    async (route) => {
      if (route.request().method() !== "POST" || !options.creationPreview) {
        await route.fulfill({ status: 405 });
        return;
      }
      observations.creationPreviews.push(route.request().postDataJSON());
      await route.fulfill({
        body: JSON.stringify(options.creationPreview),
        contentType: "application/json",
        status: 200,
      });
    },
  );

  await page.route("**/api/v1/configuration/creation", async (route) => {
    if (route.request().method() !== "PUT" || !options.created) {
      await route.fulfill({ status: 405 });
      return;
    }
    observations.creations.push(route.request().postDataJSON());
    selected = options.created;
    await route.fulfill({
      body: JSON.stringify(selected),
      contentType: "application/json",
      status: 200,
    });
  });

  await page.route("**/api/v1/configuration/recovery", async (route) => {
    if (route.request().method() !== "PUT" || !options.recovered) {
      await route.fulfill({ status: 405 });
      return;
    }
    observations.recoveries.push(route.request().postDataJSON());
    selected = options.recovered;
    if (options.recoveryFailure) {
      await route.fulfill({
        body: JSON.stringify({
          error: {
            code: options.recoveryFailure.code,
            message: "Do not reflect this mock response.",
          },
        }),
        contentType: "application/json",
        status: options.recoveryFailure.status,
      });
      return;
    }
    await route.fulfill({
      body: JSON.stringify(selected),
      contentType: "application/json",
      status: 200,
    });
  });

  return observations;
}
