import type { Page } from "@playwright/test";

type ConfigurationSnapshot = Record<string, unknown>;

const source = {
  baseRevisionToken: "A".repeat(43),
  configurationPath: "/srv/lego/.lego.yml",
  dotenvPaths: ["/srv/lego/cloudflare.env"],
  runtimeManifestId: "lego-v5.3.1",
};

export const readyConfiguration = {
  state: "ready",
  source,
  projection: [
    {
      fieldId: "account.eab_hmac",
      bindings: [{ id: "account", value: "home" }],
      label: "External account binding secret",
      kind: "secret",
      present: true,
      configured: true,
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

export const unsupportedConfiguration = {
  ...readyConfiguration,
  state: "unsupported",
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
  source,
  recovery: {
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
    recoveries: unknown[];
    saves: unknown[];
  } = {
    previews: [],
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
