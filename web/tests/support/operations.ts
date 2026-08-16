import type { Page } from "@playwright/test";

export const operationPolicy = {
  browserDisconnect: "continues",
  cancellation: "not_supported",
  retry: "manual_only",
  timeoutSeconds: 1800,
} as const;

export const disabledAutomaticSchedule = {
  state: "disabled",
  enabled: false,
  timeZone: null,
  localTime: null,
  nextEvaluationAt: null,
  lastTriggeredAt: null,
  reasonCode: "not_configured",
} as const;

export const manualOperationPreview = {
  state: "review_required",
  reviewedPreviewToken: "P".repeat(43),
  intent: {
    kind: "manual_workspace_run",
    workingDirectory: "/srv/lego",
    configurationPath: "/srv/lego/.lego.yml",
    storagePath: "/srv/lego/data",
    runtime: { identity: "v5.3.1", manifestId: "lego-v5.3.1" },
    certificates: [
      {
        name: "gateway",
        domains: ["gateway.home.example"],
        account: "primary",
        ca: "letsencrypt",
        challenge: {
          name: "http-home",
          kind: "http-01",
          mode: "listener",
        },
      },
      {
        name: "media",
        domains: ["media.home.example", "stream.home.example"],
        account: "primary",
        ca: "letsencrypt",
        challenge: {
          name: "http-webroot",
          kind: "http-01",
          mode: "webroot",
        },
      },
    ],
    cloudAccess: [],
    nativeEffects: [
      "acme_accounts_may_change",
      "certificate_artifacts_may_change",
      "native_configuration_backup_may_change",
      "external_acme_state_may_change",
    ],
  },
  policy: operationPolicy,
} as const;

export const queuedOperation = {
  id: "a".repeat(32),
  kind: "manual",
  state: "queued",
  phase: "queued",
  requestedAt: "2030-01-01T00:00:00Z",
  startedAt: null,
} as const;

export const runningOperation = {
  ...queuedOperation,
  state: "running",
  phase: "executing",
  startedAt: "2030-01-01T00:00:01Z",
} as const;

export const partialOperationResult = {
  id: queuedOperation.id,
  kind: "manual",
  state: "partial",
  reasonCode: "certificate_failed",
  requestedAt: queuedOperation.requestedAt,
  startedAt: "2030-01-01T00:00:01Z",
  finishedAt: "2030-01-01T00:02:00Z",
  mayHaveChanged: true,
  output: {
    text: "[stdout]\ngateway completed\n[stderr]\nmedia failed\n",
    truncated: false,
  },
  certificates: [
    { name: "gateway", state: "completed", reasonCode: "completed" },
    { name: "media", state: "failed", reasonCode: "upstream_failed" },
    {
      name: "router",
      state: "not_attempted",
      reasonCode: "upstream_stopped",
    },
  ],
  inventory: {
    state: "refreshed",
    certificateCount: 2,
    summary: "Native inventory was refreshed after the fail-fast run.",
  },
} as const;

export const successfulOperationResult = {
  ...partialOperationResult,
  state: "succeeded",
  reasonCode: "completed",
  mayHaveChanged: false,
  output: {
    text: "[stdout]\ncertificate evaluation completed\n",
    truncated: false,
  },
  certificates: [
    { name: "gateway", state: "completed", reasonCode: "completed" },
    { name: "media", state: "completed", reasonCode: "completed" },
  ],
} as const;

export const idleOperationClient = {
  getStatus: async () => ({ state: "idle" }) as const,
  getLatest: async () => ({ state: "empty" }) as const,
  getCancelPolicy: async () => operationPolicy,
  previewManual: async () => JSON.parse(JSON.stringify(manualOperationPreview)),
  enqueueManual: async () => queuedOperation,
  getAutomaticSchedule: async () => disabledAutomaticSchedule,
  updateAutomaticSchedule: async () => disabledAutomaticSchedule,
};

type OperationMockOptions = {
  initialStatus?: Record<string, unknown>;
  initialLatest?: Record<string, unknown>;
  preview?: Record<string, unknown>;
  enqueue?: Record<string, unknown>;
  enqueueFailure?: {
    code: "operation_active" | "operation_changed" | "service_unavailable";
    status: 409 | 503;
  };
  schedule?: Record<string, unknown>;
};

export async function mockOperations(
  page: Page,
  options: OperationMockOptions = {},
) {
  let status: Record<string, unknown> = options.initialStatus ?? {
    state: "idle",
  };
  let latest: Record<string, unknown> = options.initialLatest ?? {
    state: "empty",
  };
  let schedule: Record<string, unknown> =
    options.schedule ?? disabledAutomaticSchedule;
  const observations: {
    previews: unknown[];
    enqueues: unknown[];
    scheduleUpdates: unknown[];
    setActive(operation: Record<string, unknown>): void;
    complete(result: Record<string, unknown>): void;
  } = {
    previews: [],
    enqueues: [],
    scheduleUpdates: [],
    setActive(operation) {
      status = { state: "active", operation };
    },
    complete(result) {
      status = { state: "idle" };
      latest = { state: "available", result };
    },
  };

  await page.route("**/api/v1/automatic-schedule", async (route) => {
    if (route.request().method() === "GET") {
      await route.fulfill({
        body: JSON.stringify(schedule),
        contentType: "application/json",
        status: 200,
      });
      return;
    }
    if (route.request().method() === "PUT") {
      const update = route.request().postDataJSON() as Record<string, unknown>;
      observations.scheduleUpdates.push(update);
      schedule = {
        state: update.enabled ? "scheduled" : "disabled",
        enabled: update.enabled,
        timeZone: update.timeZone,
        localTime: update.localTime,
        nextEvaluationAt: update.enabled ? "2030-01-02T10:35:00Z" : null,
        lastTriggeredAt: null,
        reasonCode: update.enabled ? "schedule_saved" : "schedule_disabled",
      };
      await route.fulfill({
        body: JSON.stringify(schedule),
        contentType: "application/json",
        status: 200,
      });
      return;
    }
    await route.fulfill({ status: 405 });
  });

  await page.route("**/api/v1/operations/status", async (route) => {
    if (route.request().method() !== "GET") {
      await route.fulfill({ status: 405 });
      return;
    }
    await route.fulfill({
      body: JSON.stringify(status),
      contentType: "application/json",
      status: 200,
    });
  });

  await page.route("**/api/v1/operations/latest", async (route) => {
    if (route.request().method() !== "GET") {
      await route.fulfill({ status: 405 });
      return;
    }
    await route.fulfill({
      body: JSON.stringify(latest),
      contentType: "application/json",
      status: 200,
    });
  });

  await page.route("**/api/v1/operations/cancel-policy", async (route) => {
    if (route.request().method() !== "GET") {
      await route.fulfill({ status: 405 });
      return;
    }
    await route.fulfill({
      body: JSON.stringify({ policy: operationPolicy }),
      contentType: "application/json",
      status: 200,
    });
  });

  await page.route("**/api/v1/operations/manual/previews", async (route) => {
    if (route.request().method() !== "POST") {
      await route.fulfill({ status: 405 });
      return;
    }
    observations.previews.push(route.request().postDataJSON());
    await route.fulfill({
      body: JSON.stringify(options.preview ?? manualOperationPreview),
      contentType: "application/json",
      status: 200,
    });
  });

  await page.route("**/api/v1/operations/manual", async (route) => {
    if (route.request().method() !== "POST") {
      await route.fulfill({ status: 405 });
      return;
    }
    observations.enqueues.push(route.request().postDataJSON());
    if (options.enqueueFailure) {
      if (options.enqueueFailure.code === "operation_active") {
        status = { state: "active", operation: runningOperation };
      }
      await route.fulfill({
        body: JSON.stringify({
          error: {
            code: options.enqueueFailure.code,
            message: "Do not reflect this mock response.",
          },
        }),
        contentType: "application/json",
        status: options.enqueueFailure.status,
      });
      return;
    }
    const operation = options.enqueue ?? queuedOperation;
    status = { state: "active", operation };
    await route.fulfill({
      body: JSON.stringify({ operation }),
      contentType: "application/json",
      status: 202,
    });
  });

  return observations;
}
