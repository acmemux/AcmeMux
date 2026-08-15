import type { Page } from "@playwright/test";

type RuntimeEvidence = {
  canonicalPath: string;
  version: string | null;
  commit: string | null;
  versionOutput: string;
  platform: { os: string; architecture: string };
  metadata: {
    sizeBytes: number;
    modifiedAt: string;
    changedAt: string;
    mode: string;
    capabilities: "none" | "cap_net_bind_service=ep";
    uid: number;
    gid: number;
    device: string;
    inode: string;
  };
  build: {
    available: boolean;
    provenanceComplete: boolean;
    goVersion: string;
    commandPath: string;
    mainPath: string;
    mainVersion: string;
    dependencyGraphSha256: string;
    goos: string;
    goarch: string;
    vcsRevision: string;
    vcsModifiedKnown: boolean;
    vcsModifiedValid: boolean;
    vcsModified: boolean;
  };
  sha256: string;
};

type RuntimeCompatibility = {
  state: "supported" | "unverified" | "incompatible";
  code: string;
  manifestId?: string;
  summary: string;
};

type RuntimeSnapshot =
  | { state: "unselected" }
  | {
      state: "supported" | "unverified" | "incompatible";
      runtime: RuntimeEvidence;
      compatibility: RuntimeCompatibility;
    }
  | {
      state:
        "missing" | "unsafe" | "changed" | "malformed_output" | "timed_out";
      path: string;
      diagnostic: { code: string; message: string };
    };

type RuntimeCandidate =
  | {
      state: "review_required";
      candidate: RuntimeEvidence;
      compatibility: RuntimeCompatibility;
      reviewedEvidenceSha256?: string;
    }
  | {
      state: "missing" | "unsafe" | "malformed_output" | "timed_out";
      path: string;
      diagnostic: { code: string; message: string };
    };

export const runtimeEvidence: RuntimeEvidence = {
  canonicalPath: "/usr/local/bin/lego",
  version: "v5.3.1",
  commit: null,
  versionOutput: "lego version v5.3.1 linux/amd64",
  platform: { os: "linux", architecture: "amd64" },
  metadata: {
    sizeBytes: 24_001_024,
    modifiedAt: "2030-01-01T00:00:00Z",
    changedAt: "2030-01-01T00:00:01Z",
    mode: "0755",
    capabilities: "none",
    uid: 1000,
    gid: 1000,
    device: "259",
    inode: "123456",
  },
  build: {
    available: true,
    provenanceComplete: true,
    goVersion: "go1.26.6",
    commandPath: "github.com/go-acme/lego/v5",
    mainPath: "github.com/go-acme/lego/v5",
    mainVersion: "v5.3.1",
    dependencyGraphSha256: "d".repeat(64),
    goos: "linux",
    goarch: "amd64",
    vcsRevision: "589c84af4f26629fbdaa7fbca712f806632ccb7e",
    vcsModifiedKnown: true,
    vcsModifiedValid: true,
    vcsModified: false,
  },
  sha256: "a".repeat(64),
};

export const supportedRuntime: RuntimeSnapshot = {
  state: "supported",
  runtime: runtimeEvidence,
  compatibility: {
    state: "supported",
    code: "compatible",
    manifestId: "lego-v5.3.1",
    summary:
      "Exact release and platform match the qualified compatibility evidence.",
  },
};

export const supportedCandidate = {
  state: "review_required",
  candidate: runtimeEvidence,
  compatibility: {
    state: "supported",
    code: "compatible",
    manifestId: "lego-v5.3.1",
    summary:
      "Exact release and platform match the qualified compatibility evidence.",
  },
  reviewedEvidenceSha256: "b".repeat(64),
} as const satisfies RuntimeCandidate;

type RuntimeMockOptions = {
  initial?: RuntimeSnapshot;
  candidate?: RuntimeCandidate;
};

export async function mockRuntime(
  page: Page,
  options: RuntimeMockOptions = {},
) {
  let selected = options.initial ?? ({ state: "unselected" } as const);
  const candidate = options.candidate ?? supportedCandidate;
  const observations: { inspections: unknown[]; adoptions: unknown[] } = {
    inspections: [],
    adoptions: [],
  };

  await page.route("**/api/v1/runtime", async (route) => {
    const request = route.request();
    if (request.method() === "GET") {
      await route.fulfill({
        body: JSON.stringify(selected),
        contentType: "application/json",
        status: 200,
      });
      return;
    }
    if (request.method() === "PUT") {
      const body: unknown = request.postDataJSON();
      observations.adoptions.push(body);
      selected = supportedRuntime;
      await route.fulfill({
        body: JSON.stringify(selected),
        contentType: "application/json",
        status: 200,
      });
      return;
    }
    await route.fulfill({ status: 405 });
  });

  await page.route("**/api/v1/runtime/candidates", async (route) => {
    if (route.request().method() !== "POST") {
      await route.fulfill({ status: 405 });
      return;
    }
    observations.inspections.push(route.request().postDataJSON());
    await route.fulfill({
      body: JSON.stringify(candidate),
      contentType: "application/json",
      status: 200,
    });
  });

  return observations;
}
