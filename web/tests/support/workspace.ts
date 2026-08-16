import type { Page } from "@playwright/test";

type PathMetadata = {
  uid: number;
  gid: number;
  mode: string;
  nlink: number;
  device: string;
  inode: string;
  sizeBytes: number;
  modifiedAt: string;
  changedAt: string;
};

type PathEvidence = {
  configuredPath: string | null;
  canonicalPath: string | null;
  status: "available" | "missing" | "inaccessible" | "unsafe" | "unresolved";
  access: {
    readable: boolean;
    writable: boolean;
    searchable: boolean;
  };
  type:
    | "unknown"
    | "directory"
    | "regular_file"
    | "symlink"
    | "other"
    | "missing"
    | "unresolved";
  metadata: PathMetadata | null;
  components: Array<{
    path: string;
    type:
      | "unknown"
      | "directory"
      | "regular_file"
      | "symlink"
      | "other"
      | "missing";
    device: string;
    inode: string;
    mode: string;
    uid: number;
    gid: number;
    access: {
      readable: boolean;
      writable: boolean;
      searchable: boolean;
    };
  }>;
  safe: boolean;
};

type WorkspaceEvidence = {
  workingDirectory: PathEvidence;
  configuration: {
    source: "conventional_lego_yml" | "conventional_lego_yaml" | "explicit";
    path: PathEvidence;
  };
  storage: PathEvidence;
  dotenv: PathEvidence[];
  webroots: PathEvidence[];
};

type Diagnostic = {
  code: string;
  severity: "blocking" | "notice";
  role:
    | "working_directory"
    | "configuration"
    | "storage"
    | "dotenv"
    | "webroot"
    | "inventory"
    | "runtime"
    | "workspace";
  message: string;
  path: string | null;
  component: string | null;
};

type Certificate = {
  name: string;
  dnsNames: string[];
  issuer: string;
  expiresAt: string;
  health: "healthy" | "expiring" | "expired";
  artifact: {
    nativePath: string;
    uid: number;
    gid: number;
    mode: string;
    nlink: number;
    device: string;
    inode: string;
    sizeBytes: number;
    modifiedAt: string;
    changedAt: string;
  };
};

type WorkspaceSnapshot =
  | { state: "unadopted" }
  | {
      state:
        | "ready"
        | "changed"
        | "missing"
        | "read_only"
        | "unsafe"
        | "incompatible"
        | "inventory_unavailable";
      workspace?: WorkspaceEvidence;
      inventory: Certificate[];
      inventoryObservedAt: string | null;
      diagnostics: Diagnostic[];
    };

type WorkspaceCandidate = {
  state: "review_required";
  candidate: WorkspaceEvidence;
  reviewedEvidenceSha256: string;
  adoptable: boolean;
  diagnostics: Diagnostic[];
};

const metadata: PathMetadata = {
  uid: 991,
  gid: 991,
  mode: "0750",
  nlink: 2,
  device: "259",
  inode: "81234",
  sizeBytes: 4096,
  modifiedAt: "2030-01-01T00:00:00Z",
  changedAt: "2030-01-01T00:00:01Z",
};

function pathEvidence(
  configuredPath: string,
  canonicalPath: string,
  type: "directory" | "regular_file",
): PathEvidence {
  const componentPaths = [
    "/",
    ...canonicalPath
      .slice(1)
      .split("/")
      .map((_, index, parts) => `/${parts.slice(0, index + 1).join("/")}`),
  ];
  const finalMode = type === "regular_file" ? "0600" : "0750";
  const finalInode = String(81000 + componentPaths.length - 1);
  return {
    configuredPath,
    canonicalPath,
    status: "available",
    access: {
      readable: true,
      writable: true,
      searchable: type === "directory",
    },
    type,
    metadata: {
      ...metadata,
      mode: finalMode,
      nlink: type === "regular_file" ? 1 : metadata.nlink,
      inode: finalInode,
    },
    components: componentPaths.map((path, index) => ({
      path,
      type: index === componentPaths.length - 1 ? type : "directory",
      device: "259",
      inode: String(81000 + index),
      mode:
        index === 0
          ? "0755"
          : index === componentPaths.length - 1
            ? finalMode
            : "0750",
      uid: index === 0 ? 0 : 991,
      gid: index === 0 ? 0 : 991,
      access: {
        readable: true,
        writable: index !== 0,
        searchable: index !== componentPaths.length - 1 || type === "directory",
      },
    })),
    safe: true,
  };
}

export const workspaceEvidence: WorkspaceEvidence = {
  workingDirectory: pathEvidence("/srv/lego", "/srv/lego", "directory"),
  configuration: {
    source: "conventional_lego_yml",
    path: pathEvidence(
      "/srv/lego/.lego.yml",
      "/srv/lego/.lego.yml",
      "regular_file",
    ),
  },
  storage: pathEvidence("./data", "/srv/lego/data", "directory"),
  dotenv: [
    pathEvidence(
      "./cloudflare.env",
      "/srv/lego/cloudflare.env",
      "regular_file",
    ),
  ],
  webroots: [pathEvidence("./public", "/srv/lego/public", "directory")],
};

export const workspaceCertificate: Certificate = {
  name: "gateway.home.example",
  dnsNames: ["gateway.home.example", "home.example"],
  issuer: "Let's Encrypt Authority X3",
  expiresAt: "2030-03-31T12:30:00Z",
  health: "healthy",
  artifact: {
    nativePath: "/srv/lego/data/certificates/gateway.home.example.crt",
    ...metadata,
    mode: "0640",
    nlink: 1,
    sizeBytes: 2834,
  },
};

export const reviewedWorkspaceCandidate = {
  state: "review_required",
  candidate: workspaceEvidence,
  reviewedEvidenceSha256: "c".repeat(64),
  adoptable: true,
  diagnostics: [],
} as const satisfies WorkspaceCandidate;

export const readyWorkspace = {
  state: "ready",
  workspace: workspaceEvidence,
  inventory: [workspaceCertificate],
  inventoryObservedAt: "2030-01-01T00:00:00Z",
  diagnostics: [],
} as const satisfies WorkspaceSnapshot;

type WorkspaceMockOptions = {
  initial?: WorkspaceSnapshot;
  candidate?: WorkspaceCandidate;
  adopted?: WorkspaceSnapshot;
};

export async function mockWorkspace(
  page: Page,
  options: WorkspaceMockOptions = {},
) {
  let selected = options.initial ?? ({ state: "unadopted" } as const);
  const candidate = options.candidate ?? reviewedWorkspaceCandidate;
  const adopted = options.adopted ?? readyWorkspace;
  const observations: { inspections: unknown[]; adoptions: unknown[] } = {
    inspections: [],
    adoptions: [],
  };

  await page.route("**/api/v1/workspace", async (route) => {
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
      observations.adoptions.push(request.postDataJSON());
      selected = adopted;
      await route.fulfill({
        body: JSON.stringify(selected),
        contentType: "application/json",
        status: 200,
      });
      return;
    }
    await route.fulfill({ status: 405 });
  });

  await page.route("**/api/v1/workspace/candidates", async (route) => {
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
