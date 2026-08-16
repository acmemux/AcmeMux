import { CSRF_COOKIE_NAME, CSRF_HEADER_NAME } from "./session";

// Linux PATH_MAX includes the terminating NUL byte.
export const MAX_WORKSPACE_PATH_LENGTH = 4095;

export type WorkspacePathStatus =
  "available" | "missing" | "inaccessible" | "unsafe" | "unresolved";
export type WorkspacePathType =
  | "unknown"
  | "directory"
  | "regular_file"
  | "symlink"
  | "other"
  | "missing"
  | "unresolved";

export type WorkspaceAccessEvidence = {
  readable: boolean;
  writable: boolean;
  searchable: boolean;
};

export type WorkspaceComponentEvidence = {
  path: string;
  type:
    "unknown" | "directory" | "regular_file" | "symlink" | "other" | "missing";
  device: string;
  inode: string;
  mode: string;
  uid: number;
  gid: number;
  access: WorkspaceAccessEvidence;
};

export type WorkspacePathMetadata = {
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

export type WorkspacePathEvidence = {
  configuredPath: string | null;
  canonicalPath: string | null;
  status: WorkspacePathStatus;
  access: WorkspaceAccessEvidence;
  type: WorkspacePathType;
  metadata: WorkspacePathMetadata | null;
  components: WorkspaceComponentEvidence[];
  safe: boolean;
};

export type WorkspaceConfigurationSource =
  "conventional_lego_yml" | "conventional_lego_yaml" | "explicit";

export type WorkspaceEvidence = {
  workingDirectory: WorkspacePathEvidence;
  configuration: {
    source: WorkspaceConfigurationSource;
    path: WorkspacePathEvidence;
  };
  storage: WorkspacePathEvidence;
  dotenv: WorkspacePathEvidence[];
  webroots: WorkspacePathEvidence[];
};

export type WorkspaceDiagnosticCode =
  | "invalid_policy"
  | "context_required"
  | "path_required"
  | "path_not_absolute"
  | "path_not_canonical"
  | "path_too_long"
  | "path_too_deep"
  | "path_missing"
  | "path_unavailable"
  | "symlink_not_allowed"
  | "component_not_directory"
  | "path_type_unsafe"
  | "path_owner_untrusted"
  | "path_permissions_unsafe"
  | "path_hardlink_unsafe"
  | "path_not_readable"
  | "path_read_only"
  | "path_not_searchable"
  | "configuration_missing"
  | "configuration_precedence"
  | "configuration_too_large"
  | "configuration_malformed"
  | "configuration_duplicate_key"
  | "configuration_too_complex"
  | "configuration_reference_invalid"
  | "changed_during_inspection"
  | "inspection_canceled"
  | "review_evidence_limit"
  | "review_evidence_changed"
  | "not_directory"
  | "not_regular"
  | "untrusted_owner"
  | "unsafe_permissions"
  | "not_readable"
  | "hard_link_not_allowed"
  | "artifact_size_invalid"
  | "neutral_directory_not_private"
  | "neutral_configuration_present"
  | "tree_entry_limit"
  | "tree_depth_limit"
  | "certificate_limit"
  | "runtime_unavailable"
  | "inventory_busy"
  | "inventory_timeout"
  | "inventory_canceled"
  | "inventory_output_limit"
  | "inventory_command_failed"
  | "malformed_inventory_output"
  | "duplicate_inventory_entry"
  | "certificate_path_outside_storage"
  | "inventory_artifacts_changed"
  | "prepared_executable_close_failed"
  | "service_busy";

export type WorkspaceDiagnostic = {
  code: WorkspaceDiagnosticCode;
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

export type CertificateInventoryItem = {
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

export type WorkspaceAdoptedState =
  | "ready"
  | "changed"
  | "missing"
  | "read_only"
  | "unsafe"
  | "incompatible"
  | "inventory_unavailable";

export type WorkspaceSnapshot =
  | { state: "unadopted" }
  | {
      state: "ready";
      workspace: WorkspaceEvidence;
      inventory: CertificateInventoryItem[];
      inventoryObservedAt?: string;
      diagnostics: WorkspaceDiagnostic[];
    }
  | {
      state: "read_only" | "unsafe" | "incompatible" | "inventory_unavailable";
      workspace: WorkspaceEvidence;
      inventory: CertificateInventoryItem[];
      inventoryObservedAt?: null;
      diagnostics: WorkspaceDiagnostic[];
    }
  | {
      state: "changed" | "missing";
      workspace: WorkspaceEvidence;
      inventory: CertificateInventoryItem[];
      inventoryObservedAt?: null;
      diagnostics: WorkspaceDiagnostic[];
    };

export type WorkspaceCandidate = {
  state: "review_required";
  candidate: WorkspaceEvidence;
  reviewedEvidenceSha256: string;
  adoptable: boolean;
  diagnostics: WorkspaceDiagnostic[];
};

export type WorkspaceErrorCode =
  | "authentication_required"
  | "request_not_allowed"
  | "invalid_request"
  | "workspace_changed"
  | "recovery_required"
  | "service_busy"
  | "service_unavailable"
  | "invalid_response"
  | "network_failure";

export class WorkspaceRequestError extends Error {
  readonly code: WorkspaceErrorCode;
  readonly status: number;

  constructor(code: WorkspaceErrorCode, status: number) {
    super(workspaceErrorMessage(code));
    this.name = "WorkspaceRequestError";
    this.code = code;
    this.status = status;
  }
}

export interface WorkspaceClient {
  getWorkspace(): Promise<WorkspaceSnapshot>;
  inspectCandidate(
    workingDirectory: string,
    configurationPath: string | null,
  ): Promise<WorkspaceCandidate>;
  adoptCandidate(
    workingDirectory: string,
    configurationPath: string | null,
    reviewedEvidenceSha256: string,
  ): Promise<WorkspaceSnapshot | WorkspaceCandidate>;
}

type WorkspaceClientOptions = {
  fetch?: typeof globalThis.fetch;
  readCookies?: () => string;
};

const pathStatuses = new Set<WorkspacePathStatus>([
  "available",
  "missing",
  "inaccessible",
  "unsafe",
  "unresolved",
]);
const pathTypes = new Set<WorkspacePathType>([
  "unknown",
  "directory",
  "regular_file",
  "symlink",
  "other",
  "missing",
  "unresolved",
]);
const componentTypes = new Set<WorkspaceComponentEvidence["type"]>([
  "unknown",
  "directory",
  "regular_file",
  "symlink",
  "other",
  "missing",
]);
const configurationSources = new Set<WorkspaceConfigurationSource>([
  "conventional_lego_yml",
  "conventional_lego_yaml",
  "explicit",
]);
const adoptedStates = new Set<WorkspaceAdoptedState>([
  "ready",
  "changed",
  "missing",
  "read_only",
  "unsafe",
  "incompatible",
  "inventory_unavailable",
]);
const certificateHealthStates = new Set<CertificateInventoryItem["health"]>([
  "healthy",
  "expiring",
  "expired",
]);
const diagnosticCodes = new Set<WorkspaceDiagnosticCode>([
  "invalid_policy",
  "context_required",
  "path_required",
  "path_not_absolute",
  "path_not_canonical",
  "path_too_long",
  "path_too_deep",
  "path_missing",
  "path_unavailable",
  "symlink_not_allowed",
  "component_not_directory",
  "path_type_unsafe",
  "path_owner_untrusted",
  "path_permissions_unsafe",
  "path_hardlink_unsafe",
  "path_not_readable",
  "path_read_only",
  "path_not_searchable",
  "configuration_missing",
  "configuration_precedence",
  "configuration_too_large",
  "configuration_malformed",
  "configuration_duplicate_key",
  "configuration_too_complex",
  "configuration_reference_invalid",
  "changed_during_inspection",
  "inspection_canceled",
  "review_evidence_limit",
  "review_evidence_changed",
  "not_directory",
  "not_regular",
  "untrusted_owner",
  "unsafe_permissions",
  "not_readable",
  "hard_link_not_allowed",
  "artifact_size_invalid",
  "neutral_directory_not_private",
  "neutral_configuration_present",
  "tree_entry_limit",
  "tree_depth_limit",
  "certificate_limit",
  "runtime_unavailable",
  "inventory_busy",
  "inventory_timeout",
  "inventory_canceled",
  "inventory_output_limit",
  "inventory_command_failed",
  "malformed_inventory_output",
  "duplicate_inventory_entry",
  "certificate_path_outside_storage",
  "inventory_artifacts_changed",
  "prepared_executable_close_failed",
  "service_busy",
]);
const diagnosticRoles = new Set<WorkspaceDiagnostic["role"]>([
  "working_directory",
  "configuration",
  "storage",
  "dotenv",
  "webroot",
  "inventory",
  "runtime",
  "workspace",
]);
const workspaceInspectionDiagnosticRoles = new Set<WorkspaceDiagnostic["role"]>(
  [
    "working_directory",
    "configuration",
    "storage",
    "dotenv",
    "webroot",
    "workspace",
  ],
);
const inventoryDiagnosticCodes = new Set<WorkspaceDiagnosticCode>([
  "invalid_policy",
  "path_required",
  "path_not_absolute",
  "path_not_canonical",
  "path_too_long",
  "path_unavailable",
  "symlink_not_allowed",
  "not_directory",
  "not_regular",
  "untrusted_owner",
  "unsafe_permissions",
  "not_readable",
  "hard_link_not_allowed",
  "artifact_size_invalid",
  "neutral_directory_not_private",
  "neutral_configuration_present",
  "tree_entry_limit",
  "tree_depth_limit",
  "certificate_limit",
  "inventory_busy",
  "inventory_timeout",
  "inventory_canceled",
  "inventory_output_limit",
  "inventory_command_failed",
  "malformed_inventory_output",
  "duplicate_inventory_entry",
  "certificate_path_outside_storage",
  "inventory_artifacts_changed",
  "prepared_executable_close_failed",
]);
const workspaceInspectionDiagnosticCodes = new Set<WorkspaceDiagnosticCode>([
  "invalid_policy",
  "context_required",
  "path_required",
  "path_not_absolute",
  "path_not_canonical",
  "path_too_long",
  "path_too_deep",
  "path_missing",
  "path_unavailable",
  "symlink_not_allowed",
  "component_not_directory",
  "path_type_unsafe",
  "path_owner_untrusted",
  "path_permissions_unsafe",
  "path_hardlink_unsafe",
  "path_not_readable",
  "path_read_only",
  "path_not_searchable",
  "configuration_missing",
  "configuration_precedence",
  "configuration_too_large",
  "configuration_malformed",
  "configuration_duplicate_key",
  "configuration_too_complex",
  "configuration_reference_invalid",
  "changed_during_inspection",
  "inspection_canceled",
  "review_evidence_limit",
  "review_evidence_changed",
]);
const knownErrorCodes = new Set<WorkspaceErrorCode>([
  "authentication_required",
  "request_not_allowed",
  "invalid_request",
  "workspace_changed",
  "recovery_required",
  "service_busy",
  "service_unavailable",
]);
const digestPattern = /^[a-f0-9]{64}$/;
const modePattern = /^[0-7]{4}$/;
const numericIdentifierPattern = /^(?:0|[1-9][0-9]{0,19})$/;
const maximumUint32 = 0xffff_ffff;
const maximumUint64 = 0xffff_ffff_ffff_ffffn;
const maximumConfigurationSize = 8 * 1024 * 1024;
const maximumCertificateArtifactSize = 4 * 1024 * 1024;

function workspaceErrorMessage(code: WorkspaceErrorCode): string {
  switch (code) {
    case "authentication_required":
      return "The administrator session ended.";
    case "request_not_allowed":
      return "The protected workspace request was blocked.";
    case "invalid_request":
      return "The workspace request was invalid.";
    case "workspace_changed":
      return "The workspace changed after review.";
    case "recovery_required":
      return "Native configuration recovery must be resolved before changing the workspace.";
    case "service_busy":
      return "Another bounded workspace inspection is already running.";
    case "service_unavailable":
    case "network_failure":
      return "Workspace status is unavailable.";
    case "invalid_response":
      return "The workspace service returned an invalid response.";
  }
}

function invalidResponse(): never {
  throw new WorkspaceRequestError("invalid_response", 0);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const keys = Object.keys(value);
  const allowed = new Set([...required, ...optional]);
  return (
    required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) &&
    keys.every((key) => allowed.has(key))
  );
}

function boundedString(value: unknown, maximum = 4096): value is string {
  return (
    typeof value === "string" && value.length > 0 && value.length <= maximum
  );
}

function boundedDisplayText(
  value: unknown,
  maximumBytes: number,
): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    new TextEncoder().encode(value).length <= maximumBytes &&
    !containsControlCharacter(value)
  );
}

function safeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function uint32(value: unknown): value is number {
  return safeInteger(value) && value <= maximumUint32;
}

function uint64Identifier(value: unknown): value is string {
  return (
    typeof value === "string" &&
    numericIdentifierPattern.test(value) &&
    BigInt(value) <= maximumUint64
  );
}

function containsControlCharacter(value: string): boolean {
  return Array.from(value).some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint < 0x20 || codePoint === 0x7f;
  });
}

function validTimestamp(value: unknown): value is string {
  if (!boundedString(value, 64)) {
    return false;
  }
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/.exec(
      value,
    );
  if (!match) {
    return false;
  }
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const fractional = match[7];
  const leapYear = year % 400 === 0 || (year % 4 === 0 && year % 100 !== 0);
  const daysInMonth = [
    31,
    leapYear ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ];
  return (
    year >= 1 &&
    month >= 1 &&
    month <= 12 &&
    day >= 1 &&
    day <= (daysInMonth[month - 1] ?? 0) &&
    hour <= 23 &&
    minute <= 59 &&
    second <= 59 &&
    (fractional === undefined || !fractional.endsWith("0"))
  );
}

function validConfiguredPath(value: unknown): value is string {
  return (
    boundedString(value, MAX_WORKSPACE_PATH_LENGTH) &&
    new TextEncoder().encode(value).length <= MAX_WORKSPACE_PATH_LENGTH &&
    !containsControlCharacter(value)
  );
}

function validAbsolutePath(value: unknown): value is string {
  return validConfiguredPath(value) && value.startsWith("/");
}

function validCanonicalAbsolutePath(value: unknown): value is string {
  if (!validAbsolutePath(value)) {
    return false;
  }
  if (value === "/") {
    return true;
  }
  return (
    !value.endsWith("/") &&
    !value
      .slice(1)
      .split("/")
      .some(
        (component) =>
          component === "" || component === "." || component === "..",
      )
  );
}

function cleanLinuxPath(base: string, reference: string): string | null {
  if (!validCanonicalAbsolutePath(base) || !validConfiguredPath(reference)) {
    return null;
  }
  const source = reference.startsWith("/")
    ? reference
    : `${base === "/" ? "" : base}/${reference}`;
  const components: string[] = [];
  for (const component of source.split("/")) {
    if (component === "" || component === ".") {
      continue;
    }
    if (component === "..") {
      components.pop();
      continue;
    }
    components.push(component);
  }
  const resolved = `/${components.join("/")}`;
  return validCanonicalAbsolutePath(resolved) ? resolved : null;
}

function childLinuxPath(parent: string, child: string): string {
  return parent === "/" ? `/${child}` : `${parent}/${child}`;
}

function decodePathMetadata(value: unknown): WorkspacePathMetadata {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "uid",
      "gid",
      "mode",
      "nlink",
      "device",
      "inode",
      "sizeBytes",
      "modifiedAt",
      "changedAt",
    ]) ||
    !uint32(value.uid) ||
    !uint32(value.gid) ||
    typeof value.mode !== "string" ||
    !modePattern.test(value.mode) ||
    !safeInteger(value.nlink) ||
    value.nlink < 1 ||
    !uint64Identifier(value.device) ||
    !uint64Identifier(value.inode) ||
    !safeInteger(value.sizeBytes) ||
    !validTimestamp(value.modifiedAt) ||
    !validTimestamp(value.changedAt)
  ) {
    invalidResponse();
  }
  return {
    uid: value.uid,
    gid: value.gid,
    mode: value.mode,
    nlink: value.nlink,
    device: value.device,
    inode: value.inode,
    sizeBytes: value.sizeBytes,
    modifiedAt: value.modifiedAt,
    changedAt: value.changedAt,
  };
}

function decodeAccessEvidence(value: unknown): WorkspaceAccessEvidence {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["readable", "writable", "searchable"]) ||
    typeof value.readable !== "boolean" ||
    typeof value.writable !== "boolean" ||
    typeof value.searchable !== "boolean"
  ) {
    invalidResponse();
  }
  return {
    readable: value.readable,
    writable: value.writable,
    searchable: value.searchable,
  };
}

function decodeComponentEvidence(value: unknown): WorkspaceComponentEvidence {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "path",
      "type",
      "device",
      "inode",
      "mode",
      "uid",
      "gid",
      "access",
    ]) ||
    !validCanonicalAbsolutePath(value.path) ||
    !componentTypes.has(value.type as WorkspaceComponentEvidence["type"]) ||
    !uint64Identifier(value.device) ||
    !uint64Identifier(value.inode) ||
    typeof value.mode !== "string" ||
    !modePattern.test(value.mode) ||
    !uint32(value.uid) ||
    !uint32(value.gid)
  ) {
    invalidResponse();
  }
  return {
    path: value.path,
    type: value.type as WorkspaceComponentEvidence["type"],
    device: value.device,
    inode: value.inode,
    mode: value.mode,
    uid: value.uid,
    gid: value.gid,
    access: decodeAccessEvidence(value.access),
  };
}

function canonicalComponentPaths(path: string): string[] {
  if (path === "/") {
    return ["/"];
  }
  const parts = path.slice(1).split("/");
  return [
    "/",
    ...parts.map((_, index) => `/${parts.slice(0, index + 1).join("/")}`),
  ];
}

function componentMatchesMetadata(
  component: WorkspaceComponentEvidence,
  metadata: WorkspacePathMetadata,
): boolean {
  return (
    component.device === metadata.device &&
    component.inode === metadata.inode &&
    component.mode === metadata.mode &&
    component.uid === metadata.uid &&
    component.gid === metadata.gid
  );
}

function accessMatches(
  left: WorkspaceAccessEvidence,
  right: WorkspaceAccessEvidence,
): boolean {
  return (
    left.readable === right.readable &&
    left.writable === right.writable &&
    left.searchable === right.searchable
  );
}

function traversalRequirementsSatisfied(path: WorkspacePathEvidence): boolean {
  return path.components
    .slice(0, -1)
    .every(
      (component) =>
        component.type === "directory" && component.access.searchable,
    );
}

function safeRoleRequirementsSatisfied(
  path: WorkspacePathEvidence,
  role:
    "working_directory" | "configuration" | "storage" | "dotenv" | "webroot",
): boolean {
  if (!path.safe || !traversalRequirementsSatisfied(path)) {
    return false;
  }
  switch (role) {
    case "working_directory":
      return path.access.readable && path.access.searchable;
    case "configuration":
    case "dotenv": {
      const parent = path.components.at(-2);
      return (
        path.access.readable &&
        parent !== undefined &&
        parent.type === "directory" &&
        parent.access.writable &&
        parent.access.searchable
      );
    }
    case "storage":
      return (
        path.access.readable && path.access.writable && path.access.searchable
      );
    case "webroot":
      return path.access.writable && path.access.searchable;
  }
}

function modeValue(mode: string): number {
  return Number.parseInt(mode, 8);
}

function accessAgreesWithMode(
  component: WorkspaceComponentEvidence,
  rootUID: number,
  serviceUID: number,
): boolean {
  const mode = modeValue(component.mode);
  if (component.uid === serviceUID) {
    const owner = (mode >> 6) & 0o7;
    return accessMatches(component.access, {
      readable: (owner & 0o4) !== 0,
      writable: (owner & 0o2) !== 0,
      searchable: component.type === "directory" && (owner & 0o1) !== 0,
    });
  }
  if (component.uid !== rootUID) {
    return false;
  }
  const group = (mode >> 3) & 0o7;
  const other = mode & 0o7;
  return !(
    (component.access.readable && (group & 0o4) === 0 && (other & 0o4) === 0) ||
    (!component.access.readable && (other & 0o4) !== 0) ||
    (component.access.writable && (group & 0o2) === 0 && (other & 0o2) === 0) ||
    (!component.access.writable && (other & 0o2) !== 0) ||
    (component.access.searchable &&
      (group & 0o1) === 0 &&
      (other & 0o1) === 0) ||
    (!component.access.searchable &&
      component.type === "directory" &&
      (other & 0o1) !== 0)
  );
}

function safeComponentFactsSatisfied(
  component: WorkspaceComponentEvidence,
  final: boolean,
  rootUID: number,
  serviceUID: number,
): boolean {
  const mode = modeValue(component.mode);
  const rootStickyAncestor =
    !final && component.uid === rootUID && (mode & 0o1000) !== 0;
  return (
    (component.uid === rootUID || component.uid === serviceUID) &&
    ((mode & 0o022) === 0 || rootStickyAncestor) &&
    (mode & 0o6000) === 0 &&
    ((mode & 0o1000) === 0 || rootStickyAncestor) &&
    (component.type !== "directory" || component.access.searchable) &&
    (component.type !== "regular_file" || !component.access.searchable) &&
    accessAgreesWithMode(component, rootUID, serviceUID)
  );
}

function sameRootComponent(
  left: WorkspaceComponentEvidence,
  right: WorkspaceComponentEvidence,
): boolean {
  return (
    left.path === right.path &&
    left.type === right.type &&
    left.device === right.device &&
    left.inode === right.inode &&
    left.mode === right.mode &&
    left.uid === right.uid &&
    left.gid === right.gid &&
    accessMatches(left.access, right.access)
  );
}

function safeWorkspaceFactsSatisfied(evidence: WorkspaceEvidence): boolean {
  const paths = allWorkspacePaths(evidence);
  if (!paths.every((path) => path.safe)) {
    return true;
  }
  const root = evidence.workingDirectory.components[0];
  const configurationMetadata = evidence.configuration.path.metadata;
  if (root === undefined || configurationMetadata === null) {
    return false;
  }
  const rootUID = root.uid;
  const serviceUID = configurationMetadata.uid;
  if (rootUID === serviceUID) {
    return false;
  }
  if (
    !paths.every((path) => {
      const pathRoot = path.components[0];
      return (
        pathRoot !== undefined &&
        sameRootComponent(root, pathRoot) &&
        path.components.every((component, index) =>
          safeComponentFactsSatisfied(
            component,
            index === path.components.length - 1,
            rootUID,
            serviceUID,
          ),
        )
      );
    })
  ) {
    return false;
  }
  const confidential = [evidence.configuration.path, ...evidence.dotenv];
  return (
    configurationMetadata.sizeBytes > 0 &&
    configurationMetadata.sizeBytes <= maximumConfigurationSize &&
    confidential.every((path) => {
      const metadata = path.metadata;
      return (
        metadata !== null &&
        metadata.uid === serviceUID &&
        metadata.nlink === 1 &&
        (modeValue(metadata.mode) & 0o077) === 0
      );
    })
  );
}

function referencesInCanonicalOrder(paths: WorkspacePathEvidence[]): boolean {
  return paths.every((path, index) => {
    if (index === 0) {
      return true;
    }
    const previous = paths[index - 1];
    if (
      previous?.canonicalPath === null ||
      previous?.canonicalPath === undefined ||
      previous.configuredPath === null ||
      path.canonicalPath === null ||
      path.configuredPath === null
    ) {
      return true;
    }
    return (
      previous.canonicalPath < path.canonicalPath ||
      (previous.canonicalPath === path.canonicalPath &&
        previous.configuredPath <= path.configuredPath)
    );
  });
}

function decodePathEvidence(value: unknown): WorkspacePathEvidence {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "configuredPath",
      "canonicalPath",
      "status",
      "access",
      "type",
      "metadata",
      "components",
      "safe",
    ]) ||
    (value.configuredPath !== null &&
      !validConfiguredPath(value.configuredPath)) ||
    (value.canonicalPath !== null &&
      !validCanonicalAbsolutePath(value.canonicalPath)) ||
    !pathStatuses.has(value.status as WorkspacePathStatus) ||
    !pathTypes.has(value.type as WorkspacePathType) ||
    (value.metadata !== null && !isRecord(value.metadata)) ||
    !Array.isArray(value.components) ||
    value.components.length > 64 ||
    typeof value.safe !== "boolean"
  ) {
    invalidResponse();
  }

  const status = value.status as WorkspacePathStatus;
  const access = decodeAccessEvidence(value.access);
  const type = value.type as WorkspacePathType;
  const metadata =
    value.metadata === null ? null : decodePathMetadata(value.metadata);
  const components = value.components.map(decodeComponentEvidence);
  const componentPathBytes = components.reduce(
    (total, component) =>
      total + new TextEncoder().encode(component.path).length,
    0,
  );
  const expectedComponents =
    value.canonicalPath === null
      ? []
      : canonicalComponentPaths(value.canonicalPath);
  const componentOrderValid = components.every(
    (component, index) => component.path === expectedComponents[index],
  );
  const finalComponent = components.at(-1);
  if (
    (status === "available" &&
      (value.canonicalPath === null ||
        type === "missing" ||
        metadata === null)) ||
    (status === "missing" &&
      (type !== "missing" ||
        access.readable ||
        access.writable ||
        access.searchable ||
        metadata !== null ||
        value.safe)) ||
    (status === "unresolved" &&
      (value.configuredPath !== null ||
        value.canonicalPath !== null ||
        type !== "unresolved" ||
        access.readable ||
        access.writable ||
        access.searchable ||
        metadata !== null ||
        components.length !== 0 ||
        value.safe)) ||
    (status !== "unresolved" &&
      (value.configuredPath === null || value.canonicalPath === null)) ||
    (type === "unresolved" && status !== "unresolved") ||
    (type === "missing" && status !== "missing") ||
    (status === "available") !== value.safe ||
    new Set(components.map((component) => component.path)).size !==
      components.length ||
    componentPathBytes > 32 * 1024 ||
    !componentOrderValid ||
    components.length > expectedComponents.length ||
    (metadata !== null &&
      (components.length !== expectedComponents.length ||
        finalComponent === undefined ||
        finalComponent.path !== value.canonicalPath ||
        finalComponent.type !== type ||
        !accessMatches(finalComponent.access, access) ||
        !componentMatchesMetadata(finalComponent, metadata)))
  ) {
    invalidResponse();
  }

  return {
    configuredPath: value.configuredPath,
    canonicalPath: value.canonicalPath,
    status,
    access,
    type,
    metadata,
    components,
    safe: value.safe,
  };
}

function decodeWorkspaceEvidence(value: unknown): WorkspaceEvidence {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "workingDirectory",
      "configuration",
      "storage",
      "dotenv",
      "webroots",
    ]) ||
    !isRecord(value.configuration) ||
    !hasExactKeys(value.configuration, ["source", "path"]) ||
    !configurationSources.has(
      value.configuration.source as WorkspaceConfigurationSource,
    ) ||
    !Array.isArray(value.dotenv) ||
    value.dotenv.length > 256 ||
    !Array.isArray(value.webroots) ||
    value.webroots.length > 128 ||
    value.dotenv.length + value.webroots.length > 128
  ) {
    invalidResponse();
  }
  const workingDirectory = decodePathEvidence(value.workingDirectory);
  const configurationPath = decodePathEvidence(value.configuration.path);
  const storage = decodePathEvidence(value.storage);
  const dotenv = value.dotenv.map(decodePathEvidence);
  const webroots = value.webroots.map(decodePathEvidence);
  const workingCanonical = workingDirectory.canonicalPath;
  const configurationCanonical = configurationPath.canonicalPath;
  const source = value.configuration.source as WorkspaceConfigurationSource;
  const selectedPathsAgree =
    workingCanonical !== null &&
    workingDirectory.configuredPath === workingCanonical &&
    configurationCanonical !== null &&
    configurationPath.configuredPath === configurationCanonical;
  const configurationSourceAgrees =
    selectedPathsAgree &&
    (source === "explicit" ||
      configurationCanonical ===
        childLinuxPath(
          workingCanonical,
          source === "conventional_lego_yml" ? ".lego.yml" : ".lego.yaml",
        ));
  const referenceAgrees = (path: WorkspacePathEvidence): boolean =>
    path.status === "unresolved" ||
    (path.configuredPath !== null &&
      path.canonicalPath !== null &&
      cleanLinuxPath(workingCanonical ?? "", path.configuredPath) ===
        path.canonicalPath);
  if (
    !configurationSourceAgrees ||
    !referenceAgrees(storage) ||
    dotenv.some((path) => !referenceAgrees(path)) ||
    webroots.some((path) => !referenceAgrees(path)) ||
    workingDirectory.status === "unresolved" ||
    configurationPath.status === "unresolved" ||
    dotenv.some((path) => path.status === "unresolved") ||
    webroots.some((path) => path.status === "unresolved") ||
    (workingDirectory.safe &&
      (workingDirectory.type !== "directory" ||
        !safeRoleRequirementsSatisfied(
          workingDirectory,
          "working_directory",
        ))) ||
    (configurationPath.safe &&
      (configurationPath.type !== "regular_file" ||
        !safeRoleRequirementsSatisfied(configurationPath, "configuration"))) ||
    (storage.safe &&
      (storage.type !== "directory" ||
        !safeRoleRequirementsSatisfied(storage, "storage"))) ||
    dotenv.some(
      (path) =>
        path.safe &&
        (path.type !== "regular_file" ||
          !safeRoleRequirementsSatisfied(path, "dotenv")),
    ) ||
    webroots.some(
      (path) =>
        path.safe &&
        (path.type !== "directory" ||
          !safeRoleRequirementsSatisfied(path, "webroot")),
    ) ||
    !referencesInCanonicalOrder(dotenv) ||
    !referencesInCanonicalOrder(webroots) ||
    !safeWorkspaceFactsSatisfied({
      workingDirectory,
      configuration: { source, path: configurationPath },
      storage,
      dotenv,
      webroots,
    })
  ) {
    invalidResponse();
  }
  return {
    workingDirectory,
    configuration: {
      source: value.configuration.source as WorkspaceConfigurationSource,
      path: configurationPath,
    },
    storage,
    dotenv,
    webroots,
  };
}

function allWorkspacePaths(
  evidence: WorkspaceEvidence,
): WorkspacePathEvidence[] {
  return [
    evidence.workingDirectory,
    evidence.configuration.path,
    evidence.storage,
    ...evidence.dotenv,
    ...evidence.webroots,
  ];
}

function workspaceEvidenceIsAdoptable(evidence: WorkspaceEvidence): boolean {
  return allWorkspacePaths(evidence).every((path) => path.safe);
}

function pathsForDiagnosticRole(
  evidence: WorkspaceEvidence,
  role: WorkspaceDiagnostic["role"],
): WorkspacePathEvidence[] {
  switch (role) {
    case "working_directory":
      return [evidence.workingDirectory];
    case "configuration":
      return [evidence.configuration.path];
    case "storage":
      return [evidence.storage];
    case "dotenv":
      return evidence.dotenv;
    case "webroot":
      return evidence.webroots;
    case "inventory":
    case "runtime":
    case "workspace":
      return [];
  }
}

function diagnosticMatchesPath(
  diagnostic: WorkspaceDiagnostic,
  evidence: WorkspaceEvidence,
  predicate: (path: WorkspacePathEvidence) => boolean,
): boolean {
  return pathsForDiagnosticRole(evidence, diagnostic.role).some(
    (path) =>
      path.canonicalPath !== null &&
      diagnostic.path === path.canonicalPath &&
      predicate(path),
  );
}

function readOnlyEvidenceMatchesRole(
  role: WorkspaceDiagnostic["role"],
  path: WorkspacePathEvidence,
): boolean {
  if (path.safe) {
    return false;
  }
  switch (role) {
    case "storage":
    case "webroot":
      return !path.access.writable;
    case "configuration":
    case "dotenv": {
      const parent = path.components.at(-2);
      return parent === undefined || !parent.access.writable;
    }
    case "working_directory":
    case "inventory":
    case "runtime":
    case "workspace":
      return false;
  }
}

function snapshotEvidenceMatchesState(
  state: WorkspaceAdoptedState,
  diagnostics: WorkspaceDiagnostic[],
  evidence: WorkspaceEvidence,
): boolean {
  const blocking = diagnostics.filter(
    (diagnostic) => diagnostic.severity === "blocking",
  );
  const hasMissingEvidence = allWorkspacePaths(evidence).some(
    (path) => path.status === "missing" || path.type === "missing",
  );
  const hasReadOnlyEvidence = (
    [
      "configuration",
      "storage",
      "dotenv",
      "webroot",
    ] as const satisfies readonly WorkspaceDiagnostic["role"][]
  ).some((role) =>
    pathsForDiagnosticRole(evidence, role).some((path) =>
      readOnlyEvidenceMatchesRole(role, path),
    ),
  );
  if (state === "missing") {
    return blocking.some(
      (diagnostic) =>
        (diagnostic.code === "path_missing" ||
          diagnostic.code === "configuration_missing") &&
        diagnosticMatchesPath(
          diagnostic,
          evidence,
          (path) => path.status === "missing" && path.type === "missing",
        ),
    );
  }
  if (state === "read_only") {
    return (
      !hasMissingEvidence &&
      blocking.some(
        (diagnostic) =>
          diagnostic.code === "path_read_only" &&
          diagnosticMatchesPath(diagnostic, evidence, (path) =>
            readOnlyEvidenceMatchesRole(diagnostic.role, path),
          ),
      )
    );
  }
  if (state === "unsafe") {
    return !hasMissingEvidence && !hasReadOnlyEvidence;
  }
  return true;
}

function diagnosticsMatchEvidence(
  diagnostics: WorkspaceDiagnostic[],
  evidence: WorkspaceEvidence,
): boolean {
  const precedence = diagnostics.filter(
    (diagnostic) => diagnostic.code === "configuration_precedence",
  );
  if (precedence.length === 0) {
    return true;
  }
  const workingDirectory = evidence.workingDirectory.canonicalPath;
  const configuration = evidence.configuration.path.canonicalPath;
  const diagnostic = precedence[0];
  return (
    precedence.length === 1 &&
    evidence.configuration.source === "conventional_lego_yml" &&
    workingDirectory !== null &&
    configuration !== null &&
    diagnostic?.path === configuration &&
    diagnostic.component === childLinuxPath(workingDirectory, ".lego.yaml")
  );
}

function decodeDiagnostic(value: unknown): WorkspaceDiagnostic {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "code",
      "severity",
      "role",
      "message",
      "path",
      "component",
    ]) ||
    !diagnosticCodes.has(value.code as WorkspaceDiagnosticCode) ||
    (value.severity !== "blocking" && value.severity !== "notice") ||
    !diagnosticRoles.has(value.role as WorkspaceDiagnostic["role"]) ||
    !boundedString(value.message, 1024) ||
    (value.path !== null && !validCanonicalAbsolutePath(value.path)) ||
    (value.component !== null &&
      !validCanonicalAbsolutePath(value.component)) ||
    (value.code === "configuration_precedence") !==
      (value.severity === "notice") ||
    (value.code === "configuration_precedence" &&
      value.role !== "configuration")
  ) {
    invalidResponse();
  }
  return {
    code: value.code as WorkspaceDiagnosticCode,
    severity: value.severity,
    role: value.role as WorkspaceDiagnostic["role"],
    message: value.message,
    path: value.path,
    component: value.component,
  };
}

function decodeDiagnostics(value: unknown): WorkspaceDiagnostic[] {
  if (!Array.isArray(value) || value.length > 256) {
    invalidResponse();
  }
  return value.map(decodeDiagnostic);
}

function diagnosticsMatchSnapshotState(
  state: WorkspaceAdoptedState,
  diagnostics: WorkspaceDiagnostic[],
): boolean {
  const blocking = diagnostics.filter(
    (diagnostic) => diagnostic.severity === "blocking",
  );
  const hasReviewChange = blocking.some(
    (diagnostic) =>
      diagnostic.code === "review_evidence_changed" &&
      diagnostic.role === "workspace",
  );
  const hasOnlyWorkspaceBlockers = blocking.every(
    (diagnostic) =>
      workspaceInspectionDiagnosticCodes.has(diagnostic.code) &&
      workspaceInspectionDiagnosticRoles.has(diagnostic.role),
  );
  switch (state) {
    case "ready":
      return blocking.length === 0;
    case "incompatible":
      return (
        blocking.length === 1 &&
        blocking[0]?.role === "runtime" &&
        (blocking[0].code === "runtime_unavailable" ||
          blocking[0].code === "service_busy")
      );
    case "inventory_unavailable":
      return (
        blocking.length === 1 &&
        blocking[0]?.role === "inventory" &&
        inventoryDiagnosticCodes.has(blocking[0].code)
      );
    case "changed":
      return (
        hasOnlyWorkspaceBlockers && hasReviewChange && blocking.length === 1
      );
    case "missing":
      return (
        hasOnlyWorkspaceBlockers &&
        hasReviewChange &&
        blocking.some(
          (diagnostic) =>
            diagnostic.code === "path_missing" ||
            diagnostic.code === "configuration_missing",
        )
      );
    case "read_only":
      return (
        hasOnlyWorkspaceBlockers &&
        hasReviewChange &&
        !blocking.some(
          (diagnostic) =>
            diagnostic.code === "path_missing" ||
            diagnostic.code === "configuration_missing",
        ) &&
        blocking.some((diagnostic) => diagnostic.code === "path_read_only")
      );
    case "unsafe":
      return (
        hasOnlyWorkspaceBlockers &&
        hasReviewChange &&
        blocking.length > 1 &&
        !blocking.some(
          (diagnostic) =>
            diagnostic.code === "path_missing" ||
            diagnostic.code === "configuration_missing" ||
            diagnostic.code === "path_read_only",
        )
      );
  }
}

function decodeArtifact(value: unknown): CertificateInventoryItem["artifact"] {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "nativePath",
      "uid",
      "gid",
      "mode",
      "nlink",
      "device",
      "inode",
      "sizeBytes",
      "modifiedAt",
      "changedAt",
    ]) ||
    !validCanonicalAbsolutePath(value.nativePath) ||
    !uint32(value.uid) ||
    !uint32(value.gid) ||
    typeof value.mode !== "string" ||
    !modePattern.test(value.mode) ||
    value.nlink !== 1 ||
    !uint64Identifier(value.device) ||
    !uint64Identifier(value.inode) ||
    !safeInteger(value.sizeBytes) ||
    value.sizeBytes < 1 ||
    value.sizeBytes > maximumCertificateArtifactSize ||
    (modeValue(value.mode) & 0o7022) !== 0 ||
    !validTimestamp(value.modifiedAt) ||
    !validTimestamp(value.changedAt)
  ) {
    invalidResponse();
  }
  return {
    nativePath: value.nativePath,
    uid: value.uid,
    gid: value.gid,
    mode: value.mode,
    nlink: value.nlink,
    device: value.device,
    inode: value.inode,
    sizeBytes: value.sizeBytes,
    modifiedAt: value.modifiedAt,
    changedAt: value.changedAt,
  };
}

function decodeCertificate(value: unknown): CertificateInventoryItem {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "name",
      "dnsNames",
      "issuer",
      "expiresAt",
      "health",
      "artifact",
    ]) ||
    !boundedDisplayText(value.name, 255) ||
    !Array.isArray(value.dnsNames) ||
    value.dnsNames.length > 100 ||
    !value.dnsNames.every((name) => boundedDisplayText(name, 253)) ||
    new Set(value.dnsNames).size !== value.dnsNames.length ||
    !boundedDisplayText(value.issuer, 4096) ||
    !validTimestamp(value.expiresAt) ||
    !certificateHealthStates.has(
      value.health as CertificateInventoryItem["health"],
    )
  ) {
    invalidResponse();
  }
  return {
    name: value.name,
    dnsNames: [...value.dnsNames] as string[],
    issuer: value.issuer,
    expiresAt: value.expiresAt,
    health: value.health as CertificateInventoryItem["health"],
    artifact: decodeArtifact(value.artifact),
  };
}

function decodeInventory(value: unknown): CertificateInventoryItem[] {
  if (!Array.isArray(value) || value.length > 10_000) {
    invalidResponse();
  }
  const inventory = value.map(decodeCertificate);
  if (new Set(inventory.map((item) => item.name)).size !== inventory.length) {
    invalidResponse();
  }
  return inventory;
}

function inventoryMatchesWorkspace(
  inventory: CertificateInventoryItem[],
  workspace: WorkspaceEvidence,
): boolean {
  const storage = workspace.storage.canonicalPath;
  if (storage === null) {
    return false;
  }
  const certificateDirectory = childLinuxPath(storage, "certificates");
  const rootUID = workspace.workingDirectory.components[0]?.uid;
  const serviceUID = workspace.configuration.path.metadata?.uid;
  if (rootUID === undefined || serviceUID === undefined) {
    return false;
  }
  return (
    new Set(inventory.map((item) => item.artifact.nativePath)).size ===
      inventory.length &&
    inventory.every((item) => {
      const mode = modeValue(item.artifact.mode);
      const readable =
        item.artifact.uid === serviceUID
          ? (mode & 0o400) !== 0
          : item.artifact.uid === rootUID && (mode & 0o044) !== 0;
      return (
        !item.name.includes("/") &&
        readable &&
        item.artifact.nativePath.startsWith(`${certificateDirectory}/`) &&
        item.artifact.nativePath.split("/").at(-1) === `${item.name}.crt`
      );
    })
  );
}

function decodeSnapshot(value: unknown): WorkspaceSnapshot {
  if (!isRecord(value) || typeof value.state !== "string") {
    invalidResponse();
  }
  if (value.state === "unadopted") {
    if (!hasExactKeys(value, ["state"])) {
      invalidResponse();
    }
    return { state: "unadopted" };
  }
  if (!adoptedStates.has(value.state as WorkspaceAdoptedState)) {
    invalidResponse();
  }
  const state = value.state as WorkspaceAdoptedState;
  if (
    !hasExactKeys(
      value,
      ["state", "workspace", "inventory", "diagnostics"],
      ["inventoryObservedAt"],
    )
  ) {
    invalidResponse();
  }
  const diagnostics = decodeDiagnostics(value.diagnostics);
  if (!diagnosticsMatchSnapshotState(state, diagnostics)) {
    invalidResponse();
  }
  const inventory = decodeInventory(value.inventory);
  if (
    (state === "ready" &&
      value.inventoryObservedAt !== undefined &&
      !validTimestamp(value.inventoryObservedAt)) ||
    (state !== "ready" &&
      value.inventoryObservedAt !== undefined &&
      value.inventoryObservedAt !== null) ||
    (state !== "ready" && inventory.length !== 0)
  ) {
    invalidResponse();
  }
  const workspace = decodeWorkspaceEvidence(value.workspace);
  if (!diagnosticsMatchEvidence(diagnostics, workspace)) {
    invalidResponse();
  }
  if (!snapshotEvidenceMatchesState(state, diagnostics, workspace)) {
    invalidResponse();
  }
  const evidenceAdoptable = workspaceEvidenceIsAdoptable(workspace);
  if (
    ((state === "ready" ||
      state === "changed" ||
      state === "inventory_unavailable" ||
      state === "incompatible") &&
      !evidenceAdoptable) ||
    ((state === "missing" || state === "read_only" || state === "unsafe") &&
      evidenceAdoptable)
  ) {
    invalidResponse();
  }
  if (state === "ready" && !inventoryMatchesWorkspace(inventory, workspace)) {
    invalidResponse();
  }
  if (state === "ready") {
    return {
      state,
      workspace,
      inventory,
      ...(value.inventoryObservedAt === undefined
        ? {}
        : { inventoryObservedAt: value.inventoryObservedAt as string }),
      diagnostics,
    };
  }
  return {
    state,
    workspace,
    inventory,
    ...(value.inventoryObservedAt === undefined
      ? {}
      : { inventoryObservedAt: null }),
    diagnostics,
  };
}

function decodeCandidate(
  value: unknown,
  allowInventoryDiagnostic = false,
): WorkspaceCandidate {
  if (
    !isRecord(value) ||
    value.state !== "review_required" ||
    !hasExactKeys(value, [
      "state",
      "candidate",
      "reviewedEvidenceSha256",
      "adoptable",
      "diagnostics",
    ]) ||
    typeof value.reviewedEvidenceSha256 !== "string" ||
    !digestPattern.test(value.reviewedEvidenceSha256) ||
    typeof value.adoptable !== "boolean"
  ) {
    invalidResponse();
  }
  const diagnostics = decodeDiagnostics(value.diagnostics);
  const candidate = decodeWorkspaceEvidence(value.candidate);
  if (!diagnosticsMatchEvidence(diagnostics, candidate)) {
    invalidResponse();
  }
  const containsBlockingDiagnostic = diagnostics.some(
    (diagnostic) => diagnostic.severity === "blocking",
  );
  if (
    diagnostics.some((diagnostic) =>
      diagnostic.role === "inventory"
        ? !allowInventoryDiagnostic ||
          !inventoryDiagnosticCodes.has(diagnostic.code)
        : !workspaceInspectionDiagnosticRoles.has(diagnostic.role) ||
          !workspaceInspectionDiagnosticCodes.has(diagnostic.code),
    ) ||
    (!value.adoptable && !containsBlockingDiagnostic) ||
    value.adoptable !==
      (workspaceEvidenceIsAdoptable(candidate) && !containsBlockingDiagnostic)
  ) {
    invalidResponse();
  }
  return {
    state: "review_required",
    candidate,
    reviewedEvidenceSha256: value.reviewedEvidenceSha256,
    adoptable: value.adoptable,
    diagnostics,
  };
}

function decodeAdoption(
  value: unknown,
): WorkspaceSnapshot | WorkspaceCandidate {
  if (isRecord(value) && value.state === "review_required") {
    return decodeCandidate(value, true);
  }
  return decodeSnapshot(value);
}

function evidenceMatchesRequestedSelection(
  evidence: WorkspaceEvidence,
  workingDirectory: string,
  configurationPath: string | null,
): boolean {
  return (
    evidence.workingDirectory.configuredPath === workingDirectory &&
    evidence.workingDirectory.canonicalPath === workingDirectory &&
    (configurationPath === null
      ? evidence.configuration.source !== "explicit"
      : evidence.configuration.source === "explicit" &&
        evidence.configuration.path.configuredPath === configurationPath &&
        evidence.configuration.path.canonicalPath === configurationPath)
  );
}

function resultEvidence(
  result: WorkspaceSnapshot | WorkspaceCandidate,
): WorkspaceEvidence | null {
  if (result.state === "review_required") {
    return result.candidate;
  }
  return result.state === "unadopted" ? null : result.workspace;
}

function isJSONContentType(value: string): boolean {
  return value.split(";", 1)[0]?.trim().toLowerCase() === "application/json";
}

async function readJSON(response: Response): Promise<unknown> {
  if (!isJSONContentType(response.headers.get("content-type") ?? "")) {
    throw new WorkspaceRequestError("invalid_response", response.status);
  }
  try {
    return await response.json();
  } catch {
    throw new WorkspaceRequestError("invalid_response", response.status);
  }
}

function readCookie(name: string, source: string): string | undefined {
  const prefix = `${encodeURIComponent(name)}=`;
  for (const segment of source.split(";")) {
    const candidate = segment.trim();
    if (!candidate.startsWith(prefix)) {
      continue;
    }
    try {
      return decodeURIComponent(candidate.slice(prefix.length));
    } catch {
      return undefined;
    }
  }
  return undefined;
}

function fallbackCode(status: number): WorkspaceErrorCode {
  switch (status) {
    case 400:
    case 413:
    case 415:
      return "invalid_request";
    case 401:
      return "authentication_required";
    case 403:
    case 421:
      return "request_not_allowed";
    case 409:
      return "workspace_changed";
    case 429:
      return "service_busy";
    case 503:
      return "service_unavailable";
    default:
      return "invalid_response";
  }
}

async function responseError(
  response: Response,
): Promise<WorkspaceRequestError> {
  if (response.status === 401) {
    return new WorkspaceRequestError("authentication_required", 401);
  }
  if (response.status === 403 || response.status === 421) {
    return new WorkspaceRequestError("request_not_allowed", response.status);
  }
  let code = fallbackCode(response.status);
  if (isJSONContentType(response.headers.get("content-type") ?? "")) {
    try {
      const value: unknown = await response.json();
      if (
        isRecord(value) &&
        hasExactKeys(value, ["error"]) &&
        isRecord(value.error) &&
        hasExactKeys(value.error, ["code", "message"]) &&
        typeof value.error.code === "string" &&
        knownErrorCodes.has(value.error.code as WorkspaceErrorCode) &&
        boundedString(value.error.message, 1024)
      ) {
        const presented = value.error.code as WorkspaceErrorCode;
        if (
          presented !== "authentication_required" &&
          presented !== "request_not_allowed"
        ) {
          code = presented;
        }
      }
    } catch {
      // Error bodies are deliberately neither retained nor rendered.
    }
  }
  return new WorkspaceRequestError(code, response.status);
}

export function workspacePathError(
  path: string,
  label: "working directory" | "configuration path",
  optional = false,
): string | undefined {
  if (path.length === 0) {
    return optional
      ? undefined
      : `Enter the absolute effective ${label} on this host.`;
  }
  if (new TextEncoder().encode(path).length > MAX_WORKSPACE_PATH_LENGTH) {
    return `The ${label} must be ${MAX_WORKSPACE_PATH_LENGTH.toLocaleString("en-US")} UTF-8 bytes or fewer.`;
  }
  if (!path.startsWith("/")) {
    return `Enter an absolute Linux ${label} beginning with /.`;
  }
  if (containsControlCharacter(path)) {
    return `The ${label} cannot contain control characters.`;
  }
  if (!validCanonicalAbsolutePath(path)) {
    return `Enter a canonical ${label} without repeated separators, dot components, or a trailing slash.`;
  }
  return undefined;
}

function validateSelection(
  workingDirectory: string,
  configurationPath: string | null,
): void {
  if (
    workspacePathError(workingDirectory, "working directory") ||
    (configurationPath !== null &&
      workspacePathError(configurationPath, "configuration path"))
  ) {
    throw new WorkspaceRequestError("invalid_request", 0);
  }
}

export function createWorkspaceClient(
  options: WorkspaceClientOptions = {},
): WorkspaceClient {
  const request =
    options.fetch ??
    ((input: RequestInfo | URL, init?: RequestInit) =>
      globalThis.fetch(input, init));
  const readCookies =
    options.readCookies ??
    (() => (typeof document === "undefined" ? "" : document.cookie));

  async function send(
    path: string,
    init: RequestInit,
    mutation = false,
  ): Promise<unknown> {
    const headers = new Headers(init.headers);
    headers.set("Accept", "application/json");
    if (mutation) {
      const csrf = readCookie(CSRF_COOKIE_NAME, readCookies());
      if (!csrf) {
        throw new WorkspaceRequestError("authentication_required", 401);
      }
      headers.set(CSRF_HEADER_NAME, csrf);
      headers.set("Content-Type", "application/json");
    }
    let response: Response;
    try {
      response = await request(path, {
        cache: "no-store",
        credentials: "same-origin",
        redirect: "error",
        ...init,
        headers,
      });
    } catch {
      throw new WorkspaceRequestError("network_failure", 0);
    }
    if (!response.ok) {
      throw await responseError(response);
    }
    return readJSON(response);
  }

  return {
    async getWorkspace() {
      return decodeSnapshot(await send("/api/v1/workspace", { method: "GET" }));
    },
    async inspectCandidate(workingDirectory, configurationPath) {
      validateSelection(workingDirectory, configurationPath);
      const candidate = decodeCandidate(
        await send(
          "/api/v1/workspace/candidates",
          {
            body: JSON.stringify({ workingDirectory, configurationPath }),
            method: "POST",
          },
          true,
        ),
      );
      if (
        !evidenceMatchesRequestedSelection(
          candidate.candidate,
          workingDirectory,
          configurationPath,
        )
      ) {
        invalidResponse();
      }
      return candidate;
    },
    async adoptCandidate(
      workingDirectory,
      configurationPath,
      reviewedEvidenceSha256,
    ) {
      validateSelection(workingDirectory, configurationPath);
      if (!digestPattern.test(reviewedEvidenceSha256)) {
        throw new WorkspaceRequestError("invalid_request", 0);
      }
      const result = decodeAdoption(
        await send(
          "/api/v1/workspace",
          {
            body: JSON.stringify({
              workingDirectory,
              configurationPath,
              reviewedEvidenceSha256,
            }),
            method: "PUT",
          },
          true,
        ),
      );
      const evidence = resultEvidence(result);
      if (
        evidence === null ||
        !evidenceMatchesRequestedSelection(
          evidence,
          workingDirectory,
          configurationPath,
        )
      ) {
        invalidResponse();
      }
      return result;
    },
  };
}

export const browserWorkspaceClient = createWorkspaceClient();
