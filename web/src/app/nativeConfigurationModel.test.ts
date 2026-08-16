import type { ProjectedField } from "../api/configuration";
import {
  acknowledgeUnsupportedField,
  changesFromDraft,
  initialConfigurationDraft,
  managedFieldIds,
  maximumConfigurationChanges,
  newDNSChallenge,
  type NativeConfigurationDraft,
  validateChangeBudget,
  validateDraft,
} from "./nativeConfigurationModel";

const accountBindings = [{ id: "account", value: "primary" }];
const challengeBindings = [{ id: "challenge", value: "http-home" }];
const certificateBindings = [{ id: "certificate", value: "home" }];

function validDraft(): NativeConfigurationDraft {
  const draft = initialConfigurationDraft([], true);
  draft.storage = "/srv/lego/storage";
  draft.accounts[0] = {
    ...draft.accounts[0]!,
    email: "admin@example.com",
    acceptsTerms: true,
  };
  draft.challenges[0] = {
    ...draft.challenges[0]!,
    address: "127.0.0.1:8080",
    delay: "1m30s",
    proxyHeader: "X-Forwarded-Port",
  };
  draft.certificates[0] = {
    ...draft.certificates[0]!,
    domains: ["home.example.com", "router.example.com"],
    renewDays: 30,
    reuseKey: true,
    disableRandomSleep: true,
    disableARI: true,
    ariWait: "5m",
  };
  return draft;
}

function stringField(
  fieldId: string,
  bindings: ProjectedField["bindings"],
  value: string,
): ProjectedField {
  return {
    fieldId,
    bindings,
    label: fieldId,
    kind: "string",
    present: true,
    configured: true,
    defaulted: false,
    presenceKnown: true,
    value,
  };
}

function stringListField(
  fieldId: string,
  bindings: ProjectedField["bindings"],
  value: string[],
): ProjectedField {
  return {
    fieldId,
    bindings,
    label: fieldId,
    kind: "string_list",
    present: true,
    configured: true,
    defaulted: false,
    presenceKnown: true,
    value,
  };
}

function defaultedStringField(
  fieldId: string,
  bindings: ProjectedField["bindings"],
  value: string,
): ProjectedField {
  return {
    fieldId,
    bindings,
    label: fieldId,
    kind: "string",
    present: false,
    configured: true,
    defaulted: true,
    presenceKnown: true,
    value,
  };
}

function booleanField(
  fieldId: string,
  bindings: ProjectedField["bindings"],
  value: boolean,
): ProjectedField {
  return {
    fieldId,
    bindings,
    label: fieldId,
    kind: "boolean",
    present: true,
    configured: true,
    defaulted: false,
    presenceKnown: true,
    value,
  };
}

function integerField(
  fieldId: string,
  bindings: ProjectedField["bindings"],
  value: number,
): ProjectedField {
  return {
    fieldId,
    bindings,
    label: fieldId,
    kind: "integer",
    present: true,
    configured: true,
    defaulted: false,
    presenceKnown: true,
    value,
  };
}

function unsupportedStringField(
  fieldId: string,
  bindings: ProjectedField["bindings"],
): ProjectedField {
  return {
    fieldId,
    bindings,
    label: fieldId,
    kind: "string",
    present: true,
    configured: false,
    defaulted: false,
    presenceKnown: true,
  };
}

function unsupportedField(
  fieldId: string,
  bindings: ProjectedField["bindings"],
  kind: "string" | "boolean" | "integer" | "string_list" | "secret",
): ProjectedField {
  return {
    fieldId,
    bindings,
    label: fieldId,
    kind,
    present: true,
    configured: false,
    defaulted: false,
    presenceKnown: true,
  };
}

describe("native configuration model", () => {
  it("emits the exact listener creation changes", () => {
    expect(changesFromDraft(validDraft(), [], true)).toEqual([
      {
        fieldId: managedFieldIds.storage,
        bindings: [],
        operation: "set",
        value: "/srv/lego/storage",
      },
      {
        fieldId: managedFieldIds.accountServer,
        bindings: accountBindings,
        operation: "set",
        value: "letsencrypt",
      },
      {
        fieldId: managedFieldIds.accountEmail,
        bindings: accountBindings,
        operation: "set",
        value: "admin@example.com",
      },
      {
        fieldId: managedFieldIds.accountKeyType,
        bindings: accountBindings,
        operation: "set",
        value: "EC256",
      },
      {
        fieldId: managedFieldIds.accountTerms,
        bindings: accountBindings,
        operation: "set",
        value: true,
      },
      {
        fieldId: managedFieldIds.challengeDelay,
        bindings: challengeBindings,
        operation: "set",
        value: "1m30s",
      },
      {
        fieldId: managedFieldIds.challengeAddress,
        bindings: challengeBindings,
        operation: "set",
        value: "127.0.0.1:8080",
      },
      {
        fieldId: managedFieldIds.challengeProxyHeader,
        bindings: challengeBindings,
        operation: "set",
        value: "X-Forwarded-Port",
      },
      {
        fieldId: managedFieldIds.certificateDomains,
        bindings: certificateBindings,
        operation: "set",
        value: ["home.example.com", "router.example.com"],
      },
      {
        fieldId: managedFieldIds.certificateAccount,
        bindings: certificateBindings,
        operation: "set",
        value: "primary",
      },
      {
        fieldId: managedFieldIds.certificateChallenge,
        bindings: certificateBindings,
        operation: "set",
        value: "http-home",
      },
      {
        fieldId: managedFieldIds.certificateKeyType,
        bindings: certificateBindings,
        operation: "set",
        value: "EC256",
      },
      {
        fieldId: managedFieldIds.certificateRenewDays,
        bindings: certificateBindings,
        operation: "set",
        value: 30,
      },
      {
        fieldId: managedFieldIds.certificateRenewReuseKey,
        bindings: certificateBindings,
        operation: "set",
        value: true,
      },
      {
        fieldId: managedFieldIds.certificateRenewDisableRandomSleep,
        bindings: certificateBindings,
        operation: "set",
        value: true,
      },
      {
        fieldId: managedFieldIds.certificateRenewAriDisable,
        bindings: certificateBindings,
        operation: "set",
        value: true,
      },
      {
        fieldId: managedFieldIds.certificateRenewAriWait,
        bindings: certificateBindings,
        operation: "set",
        value: "5m",
      },
    ]);
  });

  it("emits explicit challenge and renewal defaults for creation", () => {
    const draft = initialConfigurationDraft([], true);
    draft.accounts[0] = {
      ...draft.accounts[0]!,
      email: "admin@example.com",
      acceptsTerms: true,
    };
    draft.certificates[0] = {
      ...draft.certificates[0]!,
      domains: ["home.example.com"],
    };

    const changes = changesFromDraft(draft, [], true);

    expect(changes).toEqual(
      expect.arrayContaining([
        {
          fieldId: managedFieldIds.challengeDelay,
          bindings: challengeBindings,
          operation: "set",
          value: "0s",
        },
        {
          fieldId: managedFieldIds.certificateRenewDays,
          bindings: certificateBindings,
          operation: "set",
          value: 0,
        },
        {
          fieldId: managedFieldIds.certificateRenewReuseKey,
          bindings: certificateBindings,
          operation: "set",
          value: false,
        },
        {
          fieldId: managedFieldIds.certificateRenewDisableRandomSleep,
          bindings: certificateBindings,
          operation: "set",
          value: false,
        },
        {
          fieldId: managedFieldIds.certificateRenewAriDisable,
          bindings: certificateBindings,
          operation: "set",
          value: false,
        },
        {
          fieldId: managedFieldIds.certificateRenewAriWait,
          bindings: certificateBindings,
          operation: "set",
          value: "0s",
        },
      ]),
    );
  });

  it("keeps the largest creation form within the reviewed wire budget", () => {
    const draft = initialConfigurationDraft([], true);
    const baseAccount = draft.accounts[0]!;
    const baseChallenge = draft.challenges[0]!;
    const baseCertificate = draft.certificates[0]!;
    draft.accounts = Array.from({ length: 6 }, (_, index) => ({
      ...baseAccount,
      name: `account-${index + 1}`,
      server: "googletrust",
      email: `admin-${index + 1}@example.com`,
      acceptsTerms: true,
      eabKid: `kid-${index + 1}`,
      eabHmac: { action: "replace" as const, secret: "YWJjZA==" },
    }));
    draft.challenges = Array.from({ length: 6 }, (_, index) => ({
      ...baseChallenge,
      name: `http-${index + 1}`,
      address: `127.0.0.1:${8080 + index}`,
      proxyHeader: "X-Forwarded-Host",
    }));
    draft.certificates = Array.from({ length: 8 }, (_, index) => ({
      ...baseCertificate,
      name: `certificate-${index + 1}`,
      domains: [`host-${index + 1}.example.com`],
      account: draft.accounts[index % draft.accounts.length]!.name,
      challenge: draft.challenges[index % draft.challenges.length]!.name,
    }));

    expect(validateDraft(draft)).toEqual([]);
    const bounded = changesFromDraft(draft, [], true);
    expect(bounded).toHaveLength(127);
    expect(validateChangeBudget(bounded)).toEqual([]);

    draft.certificates.push({
      ...baseCertificate,
      name: "certificate-9",
      domains: ["host-9.example.com"],
      account: draft.accounts[0]!.name,
      challenge: draft.challenges[0]!.name,
    });
    const oversized = changesFromDraft(draft, [], true);
    expect(oversized.length).toBeGreaterThan(maximumConfigurationChanges);
    expect(validateChangeBudget(oversized)).toEqual([
      expect.objectContaining({
        fieldId: "managed-configuration-heading",
        message: expect.stringContaining("at most 128"),
      }),
    ]);
  });

  it("renders accepted exact CA aliases without normalizing an untouched account", () => {
    const projection = [
      stringField(
        managedFieldIds.accountServer,
        accountBindings,
        "https://acme-v02.api.letsencrypt.org/directory",
      ),
    ];
    const draft = initialConfigurationDraft(projection);

    expect(draft.accounts[0]).toMatchObject({
      originalServer: "letsencrypt",
      server: "letsencrypt",
    });
    expect(changesFromDraft(draft, projection, false)).not.toContainEqual(
      expect.objectContaining({ fieldId: managedFieldIds.accountServer }),
    );
  });

  it("round-trips upstream account and HTTP-01 defaults as explicit required references", () => {
    const defaultAccountBindings = [
      { id: "account", value: "noemail@example.com" },
    ];
    const projection: ProjectedField[] = [
      defaultedStringField(
        managedFieldIds.accountServer,
        defaultAccountBindings,
        "letsencrypt",
      ),
      stringListField(managedFieldIds.certificateDomains, certificateBindings, [
        "home.example.com",
      ]),
      defaultedStringField(
        managedFieldIds.certificateAccount,
        certificateBindings,
        "noemail@example.com",
      ),
      defaultedStringField(
        managedFieldIds.certificateChallenge,
        certificateBindings,
        "http-01",
      ),
      defaultedStringField(
        managedFieldIds.challengeAddress,
        [{ id: "challenge", value: "http-01" }],
        ":80",
      ),
      defaultedStringField(
        managedFieldIds.challengeDelay,
        [{ id: "challenge", value: "http-01" }],
        "0s",
      ),
    ];
    const draft = initialConfigurationDraft(projection);

    expect(draft.accounts[0]?.name).toBe("noemail@example.com");
    expect(draft.challenges).toEqual([
      expect.objectContaining({ name: "http-01", predefined: true }),
    ]);
    expect(draft.certificates[0]).toMatchObject({
      account: "noemail@example.com",
      challenge: "http-01",
    });
    expect(validateDraft(draft)).toEqual([]);

    const changes = changesFromDraft(draft, projection, false);
    expect(changes).toEqual(
      expect.arrayContaining([
        {
          fieldId: managedFieldIds.accountServer,
          bindings: defaultAccountBindings,
          operation: "set",
          value: "letsencrypt",
        },
        {
          fieldId: managedFieldIds.certificateAccount,
          bindings: certificateBindings,
          operation: "set",
          value: "noemail@example.com",
        },
        {
          fieldId: managedFieldIds.certificateChallenge,
          bindings: certificateBindings,
          operation: "set",
          value: "http-01",
        },
      ]),
    );
    expect(changes).toEqual(
      expect.arrayContaining([
        {
          fieldId: managedFieldIds.challengeAddress,
          bindings: [{ id: "challenge", value: "http-01" }],
          operation: "set",
          value: ":80",
        },
        {
          fieldId: managedFieldIds.challengeDelay,
          bindings: [{ id: "challenge", value: "http-01" }],
          operation: "set",
          value: "0s",
        },
      ]),
    );
  });

  it.each(["tls-alpn-01", "dns-persist-01"])(
    "preserves an implicit unsupported %s reference during unrelated edits",
    (nativeChallenge) => {
      const projection: ProjectedField[] = [
        stringField(managedFieldIds.storage, [], ".lego"),
        stringField(
          managedFieldIds.accountServer,
          accountBindings,
          "letsencrypt",
        ),
        stringListField(
          managedFieldIds.certificateDomains,
          certificateBindings,
          ["home.example.com"],
        ),
        stringField(
          managedFieldIds.certificateAccount,
          certificateBindings,
          "primary",
        ),
        defaultedStringField(
          managedFieldIds.certificateChallenge,
          certificateBindings,
          nativeChallenge,
        ),
        stringField(
          managedFieldIds.certificateKeyType,
          certificateBindings,
          "EC256",
        ),
        integerField(
          managedFieldIds.certificateRenewDays,
          certificateBindings,
          0,
        ),
        booleanField(
          managedFieldIds.certificateRenewReuseKey,
          certificateBindings,
          false,
        ),
        booleanField(
          managedFieldIds.certificateRenewDisableRandomSleep,
          certificateBindings,
          false,
        ),
        booleanField(
          managedFieldIds.certificateRenewAriDisable,
          certificateBindings,
          false,
        ),
        stringField(
          managedFieldIds.certificateRenewAriWait,
          certificateBindings,
          "0s",
        ),
      ];
      const draft = initialConfigurationDraft(projection);
      draft.storage = "/srv/lego/storage";

      expect(draft.challenges).toEqual([]);
      expect(draft.certificates[0]).toMatchObject({
        challenge: nativeChallenge,
        challengeUnsupported: true,
      });
      expect(validateDraft(draft)).toEqual([]);
      expect(changesFromDraft(draft, projection, false)).toEqual([
        {
          fieldId: managedFieldIds.storage,
          bindings: [],
          operation: "set",
          value: "/srv/lego/storage",
        },
      ]);
    },
  );

  it.each(["web", "http-01"])(
    "does not reinterpret an explicit unsupported %s challenge as HTTP",
    (nativeChallenge) => {
      const projection: ProjectedField[] = [
        stringField(managedFieldIds.storage, [], ".lego"),
        stringField(
          managedFieldIds.accountServer,
          accountBindings,
          "letsencrypt",
        ),
        stringListField(
          managedFieldIds.certificateDomains,
          certificateBindings,
          ["home.example.com"],
        ),
        stringField(
          managedFieldIds.certificateAccount,
          certificateBindings,
          "primary",
        ),
        stringField(
          managedFieldIds.certificateChallenge,
          certificateBindings,
          nativeChallenge,
        ),
      ];
      const draft = initialConfigurationDraft(projection);
      draft.storage = "/srv/lego/storage";

      expect(draft.challenges).toEqual([]);
      expect(draft.certificates[0]).toMatchObject({
        challenge: nativeChallenge,
        challengeUnsupported: true,
      });
      expect(validateDraft(draft)).toEqual([]);
      expect(changesFromDraft(draft, projection, false)).toEqual([
        {
          fieldId: managedFieldIds.storage,
          bindings: [],
          operation: "set",
          value: "/srv/lego/storage",
        },
      ]);
    },
  );

  it("preserves a suppressed CSR certificate during an unrelated edit", () => {
    const projection = [stringField(managedFieldIds.storage, [], ".lego")];
    const draft = initialConfigurationDraft(projection);
    draft.storage = "/srv/lego/storage";

    expect(draft).toMatchObject({
      creation: false,
      accounts: [],
      challenges: [],
      certificates: [],
    });
    expect(validateDraft(draft)).toEqual([]);
    expect(changesFromDraft(draft, projection, false)).toEqual([
      {
        fieldId: managedFieldIds.storage,
        bindings: [],
        operation: "set",
        value: "/srv/lego/storage",
      },
    ]);
  });

  it("preserves explicit supported default scalars during unrelated edits", () => {
    const projection: ProjectedField[] = [
      stringField(managedFieldIds.storage, [], ".lego"),
      stringField(
        managedFieldIds.accountServer,
        accountBindings,
        "letsencrypt",
      ),
      booleanField(managedFieldIds.accountTerms, accountBindings, false),
      stringField(managedFieldIds.challengeAddress, challengeBindings, ":80"),
      stringField(managedFieldIds.challengeDelay, challengeBindings, "0s"),
      stringField(
        managedFieldIds.challengeProxyHeader,
        challengeBindings,
        "Host",
      ),
      stringListField(managedFieldIds.certificateDomains, certificateBindings, [
        "home.example.com",
      ]),
      stringField(
        managedFieldIds.certificateAccount,
        certificateBindings,
        "primary",
      ),
      stringField(
        managedFieldIds.certificateChallenge,
        certificateBindings,
        "http-home",
      ),
      integerField(
        managedFieldIds.certificateRenewDays,
        certificateBindings,
        0,
      ),
      booleanField(
        managedFieldIds.certificateRenewReuseKey,
        certificateBindings,
        false,
      ),
      booleanField(
        managedFieldIds.certificateRenewDisableRandomSleep,
        certificateBindings,
        false,
      ),
      booleanField(
        managedFieldIds.certificateRenewAriDisable,
        certificateBindings,
        false,
      ),
      stringField(
        managedFieldIds.certificateRenewAriWait,
        certificateBindings,
        "0s",
      ),
    ];
    const draft = initialConfigurationDraft(projection);
    draft.storage = "/srv/lego/storage";

    expect(changesFromDraft(draft, projection, false)).toEqual([
      {
        fieldId: managedFieldIds.storage,
        bindings: [],
        operation: "set",
        value: "/srv/lego/storage",
      },
    ]);
  });

  it("emits only webroot fields for webroot creation", () => {
    const draft = validDraft();
    draft.challenges[0] = {
      ...draft.challenges[0]!,
      mode: "webroot",
      webroot: "/srv/acme/challenges",
    };

    const changes = changesFromDraft(draft, [], true);

    expect(changes).toEqual([
      {
        fieldId: managedFieldIds.storage,
        bindings: [],
        operation: "set",
        value: "/srv/lego/storage",
      },
      {
        fieldId: managedFieldIds.accountServer,
        bindings: accountBindings,
        operation: "set",
        value: "letsencrypt",
      },
      {
        fieldId: managedFieldIds.accountEmail,
        bindings: accountBindings,
        operation: "set",
        value: "admin@example.com",
      },
      {
        fieldId: managedFieldIds.accountKeyType,
        bindings: accountBindings,
        operation: "set",
        value: "EC256",
      },
      {
        fieldId: managedFieldIds.accountTerms,
        bindings: accountBindings,
        operation: "set",
        value: true,
      },
      {
        fieldId: managedFieldIds.challengeDelay,
        bindings: challengeBindings,
        operation: "set",
        value: "1m30s",
      },
      {
        fieldId: managedFieldIds.challengeWebroot,
        bindings: challengeBindings,
        operation: "set",
        value: "/srv/acme/challenges",
      },
      {
        fieldId: managedFieldIds.certificateDomains,
        bindings: certificateBindings,
        operation: "set",
        value: ["home.example.com", "router.example.com"],
      },
      {
        fieldId: managedFieldIds.certificateAccount,
        bindings: certificateBindings,
        operation: "set",
        value: "primary",
      },
      {
        fieldId: managedFieldIds.certificateChallenge,
        bindings: certificateBindings,
        operation: "set",
        value: "http-home",
      },
      {
        fieldId: managedFieldIds.certificateKeyType,
        bindings: certificateBindings,
        operation: "set",
        value: "EC256",
      },
      {
        fieldId: managedFieldIds.certificateRenewDays,
        bindings: certificateBindings,
        operation: "set",
        value: 30,
      },
      {
        fieldId: managedFieldIds.certificateRenewReuseKey,
        bindings: certificateBindings,
        operation: "set",
        value: true,
      },
      {
        fieldId: managedFieldIds.certificateRenewDisableRandomSleep,
        bindings: certificateBindings,
        operation: "set",
        value: true,
      },
      {
        fieldId: managedFieldIds.certificateRenewAriDisable,
        bindings: certificateBindings,
        operation: "set",
        value: true,
      },
      {
        fieldId: managedFieldIds.certificateRenewAriWait,
        bindings: certificateBindings,
        operation: "set",
        value: "5m",
      },
    ]);
    expect(changes).not.toContainEqual(
      expect.objectContaining({ fieldId: managedFieldIds.challengeAddress }),
    );
    expect(changes).not.toContainEqual(
      expect.objectContaining({
        fieldId: managedFieldIds.challengeProxyHeader,
      }),
    );
  });

  it("requires account prerequisites only for registration transitions and never echoes an invalid EAB secret", () => {
    const draft = validDraft();
    draft.accounts[0] = {
      ...draft.accounts[0]!,
      isNew: false,
      originalServer: "googletrust",
      server: "googletrust",
      email: "",
      acceptsTerms: false,
      eabKid: "",
      eabHmac: { action: "keep" },
      eabPresent: false,
    };

    expect(validateDraft(draft)).toEqual([]);

    draft.accounts[0]!.server = "googletrust-staging";
    expect(validateDraft(draft)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ fieldId: "account-0-terms" }),
        expect.objectContaining({ fieldId: "account-0-eab-kid" }),
        expect.objectContaining({
          fieldId: "account-0-eab-hmac-replacement",
        }),
      ]),
    );

    const invalidSecret = "do-not-echo+this";
    draft.accounts[0] = {
      ...draft.accounts[0]!,
      acceptsTerms: true,
      eabKid: "gts-key-id",
      eabHmac: { action: "replace", secret: invalidSecret },
    };
    const invalidSecretIssues = validateDraft(draft);
    expect(invalidSecretIssues).toEqual([
      {
        fieldId: "account-0-eab-hmac-replacement",
        message:
          "The write-only EAB HMAC must be nonempty base64url with valid optional padding.",
      },
    ]);
    expect(JSON.stringify(invalidSecretIssues)).not.toContain(invalidSecret);

    draft.accounts[0]!.eabHmac = {
      action: "replace",
      secret: "YWJjZA==",
    };
    expect(validateDraft(draft)).toEqual([]);
  });

  it("submits both current EAB fields for a CA registration transition", () => {
    const projection: ProjectedField[] = [
      stringField(
        managedFieldIds.accountServer,
        accountBindings,
        "googletrust",
      ),
      stringField(managedFieldIds.accountEabKid, accountBindings, "same-kid"),
      {
        fieldId: managedFieldIds.accountTerms,
        bindings: accountBindings,
        label: managedFieldIds.accountTerms,
        kind: "boolean",
        present: true,
        configured: true,
        defaulted: false,
        presenceKnown: true,
        value: true,
      },
    ];
    const draft = initialConfigurationDraft(projection);
    draft.accounts[0] = {
      ...draft.accounts[0]!,
      server: "googletrust-staging",
      acceptsTerms: true,
      eabKid: "same-kid",
      eabHmac: { action: "replace", secret: "YWJjZA==" },
    };

    const accountChanges = changesFromDraft(draft, projection, false).filter(
      (change) => change.bindings[0]?.id === "account",
    );

    expect(accountChanges).toEqual(
      expect.arrayContaining([
        {
          fieldId: managedFieldIds.accountTerms,
          bindings: accountBindings,
          operation: "set",
          value: true,
        },
        {
          fieldId: managedFieldIds.accountEabKid,
          bindings: accountBindings,
          operation: "set",
          value: "same-kid",
        },
        {
          fieldId: managedFieldIds.accountEabHmac,
          bindings: accountBindings,
          operation: "set",
          value: "YWJjZA==",
        },
      ]),
    );
  });

  it("requires retained EAB to be removed from a Let's Encrypt account", () => {
    const draft = validDraft();
    draft.accounts[0] = {
      ...draft.accounts[0]!,
      isNew: false,
      originalServer: "letsencrypt",
      server: "letsencrypt",
      eabKid: "old-provider-kid",
      eabHmac: { action: "keep" },
      eabPresent: true,
    };

    expect(validateDraft(draft)).toContainEqual({
      fieldId: "account-0-eab-kid",
      message:
        "Let's Encrypt does not accept EAB input. Clear the key identifier and remove the hidden HMAC value.",
    });

    draft.accounts[0]!.eabKid = "";
    draft.accounts[0]!.eabHmac = { action: "remove" };
    expect(validateDraft(draft)).toEqual([]);
  });

  it("caps the full wildcard DNS name at 253 bytes", () => {
    const draft = validDraft();
    const base = [
      "a".repeat(63),
      "b".repeat(63),
      "c".repeat(63),
      "d".repeat(60),
    ].join(".");
    const wildcard = `*.${base}`;
    draft.certificates[0]!.domains = [wildcard];

    expect(validateDraft(draft)).toContainEqual({
      fieldId: "certificate-0-domains",
      message: `${wildcard} is not a lowercase DNS A-label name.`,
    });
  });

  it("retains configured-false sentinels until an explicit supported repair is emitted", () => {
    const projection: ProjectedField[] = [
      unsupportedStringField(managedFieldIds.accountServer, accountBindings),
      unsupportedStringField(managedFieldIds.accountKeyType, accountBindings),
      stringField(
        managedFieldIds.challengeAddress,
        challengeBindings,
        "127.0.0.1:8080",
      ),
      stringListField(managedFieldIds.certificateDomains, certificateBindings, [
        "home.example.com",
      ]),
      stringField(
        managedFieldIds.certificateAccount,
        certificateBindings,
        "primary",
      ),
      stringField(
        managedFieldIds.certificateChallenge,
        certificateBindings,
        "http-home",
      ),
      unsupportedStringField(
        managedFieldIds.certificateKeyType,
        certificateBindings,
      ),
    ];
    let draft = initialConfigurationDraft(projection);

    expect(draft.accounts[0]).toMatchObject({
      server: "",
      keyType: "",
    });
    expect(draft.certificates[0]).toMatchObject({ keyType: "" });

    draft.accounts[0]!.server = "letsencrypt";
    draft.accounts[0]!.keyType = "EC256";
    draft.accounts[0]!.email = "admin@example.com";
    draft.accounts[0]!.acceptsTerms = true;
    draft.certificates[0]!.keyType = "EC256";
    for (const field of [...draft.unsupportedFields]) {
      draft = acknowledgeUnsupportedField(draft, field.fieldId, field.bindings);
    }

    expect(validateDraft(draft)).toEqual([]);
    expect(changesFromDraft(draft, projection, false)).toEqual(
      expect.arrayContaining([
        {
          fieldId: managedFieldIds.accountServer,
          bindings: accountBindings,
          operation: "set",
          value: "letsencrypt",
        },
        {
          fieldId: managedFieldIds.accountKeyType,
          bindings: accountBindings,
          operation: "set",
          value: "EC256",
        },
        {
          fieldId: managedFieldIds.accountTerms,
          bindings: accountBindings,
          operation: "set",
          value: true,
        },
        {
          fieldId: managedFieldIds.certificateKeyType,
          bindings: certificateBindings,
          operation: "set",
          value: "EC256",
        },
      ]),
    );
  });

  it("requires explicit repair for every hidden curated field kind", () => {
    const projection: ProjectedField[] = [
      unsupportedField(managedFieldIds.storage, [], "string"),
      stringField(
        managedFieldIds.accountServer,
        accountBindings,
        "letsencrypt",
      ),
      unsupportedField(managedFieldIds.accountEmail, accountBindings, "string"),
      unsupportedField(
        managedFieldIds.accountTerms,
        accountBindings,
        "boolean",
      ),
      unsupportedField(
        managedFieldIds.challengeAddress,
        challengeBindings,
        "string",
      ),
      unsupportedField(
        managedFieldIds.challengeDelay,
        challengeBindings,
        "string",
      ),
      unsupportedField(
        managedFieldIds.challengeProxyHeader,
        challengeBindings,
        "string",
      ),
      unsupportedField(
        managedFieldIds.challengeWebroot,
        challengeBindings,
        "string",
      ),
      unsupportedField(
        managedFieldIds.certificateDomains,
        certificateBindings,
        "string_list",
      ),
      unsupportedField(
        managedFieldIds.certificateAccount,
        certificateBindings,
        "string",
      ),
      unsupportedField(
        managedFieldIds.certificateChallenge,
        certificateBindings,
        "string",
      ),
      unsupportedField(
        managedFieldIds.certificateRenewDays,
        certificateBindings,
        "integer",
      ),
      unsupportedField(
        managedFieldIds.certificateRenewReuseKey,
        certificateBindings,
        "boolean",
      ),
      unsupportedField(
        managedFieldIds.certificateRenewDisableRandomSleep,
        certificateBindings,
        "boolean",
      ),
      unsupportedField(
        managedFieldIds.certificateRenewAriDisable,
        certificateBindings,
        "boolean",
      ),
      unsupportedField(
        managedFieldIds.certificateRenewAriWait,
        certificateBindings,
        "string",
      ),
    ];
    let draft = initialConfigurationDraft(projection);

    expect(draft.unsupportedFields.map((field) => field.fieldId)).toEqual([
      managedFieldIds.storage,
      managedFieldIds.accountEmail,
      managedFieldIds.accountTerms,
      managedFieldIds.challengeAddress,
      managedFieldIds.challengeDelay,
      managedFieldIds.challengeProxyHeader,
      managedFieldIds.challengeWebroot,
      managedFieldIds.certificateDomains,
      managedFieldIds.certificateAccount,
      managedFieldIds.certificateChallenge,
      managedFieldIds.certificateRenewDays,
      managedFieldIds.certificateRenewReuseKey,
      managedFieldIds.certificateRenewDisableRandomSleep,
      managedFieldIds.certificateRenewAriDisable,
      managedFieldIds.certificateRenewAriWait,
    ]);
    expect(
      validateDraft(draft).filter((issue) =>
        issue.message.startsWith("An unsupported native value"),
      ),
    ).toHaveLength(15);

    draft.certificates[0] = {
      ...draft.certificates[0]!,
      domains: ["home.example.com"],
      account: "primary",
      challenge: "http-home",
    };
    for (const field of [...draft.unsupportedFields]) {
      draft = acknowledgeUnsupportedField(draft, field.fieldId, field.bindings);
    }

    expect(validateDraft(draft)).toEqual([]);
    const changedIds = new Set(
      changesFromDraft(draft, projection, false).map(
        (change) => change.fieldId,
      ),
    );
    for (const field of projection.filter(
      (candidate) => !candidate.configured,
    )) {
      expect(changedIds).toContain(field.fieldId);
    }
  });

  it("accepts bounded composite durations and safe paths while rejecting unsafe HTTP input", () => {
    const draft = validDraft();
    draft.challenges[0] = {
      ...draft.challenges[0]!,
      mode: "listener",
      address: "[::1]:8080",
      delay: "9m30.5s",
    };
    draft.certificates[0]!.ariWait = "1m30s";
    expect(validateDraft(draft)).toEqual([]);

    draft.challenges[0] = {
      ...draft.challenges[0]!,
      mode: "webroot",
      webroot: "./var/lib/acme/challenges",
    };
    expect(validateDraft(draft)).toEqual([]);
    draft.challenges[0]!.webroot = "/srv/acme/challenges";
    expect(validateDraft(draft)).toEqual([]);

    draft.challenges[0] = {
      ...draft.challenges[0]!,
      mode: "listener",
      address: "acme.internal:8080",
      delay: "10m1s",
      proxyHeader: "x-forwarded-host",
    };
    draft.certificates[0]!.ariWait = "1h";
    expect(validateDraft(draft).map((issue) => issue.fieldId)).toEqual(
      expect.arrayContaining([
        "challenge-0-address",
        "challenge-0-delay",
        "challenge-0-proxy-header",
        "certificate-0-ari-wait",
      ]),
    );

    draft.challenges[0] = {
      ...draft.challenges[0]!,
      mode: "webroot",
      delay: "500ms",
      webroot: "nested/../public",
    };
    draft.certificates[0]!.ariWait = "0s";
    expect(validateDraft(draft)).toEqual([]);

    draft.challenges[0]!.webroot = "bad\npath";
    expect(validateDraft(draft)).toContainEqual(
      expect.objectContaining({ fieldId: "challenge-0-webroot" }),
    );
  });

  it("blocks an in-place SSL.com RSA/ECDSA transition and permits a new account", () => {
    const draft = validDraft();
    draft.accounts[0] = {
      ...draft.accounts[0]!,
      isNew: false,
      originalServer: "sslcomrsa",
      server: "sslcomecc",
      email: "",
      eabKid: "sslcom-key-id",
      eabHmac: { action: "replace", secret: "YWJjZA==" },
    };

    expect(validateDraft(draft)).toContainEqual({
      fieldId: "account-0-server",
      message:
        "SSL.com RSA and ECDSA share native account storage. Add a new account for the other endpoint, then reassign certificates.",
    });

    draft.accounts[0] = {
      ...draft.accounts[0]!,
      isNew: true,
      originalServer: null,
    };
    expect(validateDraft(draft)).toEqual([]);
  });

  it("maps a new Cloudflare DNS challenge to exact YAML and write-only dotenv fields", () => {
    const draft = validDraft();
    draft.challenges = [
      {
        ...newDNSChallenge("dns-home"),
        envFile: ".cloudflare.env",
        dnsTimeout: 30,
        resolvers: ["1.1.1.1:53"],
        cloudflareDnsToken: {
          action: "replace",
          secret: "write-only-token",
        },
        providerSettings: { [managedFieldIds.cloudflareTtl]: "300" },
      },
    ];
    draft.certificates[0] = {
      ...draft.certificates[0]!,
      challenge: "dns-home",
      domains: ["*.example.com", "example.com"],
    };

    expect(validateDraft(draft)).toEqual([]);
    const changes = changesFromDraft(draft, [], true);
    expect(changes).toEqual(
      expect.arrayContaining([
        {
          fieldId: managedFieldIds.challengeDnsProvider,
          bindings: [{ id: "challenge", value: "dns-home" }],
          operation: "set",
          value: "cloudflare",
        },
        {
          fieldId: managedFieldIds.challengeDnsEnvFile,
          bindings: [{ id: "challenge", value: "dns-home" }],
          operation: "set",
          value: ".cloudflare.env",
        },
        {
          fieldId: managedFieldIds.cloudflareDnsToken,
          bindings: [{ id: "challenge", value: "dns-home" }],
          operation: "set",
          value: "write-only-token",
        },
        {
          fieldId: managedFieldIds.cloudflareTtl,
          bindings: [{ id: "challenge", value: "dns-home" }],
          operation: "set",
          value: "300",
        },
      ]),
    );
    expect(
      changes.some((change) => change.fieldId.startsWith("challenge.http.")),
    ).toBe(false);
  });

  it("requires one complete DNS provider authentication mode", () => {
    const draft = validDraft();
    draft.challenges = [newDNSChallenge("dns-home")];
    draft.certificates[0]!.challenge = "dns-home";
    expect(validateDraft(draft)).toContainEqual(
      expect.objectContaining({
        fieldId: "challenge-0-cloudflare-dns-token-replacement",
      }),
    );
    draft.challenges[0]!.cloudflareDnsToken = {
      action: "replace",
      secret: "token",
    };
    expect(validateDraft(draft)).toEqual([]);
  });
});
