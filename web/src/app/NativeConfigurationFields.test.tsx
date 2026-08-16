import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ChallengesEditor } from "./NativeConfigurationFields";
import {
  initialConfigurationDraft,
  newDNSChallenge,
} from "./nativeConfigurationModel";

describe("DNS provider configuration forms", () => {
  it("shows least-privilege Cloudflare token guidance and write-only controls", () => {
    const draft = initialConfigurationDraft([], true);
    draft.challenges = [
      {
        ...newDNSChallenge("dns-home"),
        cloudflareDnsToken: { action: "replace", secret: "" },
        cloudflareZoneToken: { action: "replace", secret: "" },
      },
    ];
    render(
      <ChallengesEditor
        creation
        disabled={false}
        draft={draft}
        issues={[]}
        mutate={() => undefined}
      />,
    );

    expect(
      screen.getByText("Least-privilege Cloudflare tokens"),
    ).toBeInTheDocument();
    expect(
      within(
        screen.getByRole("group", { name: "DNS API token" }),
      ).getByLabelText("New secret value"),
    ).toHaveAttribute("type", "password");
    expect(
      within(
        screen.getByRole("group", { name: "Zone API token" }),
      ).getByLabelText("New secret value"),
    ).toHaveAttribute("type", "password");
  });

  it("explains DuckDNS sequential behavior", () => {
    const draft = initialConfigurationDraft([], true);
    draft.challenges = [
      {
        ...newDNSChallenge("dns-duck"),
        provider: "duckdns",
        duckDnsToken: { action: "replace", secret: "" },
      },
    ];
    render(
      <ChallengesEditor
        creation
        disabled={false}
        draft={draft}
        issues={[]}
        mutate={() => undefined}
      />,
    );

    expect(screen.getByText("Sequential DNS updates")).toBeInTheDocument();
    expect(
      within(
        screen.getByRole("group", { name: "DuckDNS account token" }),
      ).getByLabelText("New secret value"),
    ).toHaveAttribute("type", "password");
  });

  it("shows every Azure identity mode and ambient-access warning", () => {
    const draft = initialConfigurationDraft([], true);
    const challenge = newDNSChallenge("dns-azure");
    challenge.provider = "azuredns";
    challenge.cloudAuthMode = "azure_managed";
    challenge.providerSettings = {
      ["provider.azuredns.environment"]: "public",
      ["provider.azuredns.private_zone"]: "false",
      ["provider.azuredns.auth_method"]: "msi",
    };
    draft.challenges = [challenge];
    render(
      <ChallengesEditor
        creation
        disabled={false}
        draft={draft}
        issues={[]}
        mutate={() => undefined}
      />,
    );
    expect(
      screen.getByText("Explicit cloud identity boundary"),
    ).toBeInTheDocument();
    const mode = screen.getByLabelText("Authentication mode");
    expect(
      within(mode).getByRole("option", { name: "Workload identity" }),
    ).toBeInTheDocument();
    expect(
      within(mode).getByRole("option", { name: "Azure CLI cache" }),
    ).toBeInTheDocument();
    expect(
      within(mode).getByRole("option", { name: "Azure Pipelines identity" }),
    ).toBeInTheDocument();
    expect(
      screen.getByLabelText("Optional Azure Arc IMDS endpoint"),
    ).toBeInTheDocument();
  });
});
