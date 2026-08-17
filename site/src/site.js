(() => {
  "use strict";

  const navToggle = document.querySelector("[data-nav-toggle]");
  const navigation = document.querySelector("[data-site-nav]");

  function closeNavigation({ restoreFocus = false } = {}) {
    if (!navToggle || !navigation) return;
    navigation.classList.remove("is-open");
    navToggle.setAttribute("aria-expanded", "false");
    if (restoreFocus) navToggle.focus();
  }

  if (navToggle && navigation) {
    navToggle.addEventListener("click", () => {
      const open = navToggle.getAttribute("aria-expanded") !== "true";
      navToggle.setAttribute("aria-expanded", String(open));
      navigation.classList.toggle("is-open", open);
    });
    navigation.addEventListener("click", (event) => {
      if (event.target.closest("a")) closeNavigation();
    });
    document.addEventListener("pointerdown", (event) => {
      if (
        navToggle.getAttribute("aria-expanded") === "true" &&
        !navigation.contains(event.target) &&
        !navToggle.contains(event.target)
      ) {
        closeNavigation();
      }
    });
  }

  const dock = document.querySelector("[data-dogfood-dock]");
  const dockToggle = dock?.querySelector("[data-dock-toggle]");
  const dockPanel = dock?.querySelector("[data-dock-panel]");
  const openDockButtons = document.querySelectorAll("[data-open-dogfood]");
  let dockOpenedFrom = null;

  function setDockOpen(
    open,
    { focusPanel = false, restoreFocus = false } = {},
  ) {
    if (!dockToggle || !dockPanel) return;
    dockToggle.setAttribute("aria-expanded", String(open));
    dockPanel.hidden = !open;
    if (open && focusPanel) {
      const email = dockPanel.querySelector("input[name='email']");
      email?.focus();
    }
    if (!open && restoreFocus) {
      const target = dockOpenedFrom?.isConnected ? dockOpenedFrom : dockToggle;
      target.focus();
      dockOpenedFrom = null;
    }
  }

  dockToggle?.addEventListener("click", () => {
    const open = dockToggle.getAttribute("aria-expanded") !== "true";
    dockOpenedFrom = dockToggle;
    setDockOpen(open, { restoreFocus: !open });
  });

  openDockButtons.forEach((button) => {
    button.addEventListener("click", () => {
      dockOpenedFrom = button;
      setDockOpen(true, { focusPanel: true });
    });
  });

  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    if (dockToggle?.getAttribute("aria-expanded") === "true") {
      setDockOpen(false, { restoreFocus: true });
      return;
    }
    if (navToggle?.getAttribute("aria-expanded") === "true") {
      closeNavigation({ restoreFocus: true });
    }
  });

  const exactUtc = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
  const fingerprint = /^[a-fA-F0-9]{64}$/;
  let evidence = null;
  let countdownTimer = null;

  function parseUtc(value) {
    if (typeof value !== "string" || !exactUtc.test(value)) return null;
    const result = new Date(value);
    return Number.isFinite(result.getTime()) &&
      result.toISOString().replace(".000Z", "Z") === value
      ? result
      : null;
  }

  function validEvidence(value) {
    if (!value || typeof value !== "object" || Array.isArray(value))
      return null;
    const issuedAt = parseUtc(value.issuedAt);
    const expiresAt = parseUtc(value.expiresAt);
    const nextRenewalAt = parseUtc(value.nextRenewalAt);
    const lastDeployedAt = parseUtc(value.lastDeployedAt);
    if (
      !issuedAt ||
      !expiresAt ||
      !nextRenewalAt ||
      !lastDeployedAt ||
      issuedAt >= expiresAt ||
      nextRenewalAt < issuedAt ||
      nextRenewalAt >= expiresAt ||
      lastDeployedAt < issuedAt ||
      lastDeployedAt >= expiresAt ||
      !fingerprint.test(value.fingerprintSha256 ?? "")
    ) {
      return null;
    }
    return {
      expiresAt,
      fingerprintSha256: value.fingerprintSha256.toLowerCase(),
      issuedAt,
      nextRenewalAt,
    };
  }

  function readableDate(value) {
    return new Intl.DateTimeFormat("en", {
      day: "numeric",
      hour: "2-digit",
      hour12: false,
      minute: "2-digit",
      month: "short",
      timeZone: "UTC",
      timeZoneName: "short",
      year: "numeric",
    }).format(value);
  }

  function duration(target, now) {
    const totalMinutes = Math.max(0, Math.ceil((target - now) / 60000));
    const days = Math.floor(totalMinutes / 1440);
    const hours = Math.floor((totalMinutes % 1440) / 60);
    const minutes = totalMinutes % 60;
    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m`;
  }

  function text(selector, value) {
    document.querySelectorAll(selector).forEach((target) => {
      target.textContent = value;
    });
  }

  function setEvidenceState(state) {
    if (dock) dock.dataset.state = state;
    document.body.dataset.dogfoodPageState = state;
    document.querySelectorAll("[data-status-page]").forEach((target) => {
      target.dataset.state = state;
    });
  }

  async function fetchWithin(input, init, timeoutMilliseconds) {
    const controller = new AbortController();
    const timeout = window.setTimeout(
      () => controller.abort(),
      timeoutMilliseconds,
    );
    try {
      return await fetch(input, { ...init, signal: controller.signal });
    } finally {
      window.clearTimeout(timeout);
    }
  }

  function showUnavailable() {
    if (!dock) return;
    setEvidenceState("unavailable");
    text("[data-dogfood-summary]", "Live certificate evidence is unavailable");
    text("[data-status-page-summary]", "Public evidence unavailable");
    text("[data-dogfood-state]", "Unavailable");
    text("[data-dogfood-countdown]", "Evidence unavailable");
    text("[data-cert-issued]", "Unavailable");
    text("[data-cert-expires]", "Unavailable");
    text("[data-cert-fingerprint]", "Unavailable");
    text(
      "[data-cert-basis]",
      "The public feed could not be verified. Inspect the served certificate directly.",
    );
  }

  function updateCountdown() {
    if (!dock || !evidence) return;
    const now = new Date();
    const ended = evidence.nextRenewalAt <= now;
    const expired = evidence.expiresAt <= now;
    const state = expired ? "expired" : ended ? "ended" : "healthy";
    setEvidenceState(state);
    text(
      "[data-dogfood-summary]",
      expired
        ? "Public certificate evidence is expired"
        : ended
          ? "Expected window reached; inspect evidence"
          : `Expected replacement in ${duration(evidence.nextRenewalAt, now)}`,
    );
    text(
      "[data-status-page-summary]",
      expired
        ? "Public evidence expired"
        : ended
          ? "Replacement window reached"
          : "Public feed verified",
    );
    text(
      "[data-dogfood-countdown]",
      expired
        ? "Certificate evidence expired"
        : ended
          ? "Expected window reached"
          : `Expected replacement in ${duration(evidence.nextRenewalAt, now)}`,
    );
    text(
      "[data-dogfood-state]",
      expired ? "Expired" : ended ? "Window ended" : "Healthy",
    );
    text("[data-cert-issued]", readableDate(evidence.issuedAt));
    text("[data-cert-expires]", readableDate(evidence.expiresAt));
    text("[data-cert-fingerprint]", evidence.fingerprintSha256);
    text(
      "[data-cert-basis]",
      expired
        ? "The public evidence is expired. Inspect the certificate currently served by TLS."
        : ended
          ? "Awaiting new public certificate evidence. This does not prove renewal failure."
          : "Public schedule evidence only. This is not a renewal-due prediction.",
    );
  }

  async function loadEvidence() {
    try {
      const response = await fetchWithin(
        "/certificate-status.json",
        {
          cache: "no-store",
          headers: { Accept: "application/json" },
        },
        8000,
      );
      if (!response.ok) throw new Error("unavailable");
      const value = await response.json();
      evidence = validEvidence(value);
      if (!evidence) throw new Error("invalid");
      updateCountdown();
      countdownTimer = window.setInterval(updateCountdown, 60000);
    } catch {
      showUnavailable();
    }
  }

  const reminderForm = dock?.querySelector("[data-reminder-form]");
  const reminderSubmit = reminderForm?.querySelector("[data-reminder-submit]");
  const reminderResult = reminderForm?.querySelector("[data-reminder-result]");

  function formResult(message, kind = "") {
    if (!reminderResult) return;
    reminderResult.textContent = message;
    reminderResult.dataset.kind = kind;
  }

  const reminderEmail = reminderForm?.elements.namedItem("email");
  if (reminderEmail instanceof HTMLInputElement) {
    reminderEmail.addEventListener("invalid", () => {
      formResult("Enter a valid email address.", "error");
    });
  }

  reminderForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const email = reminderForm.elements.namedItem("email");
    const website = reminderForm.elements.namedItem("website");
    if (!(email instanceof HTMLInputElement) || !email.checkValidity()) {
      email?.reportValidity();
      formResult("Enter a valid email address.", "error");
      return;
    }
    if (!(website instanceof HTMLInputElement) || !reminderSubmit) return;

    reminderSubmit.disabled = true;
    reminderSubmit.textContent = "Sending...";
    reminderForm.setAttribute("aria-busy", "true");
    formResult("Sending confirmation...", "");

    try {
      const response = await fetchWithin(
        reminderForm.action,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email: email.value.trim(),
            website: website.value,
          }),
        },
        10000,
      );
      if (!response.ok) {
        if (response.status >= 400 && response.status < 500) {
          formResult("Enter a valid email address and try again.", "error");
        } else {
          formResult(
            "Signup could not be completed. Check your inbox for an AWS confirmation before trying again.",
            "error",
          );
        }
        return;
      }
      reminderForm.reset();
      formResult(
        "Check your inbox to confirm. No reminder is active until you confirm.",
        "success",
      );
    } catch {
      formResult(
        "Signup could not be completed. Check your inbox for an AWS confirmation before trying again.",
        "error",
      );
    } finally {
      reminderSubmit.disabled = false;
      reminderSubmit.textContent = "Remind me";
      reminderForm.removeAttribute("aria-busy");
    }
  });

  loadEvidence();
  window.addEventListener("pagehide", () => {
    if (countdownTimer !== null) window.clearInterval(countdownTimer);
  });
})();
