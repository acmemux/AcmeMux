const stateLabel = (kind, text) =>
  `<span class="state-label state-${kind}">${text}</span>`;

const arrow = '<span aria-hidden="true">-&gt;</span>';

function callout(title, body, tone = "current") {
  return `<aside class="callout callout-${tone}"><strong>${title}</strong><p>${body}</p></aside>`;
}

function pageHero({ eyebrow, title, intro, side = "" }) {
  return `<section class="page-hero shell">
    <div><p class="eyebrow">${eyebrow}</p><h1>${title}</h1><p class="lede">${intro}</p></div>
    ${side ? `<div class="hero-aside">${side}</div>` : ""}
  </section>`;
}

function lifecycleVisual() {
  return `<figure class="lifecycle-figure">
    <svg viewBox="0 0 920 430" role="img" aria-labelledby="lifecycle-title lifecycle-description">
      <title id="lifecycle-title">AcmeMux current foundation and lifecycle direction</title>
      <desc id="lifecycle-description">One current upstream lego operations foundation connects to eight directional certificate lifecycle capability families.</desc>
      <defs><marker id="arrowhead" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto"><path d="M0 0 9 3 0 6Z" /></marker></defs>
      <g class="visual-links" marker-end="url(#arrowhead)">
        <path d="M310 215H405"/><path d="M500 215H590"/><path d="M450 170V90"/><path d="M450 260v78"/>
        <path d="M405 185 330 105"/><path d="m500 185 80-80"/><path d="m405 245-80 82"/><path d="m500 245 82 82"/>
      </g>
      <g class="visual-direction">
        <rect x="30" y="55" width="265" height="74" rx="16"/><text x="54" y="85">DISCOVER</text><text x="54" y="108">Inventory and ownership</text>
        <rect x="625" y="55" width="265" height="74" rx="16"/><text x="649" y="85">ISSUE</text><text x="649" y="108">Public, private, external</text>
        <rect x="30" y="301" width="265" height="74" rx="16"/><text x="54" y="331">GOVERN</text><text x="54" y="354">Policy and approvals</text>
        <rect x="625" y="301" width="265" height="74" rx="16"/><text x="649" y="331">CONNECT</text><text x="649" y="354">Alerts, APIs, integrations</text>
        <rect x="327" y="25" width="246" height="70" rx="16"/><text x="351" y="54">CONTROL</text><text x="351" y="77">Identity and team access</text>
        <rect x="327" y="335" width="246" height="70" rx="16"/><text x="351" y="364">RECOVER</text><text x="351" y="387">Backup and resilience</text>
      </g>
      <g class="visual-current"><rect x="330" y="171" width="260" height="90" rx="22"/><text x="460" y="205" text-anchor="middle">CURRENT FOUNDATION</text><text x="460" y="231" text-anchor="middle">Verified lego operations</text><text x="460" y="250" text-anchor="middle">one native workspace</text></g>
    </svg>
    <div class="lifecycle-mobile" role="img" aria-label="The current verified upstream lego foundation grows toward eight directional certificate lifecycle capability families">
      <div class="mobile-current"><small>Current foundation - pre-release</small><strong>Verified lego operations</strong><span>One native workspace</span></div>
      <span class="mobile-growth" aria-hidden="true">grows toward</span>
      <div class="mobile-direction"><span>Discovery and inventory</span><span>Public, private, external issuance</span><span>Renewal and constrained deployment</span><span>Ownership, policy, approvals</span><span>Identity and team access</span><span>Alerts, APIs, integrations</span><span>Audit and reporting evidence</span><span>Backup, recovery, resilience</span></div>
    </div>
    <figcaption><span><i class="key-current"></i> Current pre-release foundation</span><span><i class="key-direction"></i> Product direction, not available today</span></figcaption>
  </figure>`;
}

const home = {
  route: "/",
  title: "Certificate operations with a lifecycle direction | AcmeMux",
  description:
    "Run verified upstream lego certificate operations today and follow AcmeMux toward a self-hosted certificate lifecycle control plane.",
  nav: "overview",
  bodyClass: "home-page",
  body: `<section class="home-hero">
    <div class="shell hero-grid">
      <div class="hero-copy">
        <p class="eyebrow">Open source. Self-hosted. Evidence first.</p>
        <h1>Operate certificates now.<br><span>See the whole lifecycle ahead.</span></h1>
        <p class="lede">AcmeMux is building from a deliberately small, verifiable base: one administrator operating one native upstream <code>lego</code> workspace through a focused web interface.</p>
        <div class="hero-actions"><a class="button button-primary" href="https://github.com/acmemux/AcmeMux">Inspect the source ${arrow}</a><a class="button button-secondary" href="/roadmap/">Explore the direction</a></div>
        <div class="hero-signals"><span>${stateLabel("current", "Current foundation - pre-release")} Native lego operations</span><span>${stateLabel("direction", "Direction")} Full lifecycle control</span></div>
      </div>
      <div class="hero-proof" aria-label="Current product boundary">
        <div class="proof-head"><span>Current pre-release envelope</span><span class="proof-pulse">Verified slices</span></div>
        <div class="proof-command"><small>CONTROL PLANE</small><strong>Upstream lego stays authoritative</strong><span>AcmeMux constrains, schedules, and reports the exact CLI operations.</span></div>
        <dl class="proof-facts"><div><dt>Operator</dt><dd>One admin</dd></div><div><dt>Workspace</dt><dd>One native</dd></div><div><dt>Platform</dt><dd>Debian 13</dd></div><div><dt>Telemetry</dt><dd>None</dd></div></dl>
        <a href="/certificate-status/">Inspect live dogfood evidence ${arrow}</a>
      </div>
    </div>
  </section>
  <section class="proof-strip"><div class="shell proof-strip-grid"><p><strong>What works today</strong> Configure supported CAs and challenges, issue or renew on demand, schedule daily evaluation, and inspect redacted evidence.</p><p><strong>What we are building toward</strong> Discover, own, issue, deploy, govern, audit, and recover certificates across real infrastructure.</p></div></section>
  <section class="section shell split-intro">
    <div><p class="eyebrow">A narrow base on purpose</p><h2>The first release earns trust before it expands scope.</h2></div>
    <div><p>AcmeMux does not reimplement ACME or hide its foundation. An administrator supplies an exactly qualified upstream <code>lego</code> executable. AcmeMux owns orchestration and evidence; the native workspace owns certificates and account material.</p><a class="text-link" href="/product/">Understand the current product ${arrow}</a></div>
  </section>
  <section class="section shell evidence-layout">
    <div class="application-frame"><div class="frame-bar"><span></span><span></span><span></span><strong>Synthetic application state</strong></div><img src="/assets/acmemux-application.png" alt="AcmeMux administration interface showing synthetic certificate workspace configuration and operations" width="1440" height="2099" loading="lazy"></div>
    <div class="evidence-copy"><p class="eyebrow">Current product evidence</p><h2>Operations you can inspect.</h2><p>The interface maps supported choices to upstream flags, protects secrets, serializes mutating work, and turns completed commands into redacted reports.</p><ul class="check-list"><li>Five certificate-authority integrations</li><li>HTTP-01 and five curated DNS-01 providers</li><li>On-demand issue and renew operations</li><li>Durable daily evaluation with upstream eligibility</li><li>Current certificate health and latest redacted result</li></ul><a class="text-link" href="/providers/">Review exact coverage ${arrow}</a></div>
  </section>
  <section class="section direction-section"><div class="shell"><div class="section-heading"><div><p class="eyebrow direction">The lifecycle direction</p><h2>One operator problem, seen end to end.</h2></div><p>Certificates cross discovery, issuance, activation, policy, access, evidence, and recovery. Those capability families are the destination. Each will need its own verified product slice; none is implied by the diagram.</p></div>${lifecycleVisual()}<div class="section-cta"><a class="button button-amber" href="/roadmap/">Read the state-labeled roadmap ${arrow}</a></div></div></section>
  <section class="section shell dogfood-story"><div><p class="eyebrow">The site is evidence too</p><h2>Watch AcmeMux operate its own public certificate.</h2><p>AcmeMux schedules the evaluation, and upstream lego performs issuance for this site. Separate constrained automation activates the result on the web host. The public feed exposes dates and fingerprint without exposing the administration service.</p></div><div class="dogfood-card"><span class="live-mark"><i></i> Live public evidence</span><strong>Expected replacement window</strong><p>Open the quiet dock at any time. Follow the window, inspect the evidence, or request exactly one reminder.</p><button class="button button-secondary" type="button" data-open-dogfood>Open the dogfood dock</button></div></section>`,
  schema: {
    "@type": "SoftwareApplication",
    name: "AcmeMux",
    applicationCategory: "SecurityApplication",
    operatingSystem: "Debian GNU/Linux 13 amd64",
    description:
      "A self-hosted web control plane for one native upstream lego certificate workspace.",
    url: "https://acmemux.com/",
    license: "https://www.apache.org/licenses/LICENSE-2.0",
  },
};

const product = {
  route: "/product/",
  title: "Current self-hosted certificate operations | AcmeMux",
  description:
    "See the exact AcmeMux product boundary: one administrator, one upstream lego runtime, one native workspace, scheduling, health, and evidence.",
  nav: "product",
  body: `${pageHero({
    eyebrow: "Current product",
    title: "A transparent control plane for upstream lego.",
    intro:
      "AcmeMux gives a self-hosted administrator a focused way to configure, run, schedule, and understand a qualified lego CLI without replacing the CLI or its workspace.",
    side: `${stateLabel("current", "Current foundation - pre-release")}<dl class="hero-definition"><div><dt>Release</dt><dd>No tagged release yet</dd></div><div><dt>Platform</dt><dd>Debian 13 amd64</dd></div><div><dt>Install</dt><dd>Native systemd service</dd></div></dl>`,
  })}
  <section class="section shell boundary-grid"><article><span class="number">01</span><h2>Configure</h2><p>Choose a supported certificate authority, HTTP-01 or DNS-01 challenge, domains, key type, and qualified provider fields. Secrets stay server-side.</p></article><article><span class="number">02</span><h2>Operate</h2><p>Run issue and renew actions through constrained argument construction, serialized execution, timeouts, controlled termination, and redaction.</p></article><article><span class="number">03</span><h2>Schedule</h2><p>Persist one daily evaluation time. AcmeMux invokes upstream renewal evaluation; <code>lego</code> remains authoritative for eligibility.</p></article><article><span class="number">04</span><h2>Understand</h2><p>See compatible runtime identity, workspace inventory, current health, job state, and the latest bounded report without exposing credentials.</p></article></section>
  <section class="section surface-section"><div class="shell two-column"><div><p class="eyebrow">Ownership boundary</p><h2>Your native workspace remains the source of truth.</h2><p>AcmeMux adopts one administrator-selected directory. Upstream-compatible account and certificate artifacts stay portable and directly inspectable. The product stores only its own small operational state beside that boundary.</p></div><div class="boundary-diagram" role="img" aria-label="Administrator browser connects to AcmeMux, which invokes upstream lego against the native workspace"><span>Administrator browser</span><i aria-hidden="true">-&gt;</i><strong>AcmeMux service</strong><i aria-hidden="true">-&gt;</i><span>Upstream lego + native workspace</span></div></div></section>
  <section class="section shell"><div class="section-heading"><div><p class="eyebrow">Deliberate limits</p><h2>Not hidden behind an enterprise-shaped promise.</h2></div><p>These limits are current boundaries, not the end of the product.</p></div><div class="limit-grid"><div><strong>Single administrator</strong><p>No accounts, teams, RBAC, SSO, or remote multi-user administration.</p></div><div><strong>Single workspace</strong><p>No fleet inventory, discovery, multiple workspaces, private PKI, EST, or SCEP.</p></div><div><strong>Curated compatibility</strong><p>No arbitrary provider, CA URL, executable hook, or unqualified lego version.</p></div><div><strong>No certificate deployment</strong><p>Activation and reload remain separate operator automation today.</p></div></div>${callout("Direction is explicit", "AcmeMux is growing toward lifecycle-wide inventory, issuance, deployment, policy, access, integration, audit, and recovery. The roadmap labels that direction separately from what is available.", "direction")}</section>
  <section class="section shell action-band"><div><h2>Evaluate the evidence, not a claim.</h2><p>Read the exact compatibility and security boundaries before placing AcmeMux near certificate credentials.</p></div><div><a class="button button-primary" href="https://github.com/acmemux/AcmeMux">Source and installation ${arrow}</a><a class="button button-secondary" href="/security/">Security model</a></div></section>`,
  schema: {
    "@type": "SoftwareApplication",
    name: "AcmeMux",
    applicationCategory: "SecurityApplication",
    operatingSystem: "Debian GNU/Linux 13 amd64",
    description:
      "A self-hosted control plane for one administrator and one native upstream lego workspace.",
    url: "https://acmemux.com/product/",
    license: "https://www.apache.org/licenses/LICENSE-2.0",
  },
};

const providers = {
  route: "/providers/",
  title: "Supported CAs and challenge providers | AcmeMux",
  description:
    "Review the exact certificate authorities, HTTP-01 mode, DNS-01 providers, and upstream lego compatibility boundary supported by AcmeMux.",
  nav: "providers",
  body: `${pageHero({
    eyebrow: "Exact compatibility",
    title: "Curated integrations, not a pass-through catalog.",
    intro:
      "Every option shown by AcmeMux needs a complete form, exact upstream mapping, secret handling, redaction, documentation, and qualification evidence.",
    side: `${stateLabel("current", "Current scope")}<p>Five CA brands<br>Five DNS providers<br>HTTP-01 listener or webroot</p>`,
  })}
  <section class="section shell provider-section"><div><p class="eyebrow">Certificate authorities</p><h2>Public ACME issuance</h2></div><div class="provider-list"><article><strong>Let's Encrypt</strong><span>Production and staging</span></article><article><strong>ZeroSSL</strong><span>Email-assisted registration and EAB</span></article><article><strong>Google Trust Services</strong><span>Production and staging with EAB</span></article><article><strong>SSL.com</strong><span>RSA and ECDSA endpoints with EAB</span></article><article><strong>GoDaddy</strong><span>Fixed ACME service with EAB</span></article></div></section>
  <section class="section surface-section"><div class="shell provider-section"><div><p class="eyebrow">Challenge paths</p><h2>Prove domain control</h2><p>HTTP-01 uses upstream lego's built-in listener at an administrator-selected address or an existing webroot. DNS-01 uses one of five reviewed provider integrations.</p></div><div class="provider-list two-up"><article><strong>Azure DNS</strong><span>Service principal and managed identity paths</span></article><article><strong>Cloudflare</strong><span>Scoped tokens and compatible legacy import</span></article><article><strong>DigitalOcean</strong><span>API token with supported overrides</span></article><article><strong>DuckDNS</strong><span>Token-based dynamic DNS integration</span></article><article><strong>Amazon Route 53</strong><span>AWS credential chain, profiles, roles, and zone options</span></article><article class="provider-note"><strong>HTTP-01</strong><span>Built-in listener or existing webroot; no AcmeMux public listener</span></article></div></div></section>
  <section class="section shell compatibility-copy"><div><p class="eyebrow">Runtime identity</p><h2>Compatibility is an exact evidence set.</h2></div><div><p>The administrator provisions <code>lego</code>. AcmeMux resolves the executable, records its version and SHA-256 digest, and only operates identities declared compatible by the release. A path change or binary drift returns the service to an incompatible state until it is checked again.</p>${callout("Names do not imply adjacent support", "The fixed GoDaddy ACME service is a supported certificate authority. GoDaddy DNS is not one of the five current DNS-01 integrations. Unsupported workspace choices are preserved and blocked from managed execution.")}</div></section>
  <section class="section shell action-band"><div><h2>Need a provider outside this list?</h2><p>It belongs in a bounded integration slice with tests and evidence, not an unreviewed text field.</p></div><a class="button button-secondary" href="https://github.com/acmemux/AcmeMux/discussions">Discuss coverage ${arrow}</a></section>`,
};

const security = {
  route: "/security/",
  title: "Security model and operator boundary | AcmeMux",
  description:
    "Understand AcmeMux trust boundaries, local identity, secret handling, constrained lego execution, disclosure route, and operator responsibilities.",
  nav: "security",
  body: `${pageHero({
    eyebrow: "Security model",
    title: "Small trust boundaries you can inspect.",
    intro:
      "AcmeMux holds sensitive provider configuration and can invoke a certificate client. It is designed as a local administration service, not a public multi-user control plane.",
    side: `${stateLabel("current", "Current guarantee")}<p>No telemetry<br>No browser-delivered secrets<br>Private disclosure on GitHub</p>`,
  })}
  <section class="section shell security-principles"><article><span>01</span><h2>Local identity</h2><p>A host operator creates the single administrator from a local terminal. Browser access then requires a service-side session. There is no browser bootstrap, and the administration origin must not be public.</p></article><article><span>02</span><h2>Constrained execution</h2><p>AcmeMux constructs argument vectors for supported actions. It does not accept arbitrary command text, shell hooks, provider names, or CA URLs.</p></article><article><span>03</span><h2>Server-side secrets</h2><p>Provider values are written with restrictive permissions, never returned to the browser, and redacted from command evidence and reports.</p></article><article><span>04</span><h2>Native ownership</h2><p>Upstream <code>lego</code> owns ACME behavior and its native workspace. AcmeMux does not create a second certificate store or pretend to be the protocol implementation.</p></article></section>
  <section class="section surface-section"><div class="shell responsibility-grid"><div><p class="eyebrow">Operator responsibilities</p><h2>The host is part of the security boundary.</h2></div><ul class="responsibility-list"><li><strong>Keep the service private.</strong><span>Use an HTTPS origin reachable only by intended administrators.</span></li><li><strong>Protect filesystem access.</strong><span>The service account can read its state, provider secrets, and adopted lego workspace.</span></li><li><strong>Use least-privilege provider identities.</strong><span>Scope DNS permissions to the zones and operations required.</span></li><li><strong>Qualify upgrades.</strong><span>Do not silently replace the exact lego executable or AcmeMux release.</span></li><li><strong>Own activation.</strong><span>Certificate deployment and service reload are separate automation today.</span></li></ul></div></section>
  <section class="section shell disclosure"><div><p class="eyebrow">Report a vulnerability</p><h2>Use GitHub private vulnerability reporting.</h2><p>Do not open a public issue for suspected security defects or include credentials, private keys, account material, host data, or customer information in a report.</p></div><a class="button button-primary" href="https://github.com/acmemux/AcmeMux/security/advisories/new">Open a private report ${arrow}</a></section>
  <section class="section shell release-evidence"><h2>Release evidence</h2><p>Qualified releases publish checksums and an SBOM alongside source-backed artifacts. AcmeMux does not currently claim signed provenance. Verify the exact evidence supplied with the release you install.</p><a class="text-link" href="https://github.com/acmemux/AcmeMux/releases">Inspect releases ${arrow}</a></section>`,
};

const roadmap = {
  route: "/roadmap/",
  title: "Certificate lifecycle product roadmap | AcmeMux",
  description:
    "See what AcmeMux supports now, what is being qualified, proposed product horizons, and the long-term self-hosted certificate lifecycle direction.",
  nav: "roadmap",
  body: `${pageHero({
    eyebrow: "State-labeled roadmap",
    title: "A direction without pretending it is already shipped.",
    intro:
      "AcmeMux is growing outward from verified upstream lego operations toward a self-hosted certificate lifecycle control plane. Horizons describe intent, not dates or promises.",
    side: `<p class="roadmap-legend"><span>${stateLabel("current", "Current foundation")}</span><span>${stateLabel("active", "Accepted work")}</span><span>${stateLabel("proposed", "Proposed horizon")}</span><span>${stateLabel("direction", "Long-term direction")}</span></p>`,
  })}
  <section class="section shell roadmap-stack"><article class="roadmap-band band-current"><div>${stateLabel("current", "Current foundation - pre-release")}<span class="band-number">01</span></div><div><h2>One dependable native lego workflow</h2><p>One administrator, one exact compatible runtime, one workspace, curated CA and challenge configuration, issue and renew, durable daily evaluation, health, and redacted evidence. Source is available; no tagged release exists yet.</p><a class="text-link" href="/product/">See exact support ${arrow}</a></div></article><article class="roadmap-band band-active"><div>${stateLabel("active", "Accepted work")}<span class="band-number">02</span></div><div><h2>Release confidence across the current envelope</h2><p>Source distribution, install and upgrade recovery, provider and CA smoke evidence, checksums, SBOMs, and public dogfood are being qualified. Final live-provider evidence depends on credentialed environments.</p></div></article><article class="roadmap-band band-proposed"><div>${stateLabel("proposed", "Proposed horizons")}<span class="band-number">03</span></div><div><h2>Broader day-to-day certificate operations</h2><p>Potential slices include multiple managed certificates, useful inventory and expiry views, clearer ownership, operational alerts, and constrained activation connectors. Scope, order, and architecture are not committed.</p></div></article><article class="roadmap-band band-direction"><div>${stateLabel("direction", "Long-term direction")}<span class="band-number">04</span></div><div><h2>Self-hosted lifecycle control</h2><div class="direction-capabilities"><span>Discovery and unified inventory</span><span>Public, private, and external issuance</span><span>Renewal and constrained deployment</span><span>Ownership, policy, templates, approvals</span><span>Identity and team access</span><span>Alerts, APIs, operational integrations</span><span>Audit and reporting evidence</span><span>Backup, recovery, and resilience</span></div></div></article></section>
  <section class="section shell roadmap-caveat">${callout("How to read this roadmap", "A horizon is not a release date, implementation order, support promise, or commitment to a particular architecture. Every new capability must become a bounded, tested product slice before it can move into the available state.", "direction")}</section>
  <section class="section shell action-band"><div><h2>Help choose the next verified problem.</h2><p>Describe the certificate operation that causes real work or risk in your environment.</p></div><a class="button button-secondary" href="https://github.com/acmemux/AcmeMux/discussions">Join the discussion ${arrow}</a></section>`,
};

const status = {
  route: "/certificate-status/",
  title: "Live dogfood certificate evidence | AcmeMux",
  description:
    "Inspect public dates and fingerprint for the acmemux.com dogfood certificate, its expected replacement window, and the one-time reminder contract.",
  nav: null,
  body: `${pageHero({
    eyebrow: "Live public dogfood",
    title: "The certificate is part of the product evidence.",
    intro:
      "AcmeMux schedules evaluation and invokes upstream lego, which performs issuance for this site. Separate constrained automation activates the result. This page exposes only public certificate facts.",
    side: `<span class="live-mark" data-status-page-indicator><i></i><span data-status-page-summary>Checking public feed</span></span><button class="button button-secondary" type="button" data-open-dogfood>Open live evidence</button>`,
  })}
  <section class="status-live shell" data-status-page data-state="loading"><div class="status-live-heading"><div><p class="eyebrow">Current public receipt</p><h2 data-dogfood-countdown>Loading public evidence...</h2></div><span class="state-chip" data-dogfood-state>Checking</span></div><p data-cert-basis>Public certificate metadata only. This is not a renewal-due prediction.</p><dl><div><dt>Issued</dt><dd data-cert-issued>Loading</dd></div><div><dt>Expires</dt><dd data-cert-expires>Loading</dd></div><div class="status-fingerprint"><dt>SHA-256 fingerprint</dt><dd data-cert-fingerprint>Loading</dd></div></dl></section>
  <section class="section shell status-explainer"><div><p class="eyebrow">What the countdown means</p><h2>An expected replacement window, not renewal eligibility.</h2></div><div><p>The public feed provides an estimated time when the deployed certificate should be replaced. Upstream <code>lego</code> remains authoritative about whether renewal is due. ARI, certificate lifetime, evaluation timing, issuance failure, or separate deployment delay can move the actual replacement.</p>${callout("When the counter reaches zero", "Zero means the expected window ended. It does not prove the certificate is expired, unhealthy, or that renewal failed. Inspect the current public dates and fingerprint.")}</div></section>
  <section class="section surface-section"><div class="shell evidence-chain"><div><span>1</span><strong>AcmeMux evaluates</strong><p>The scheduler asks upstream lego to evaluate renewal.</p></div><i aria-hidden="true">-&gt;</i><div><span>2</span><strong>lego issues</strong><p>ACME and provider behavior remain upstream.</p></div><i aria-hidden="true">-&gt;</i><div><span>3</span><strong>Automation activates</strong><p>A separate constrained path deploys and reloads.</p></div><i aria-hidden="true">-&gt;</i><div><span>4</span><strong>Public feed attests</strong><p>Dates and SHA-256 fingerprint can be compared to TLS.</p></div></div></section>
  <section class="section shell privacy-summary"><div><p class="eyebrow">One reminder, not a list</p><h2>The signup has one narrow purpose.</h2><p>Expand the dock to request a reminder when the expected window ends. AWS sends a confirmation first. After one reminder, the email subscription and temporary hashed abuse-prevention key are deleted. There is no newsletter or marketing profile.</p></div><button class="button button-primary" type="button" data-open-dogfood>Request one reminder</button></section>`,
};

const privacy = {
  route: "/privacy/",
  title: "Privacy and One-Time Reminder | AcmeMux",
  description:
    "AcmeMux uses no analytics or tracking. Learn what the optional one-time certificate reminder collects, how confirmation works, and when data is deleted.",
  nav: null,
  body: `${pageHero({
    eyebrow: "Privacy",
    title: "No visitor profile. One optional reminder.",
    intro:
      "The AcmeMux website uses no analytics, advertising pixels, cross-site tracking, account system, or newsletter database.",
    side: `${stateLabel("current", "Current policy")}<p>No analytics<br>No external fonts<br>No marketing email</p>`,
  })}
  <section class="section shell privacy-flow"><div><span>01</span><h2>You enter an email</h2><p>The address and an empty abuse-trap field are sent to the same-origin reminder endpoint only after you submit the form.</p></div><div><span>02</span><h2>AWS asks you to confirm</h2><p>No reminder becomes active until you use the confirmation message sent by the notification provider.</p></div><div><span>03</span><h2>One reminder is sent</h2><p>The message is tied to the expected public certificate replacement window. It is not a recurring alert or newsletter.</p></div><div><span>04</span><h2>Reminder data is deleted</h2><p>After that message, the subscription and temporary hashed abuse-prevention key are removed.</p></div></section>
  <section class="section surface-section"><div class="shell privacy-detail"><div><p class="eyebrow">What is processed</p><h2>Narrow data for a narrow purpose.</h2></div><dl><div><dt>Email address</dt><dd>Used by the notification provider to confirm and deliver the one requested reminder.</dd></div><div><dt>Temporary abuse key</dt><dd>A keyed hash helps limit repeated signup attempts without publishing the address. It is deleted with the subscription.</dd></div><div><dt>Routine service logs</dt><dd>The web host and delivery infrastructure may process normal request metadata for security and reliable operation.</dd></div><div><dt>Public certificate evidence</dt><dd>The browser reads public dates and fingerprint. This contains no visitor data.</dd></div></dl></div></section>
  <section class="section shell privacy-choices"><div><h2>Your choice and control</h2><p>Do not submit the form if you do not want the address processed. An unconfirmed request expires according to the notification provider's behavior. The reminder is not an AcmeMux product account and is not connected to the private administration service.</p></div><div><h2>Source you can inspect</h2><p>The website behavior is open source. It does not load third-party JavaScript or fonts, and it does not write a tracking identifier in your browser.</p><a class="text-link" href="https://github.com/acmemux/AcmeMux/tree/main/site">Inspect website source ${arrow}</a></div></section>`,
};

const contribute = {
  route: "/contribute/",
  title: "Contribute to AcmeMux",
  description:
    "Help AcmeMux through testing, documentation, provider research, roadmap discussion, DCO-signed pull requests, or private vulnerability reports.",
  nav: null,
  body: `${pageHero({
    eyebrow: "Open-source participation",
    title: "Help turn operator pain into verified product slices.",
    intro:
      "Useful contributions start with a concrete certificate operation, a reproducible failure, or evidence that makes a boundary safer and clearer.",
    side: `<a class="button button-primary" href="https://github.com/acmemux/AcmeMux">Open the repository ${arrow}</a>`,
  })}
  <section class="section shell contribution-grid"><article><span>Discuss</span><h2>Shape the problem</h2><p>Use Discussions for experience reports, product questions, and proposed lifecycle needs before assuming an implementation.</p><a href="https://github.com/acmemux/AcmeMux/discussions">Start a discussion ${arrow}</a></article><article><span>Report</span><h2>Make defects reproducible</h2><p>Use public issues for non-sensitive bugs and include the smallest safe environment and behavior evidence.</p><a href="https://github.com/acmemux/AcmeMux/issues">Review issues ${arrow}</a></article><article><span>Improve</span><h2>Test, document, research</h2><p>Provider qualification, recovery cases, operator documentation, accessibility, and careful review all move the project forward.</p><a href="https://github.com/acmemux/AcmeMux/pulls">Review pull requests ${arrow}</a></article><article><span>Protect</span><h2>Disclose privately</h2><p>Suspected vulnerabilities and sensitive evidence belong in GitHub private vulnerability reporting, never a public issue.</p><a href="https://github.com/acmemux/AcmeMux/security/advisories/new">Open a private report ${arrow}</a></article></section>
  <section class="section surface-section"><div class="shell contribution-note"><div><p class="eyebrow">Pull requests</p><h2>Small, attributable, reviewable changes.</h2></div><div><p>Contributions require Developer Certificate of Origin sign-off. A proposal or pull request does not create a response time, merge promise, support agreement, or commitment to ship a feature.</p><p>Start with the public issue or discussion context so reviewers can evaluate the operator outcome and security boundary, not only the code shape.</p></div></div></section>`,
};

const sponsor = {
  route: "/sponsor/",
  title: "Support AcmeMux Development",
  description:
    "Support independent, open-source certificate tooling. Sponsorship helps maintenance and verified roadmap work without buying support or unsafe shortcuts.",
  nav: null,
  body: `${pageHero({
    eyebrow: "Support the work",
    title: "Fund evidence, maintenance, and careful expansion.",
    intro:
      "AcmeMux is independent open-source infrastructure work. Support can create room for qualification and documentation without turning roadmap states into sales promises.",
    side: `${stateLabel("direction", "No entitlement")}<p>No SLA<br>No feature guarantee<br>No bypass around verification</p>`,
  })}
  <section class="section shell funding-grid"><article><span>Maintain</span><h2>Keep the foundation dependable</h2><p>Dependency review, security response, compatibility qualification, install and recovery testing, and public documentation need ongoing attention.</p></article><article><span>Verify</span><h2>Test real integrations</h2><p>CA and DNS provider evidence requires isolated environments, safe credentials, repeatable fixtures, and careful review.</p></article><article><span>Expand</span><h2>Research lifecycle slices</h2><p>Discovery, deployment, policy, identity, audit, and recovery each need product and security work before implementation.</p></article></section>
  <section class="section surface-section"><div class="shell sponsor-boundary"><div><p class="eyebrow">Sponsorship boundary</p><h2>Support does not purchase the roadmap.</h2></div><div><p>Sponsorship supports maintenance and qualified roadmap work; it does not provide an SLA, private support channel, logo placement, implementation priority, or guarantee of feature delivery.</p><p>A specific product need should begin as a public proposal that can be evaluated against the same operator value, security, and verification standards.</p><a class="button button-secondary" href="https://github.com/acmemux/AcmeMux/discussions">Discuss a product need ${arrow}</a></div></div></section>
  <section class="section shell sponsor-wait"><p class="eyebrow">Funding route</p><h2>A direct funding channel is being prepared.</h2><p>Until a reviewed public route appears here, no one is authorized to collect sponsorship on behalf of AcmeMux. You can still help through testing, documentation, and grounded product discussion.</p><a class="text-link" href="/contribute/">Ways to contribute ${arrow}</a></section>`,
};

const guides = [
  {
    href: "/learn/lets-encrypt-short-lived-certificates/",
    label: "Lifecycle readiness",
    title: "Let's Encrypt short-lived certificates",
    text: "What six-day TLS changes for issuance, activation, monitoring, retries, and recovery.",
  },
  {
    href: "/learn/acme-dns-01-challenge/",
    label: "ACME fundamentals",
    title: "The DNS-01 challenge explained",
    text: "How TXT validation works, where propagation fails, and how to limit DNS authority.",
  },
  {
    href: "/learn/lego-certificate-management/",
    label: "Safe operations",
    title: "Operating the lego client safely",
    text: "Protect a native workspace with exact runtime identity, scoped secrets, and serialized work.",
  },
  {
    href: "/learn/certificate-renewal-automation/",
    label: "Reliable automation",
    title: "Certificate renewal is a pipeline",
    text: "Separate evaluation, issuance, activation, served-leaf verification, and recovery.",
  },
  {
    href: "/learn/lets-encrypt-route-53/",
    label: "Provider guide",
    title: "Let's Encrypt DNS-01 with Route 53",
    text: "Plan hosted-zone targeting, least-privilege IAM, identity, and renewal checks.",
  },
];

function guideCards() {
  return guides
    .map(
      (guide, index) =>
        `<a class="guide-card" href="${guide.href}"><span class="guide-number">0${index + 1}</span><p class="eyebrow">${guide.label}</p><h2>${guide.title}</h2><p>${guide.text}</p><span class="guide-arrow">Read guide ${arrow}</span></a>`,
    )
    .join("");
}

const learn = {
  route: "/learn/",
  title: "Learn ACME Certificate Automation | AcmeMux",
  description:
    "Practical guides to ACME, DNS-01, lego, certificate renewal, deployment boundaries, and reliable self-hosted certificate operations.",
  nav: "learn",
  body: `${pageHero({
    eyebrow: "Operator field notes",
    title: "Understand the boundaries before automating certificates.",
    intro:
      "Practical guides connect ACME mechanics to credential scope, deployment, observation, and recovery. Product support is always labeled separately from general guidance.",
  })}<section class="section shell guide-grid">${guideCards()}</section>
  <section class="section surface-section"><div class="shell learn-principle"><div><p class="eyebrow">The recurring lesson</p><h2>Issuance is only one stage.</h2></div><p>A reliable lifecycle also needs inventory, ownership, safe activation, served-certificate checks, alerts, evidence, and recovery. AcmeMux only claims the stages inside its current verified boundary; the rest defines where the product is going.</p></div></section>`,
};

function articleHero({ label, title, intro }) {
  return `<section class="article-hero shell"><a class="back-link" href="/learn/">${arrow} All guides</a><p class="eyebrow">${label}</p><h1>${title}</h1><p class="lede">${intro}</p></section>`;
}

function article({ route, title, description, label, heading, intro, body }) {
  return {
    route,
    title,
    description,
    nav: "learn",
    kind: "article",
    bodyClass: "article-page",
    body: `${articleHero({ label, title: heading, intro })}<article class="article-body shell">${body}</article><section class="shell article-end"><p>Keep going</p><a href="/learn/">Browse all certificate operations guides ${arrow}</a></section>`,
    schema: {
      "@type": "Article",
      headline: heading,
      description,
      mainEntityOfPage: `https://acmemux.com${route}`,
      author: { "@type": "Organization", name: "AcmeMux" },
      publisher: { "@type": "Organization", name: "AcmeMux" },
    },
  };
}

const shortLived = article({
  route: "/learn/lets-encrypt-short-lived-certificates/",
  title: "Let's Encrypt Short-Lived Certificates | AcmeMux",
  description:
    "Learn how Let's Encrypt short-lived certificates change renewal, deployment, monitoring, rate-limit, and recovery requirements.",
  label: "Lifecycle readiness",
  heading: "Let's Encrypt short-lived certificates: what six-day TLS changes",
  intro:
    "A shorter lifetime compresses the time available to notice, diagnose, issue, activate, and verify a replacement. It changes the operating system around ACME more than the request itself.",
  body: `<section><h2>Profile choice is not an aggressive renewal flag</h2><p>A short-lived certificate profile is a CA-side certificate choice. Repeatedly renewing a classic certificate early does not produce the same contract and can create needless issuance and rate-limit pressure.</p><p>Treat the profile, renewal information, and actual certificate lifetime as evidence. Do not infer them from a generic countdown.</p></section>
  <section><h2>The failure budget becomes roughly 160 hours</h2><p>With a certificate lasting only several days, a daily check can consume a meaningful part of the remaining lifetime. A failure can sit in issuance, DNS propagation, deployment, reload, or served-leaf verification. Alerting and retries need enough time to preserve a safe manual recovery path.</p></section>
  <section><h2>Readiness spans the entire activation chain</h2><ol><li>Evaluate using authoritative renewal information when available.</li><li>Issue without corrupting the currently valid artifact.</li><li>Activate atomically and reload the serving process safely.</li><li>Compare the certificate actually served with the intended artifact.</li><li>Escalate with enough remaining lifetime to recover.</li></ol></section>
  <section><h2>ARI helps; observation still matters</h2><p>ACME Renewal Information can give clients a CA-selected window and improve retry behavior. It does not prove DNS changes propagated, a deployment succeeded, or the new leaf reached every endpoint. Observe each boundary before deciding the next action.</p></section>
  ${callout("Current AcmeMux support", "Short-lived certificate profiles are not supported in the current managed product. An adopted configuration using an unsupported profile is preserved and blocked from managed operation. The acmemux.com dogfood certificate uses the classic Let's Encrypt profile.")}
  <section><h2>Primary references</h2><ul><li><a href="https://letsencrypt.org/2025/02/20/first-short-lived-cert-issued">Let's Encrypt short-lived certificate announcement</a></li><li><a href="https://www.rfc-editor.org/rfc/rfc9773.html">RFC 9773: ACME Renewal Information</a></li><li><a href="https://letsencrypt.org/docs/rate-limits/">Let's Encrypt rate limits</a></li></ul></section>`,
});

const dnsChallenge = article({
  route: "/learn/acme-dns-01-challenge/",
  title: "ACME DNS-01 Challenge Explained | AcmeMux",
  description:
    "Learn how DNS-01 proves domain control, enables wildcard certificates, handles TXT propagation, and limits DNS credential authority.",
  label: "ACME fundamentals",
  heading: "The ACME DNS-01 challenge, without the magic",
  intro:
    "DNS-01 proves control by placing a short-lived TXT value at a defined DNS name. The simple transaction crosses credentials, authoritative zones, caches, propagation, validation, and cleanup.",
  body: `<section><h2>The validation transaction</h2><p>The ACME server supplies a token. The client derives a key authorization and publishes it as a TXT record below <code>_acme-challenge</code>. The CA queries public DNS, compares the value, and accepts or rejects the authorization. The record can then be cleaned up.</p></section>
  <section><h2>Why DNS-01 enables wildcards</h2><p>A wildcard name cannot be validated with HTTP-01. DNS-01 proves control at the DNS boundary and can authorize both an apex name and its wildcard when the correct challenges are published.</p></section>
  <section><h2>Propagation is an evidence problem</h2><p>A provider API returning success only proves the write was accepted. Authoritative nameservers and recursive resolvers may not see the value at the same moment. Reliable automation checks the intended authoritative path and uses bounded waits rather than blind sleep.</p></section>
  <section><h2>Limit DNS credential authority</h2><p>A certificate client should not need broad account control. Prefer a dedicated identity limited to the required zones and record operations. Where practical, delegate the challenge label to a narrower zone and keep the credential off unrelated hosts.</p></section>
  ${callout("AcmeMux boundary", "AcmeMux configures only its five supported DNS provider integrations and protects their server-side values. Upstream lego performs provider and ACME behavior. Arbitrary providers, manual input, and executable hooks are not current managed options.")}
  <section><h2>Clean up conservatively</h2><p>Ambiguous results need care. Removing a record too early can break an in-flight validation; leaving stale values forever adds confusion. Capture the provider result, validation result, and cleanup result separately so recovery can start from facts.</p></section>`,
});

const legoGuide = article({
  route: "/learn/lego-certificate-management/",
  title: "Operating the lego ACME Client Safely | AcmeMux",
  description:
    "Use one native lego workspace safely with exact runtime identity, scoped credentials, serialized operations, renewal scheduling, and clear ownership.",
  label: "Safe operations",
  heading: "Operating the lego ACME client safely",
  intro:
    "The lego CLI is intentionally direct and powerful. Reliable operation comes from making its executable, workspace, provider environment, mutation, schedule, and activation boundaries explicit.",
  body: `<section><h2>Keep one authoritative workspace</h2><p>Account registrations, certificates, and related metadata belong together. Avoid shadow databases or competing writers that can disagree with native artifacts. Back up the workspace with permissions and recovery behavior intact.</p></section>
  <section><h2>Know the exact executable</h2><p>A version string is useful but not sufficient when behavior matters. Resolve the path, record a digest, and treat a changed binary as a new compatibility identity that needs review.</p></section>
  <section><h2>Constrain provider configuration</h2><p>Pass only the environment required by the selected provider. Use least-privilege identities, restrict secret-file permissions, redact output, and never accept arbitrary shell text as a shortcut for integration work.</p></section>
  <section><h2>Serialize mutation and let lego evaluate</h2><p>Concurrent issue or renew commands can contend over the same account and certificate files. Serialize mutating work. Run evaluation on a durable schedule, but let upstream lego and CA renewal information determine whether replacement is due.</p></section>
  <section><h2>Keep deployment separate and observable</h2><p>Successful issuance does not mean a service is presenting the new leaf. Activate with a constrained, atomic process, reload safely, and compare the served certificate after the change.</p></section>
  ${callout("Current AcmeMux boundary", "AcmeMux applies these controls to one qualified upstream lego runtime and one adopted workspace. It provides curated configuration, serialized operations, daily evaluation, health, and redacted results. Certificate deployment remains separate automation.")}
  <section><h2>Operator checklist</h2><ul><li>Pin and verify the intended lego executable.</li><li>Protect and back up the complete native workspace.</li><li>Scope provider credentials to the minimum authority.</li><li>Prevent competing mutating writers.</li><li>Observe issuance, activation, and the served leaf separately.</li><li>Practice recovery before certificate lifetime becomes the deadline.</li></ul></section>`,
});

const renewalGuide = article({
  route: "/learn/certificate-renewal-automation/",
  title: "Reliable Certificate Renewal Automation | AcmeMux",
  description:
    "Design certificate renewal around ARI, safe retries, atomic activation, served-certificate verification, and conservative recovery after failure.",
  label: "Reliable automation",
  heading: "Certificate renewal is a pipeline, not a cron line",
  intro:
    "A dependable replacement moves through evaluation, authorization, issuance, storage, activation, reload, and served-leaf verification. Each boundary can succeed while the next one fails.",
  body: `<section><h2>Separate the stages</h2><div class="inline-pipeline"><span>Evaluate</span><i>-&gt;</i><span>Authorize</span><i>-&gt;</i><span>Issue</span><i>-&gt;</i><span>Store</span><i>-&gt;</i><span>Activate</span><i>-&gt;</i><span>Verify</span></div><p>Record evidence at each stage. A certificate file appearing on disk is not proof that the endpoint changed. A successful reload is not proof that every listener presents the intended chain.</p></section>
  <section><h2>Use authoritative timing</h2><p>When the CA supplies ACME Renewal Information, the client can use its suggested window. Otherwise the client applies its supported lifetime policy. A scheduler should trigger evaluation, not invent a competing definition of due.</p></section>
  <section><h2>Observe before retrying</h2><p>Blind retries can multiply DNS records, consume rate limits, or obscure an ambiguous success. Reconcile the native workspace, provider state, and served leaf before repeating a mutating operation.</p></section>
  <section><h2>Activate atomically</h2><p>Validate the candidate, preserve the known-good certificate, change references or files as one constrained operation, and make reload failure recoverable. Keep certificate and private-key pairing intact.</p></section>
  <section><h2>Verify what clients receive</h2><p>Connect to the public endpoint with the intended server name and compare subject names, validity, issuer, and fingerprint. Multi-node or cached paths may require more than one observation.</p></section>
  ${callout("Current AcmeMux boundary", "AcmeMux covers reviewed lego evaluation and issuance, durable daily scheduling, native workspace health, and bounded results. Deployment remains separate. Constrained deployment is product direction, not current support.")}
  <section><h2>Recover conservatively</h2><p>Keep the last known-good certificate available, preserve evidence, avoid destructive cleanup during ambiguity, and escalate while enough lifetime remains for a manual path. Recovery is part of renewal design, not an afterthought.</p></section>`,
});

const route53Guide = article({
  route: "/learn/lets-encrypt-route-53/",
  title: "Let's Encrypt DNS-01 with Route 53 | AcmeMux",
  description:
    "Plan least-privilege Route 53 DNS-01 for Let's Encrypt and lego, including hosted-zone targeting, TXT restrictions, identity, and renewal checks.",
  label: "Provider guide",
  heading: "Let's Encrypt DNS-01 with Amazon Route 53",
  intro:
    "A reliable Route 53 setup identifies the authoritative hosted zone, grants only the DNS changes and reads required, uses a host-appropriate AWS identity, and verifies propagation before validation.",
  body: `<section><h2>Follow the validation transaction</h2><p>Upstream lego asks Route 53 to create the ACME TXT record, waits for usable DNS evidence, asks Let's Encrypt to validate, and then removes the challenge value. AcmeMux configures and invokes that supported path; it does not implement AWS or ACME protocols.</p></section>
  <section><h2>Target the intended hosted zone</h2><p>Accounts can contain public and private zones with similar names. Make the zone decision explicit and confirm that public authoritative nameservers for the certificate name lead to the selected zone.</p></section>
  <section><h2>Keep IAM authority narrow</h2><p>Use a dedicated identity. Limit record changes to the intended hosted zone and, when policy capabilities allow, TXT changes under the ACME challenge name. Permit only the list and change-status reads the client requires.</p></section>
  <section><h2>Choose identity for the host</h2><p>Prefer the AWS credential chain appropriate to the runtime: a narrowly scoped role on AWS, or a protected profile or static credential where ambient identity is unavailable. Avoid long-lived broad keys and shared personal credentials.</p></section>
  ${callout("Supported now", "AcmeMux supports Route 53 through the ambient AWS credential chain, protected static values, shared profiles, assume-role configuration, hosted-zone selection, and private-zone options. Upstream lego owns the integration behavior.")}
  <section><h2>Preflight before the first renewal</h2><ul><li>Confirm public DNS delegation and hosted-zone identity.</li><li>Test the exact service-account credential path.</li><li>Check that only required Route 53 actions are allowed.</li><li>Observe TXT propagation through authoritative DNS.</li><li>Run staging issuance before production.</li><li>Verify the stored artifact and separately activated leaf.</li></ul></section>`,
});

const notFound = {
  route: "/404.html",
  title: "Page not found | AcmeMux",
  description:
    "The requested AcmeMux page could not be found. Return to current product information, the roadmap, or certificate operations guides.",
  indexable: false,
  nav: null,
  bodyClass: "not-found-page",
  body: `<section class="not-found shell"><p class="eyebrow">404 / route unavailable</p><h1>This certificate path does not resolve.</h1><p>The page may have moved, but the current product boundary and lifecycle direction are still easy to find.</p><div><a class="button button-primary" href="/">Return to overview</a><a class="button button-secondary" href="/learn/">Browse guides</a></div></section>`,
};

export const pages = [
  home,
  product,
  providers,
  security,
  roadmap,
  status,
  privacy,
  contribute,
  sponsor,
  learn,
  shortLived,
  dnsChallenge,
  legoGuide,
  renewalGuide,
  route53Guide,
  notFound,
];
