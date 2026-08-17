const navigation = [
  ["overview", "Overview", "/"],
  ["product", "Product", "/product/"],
  ["roadmap", "Roadmap", "/roadmap/"],
  ["providers", "Providers", "/providers/"],
  ["security", "Security", "/security/"],
  ["learn", "Learn", "/learn/"],
];

const organization = {
  "@type": "Organization",
  description:
    "Open-source self-hosted certificate operations growing toward lifecycle control.",
  email: "contact@certleap.net",
  logo: "https://acmemux.com/favicon.svg",
  name: "AcmeMux",
  sameAs: ["https://github.com/acmemux"],
  url: "https://acmemux.com/",
};

function brandMark() {
  return `<svg class="brand-mark" viewBox="0 0 44 44" aria-hidden="true">
    <rect x="1" y="1" width="42" height="42" rx="12" />
    <path d="M10 31 19 11h6l9 20h-6.5l-1.8-4.5h-7.8L17 31h-7Zm10.7-9.5h3.1L22.2 17l-1.5 4.5Z" />
  </svg>`;
}

function header(active) {
  const links = navigation
    .map(([key, label, href]) => {
      const current = key === active ? ' aria-current="page"' : "";
      return `<a href="${href}"${current}>${label}</a>`;
    })
    .join("");
  return `<header class="site-header">
    <div class="shell header-inner">
      <a class="brand" href="/" aria-label="AcmeMux home">${brandMark()}<span>AcmeMux</span></a>
      <button class="menu-button" type="button" aria-expanded="false" aria-controls="primary-navigation" data-nav-toggle>
        <span>Menu</span><span class="menu-glyph" aria-hidden="true"></span>
      </button>
      <nav id="primary-navigation" class="primary-navigation" aria-label="Primary navigation" data-site-nav>${links}</nav>
      <a class="header-github" href="https://github.com/acmemux/AcmeMux">GitHub <span aria-hidden="true">-&gt;</span></a>
    </div>
  </header>`;
}

function footer() {
  return `<footer class="site-footer">
    <div class="shell footer-grid">
      <div class="footer-brand"><a class="brand" href="/">${brandMark()}<span>AcmeMux</span></a><p>Self-hosted certificate operations, built outward from a verified upstream lego foundation.</p></div>
      <div><strong>Product</strong><a href="/product/">Current product</a><a href="/roadmap/">Direction</a><a href="/providers/">Coverage</a><a href="/certificate-status/">Live proof</a></div>
      <div><strong>Project</strong><a href="https://github.com/acmemux/AcmeMux">Source</a><a href="/contribute/">Contribute</a><a href="/sponsor/">Sponsor</a><a href="mailto:contact@certleap.net?subject=AcmeMux%20inquiry">Contact</a><a href="/privacy/">Privacy</a></div>
      <div><strong>Operate safely</strong><a href="/security/">Security model</a><a data-private-report href="https://github.com/acmemux/AcmeMux/security/policy">Report privately</a><a href="https://github.com/acmemux/AcmeMux/discussions">Discussions</a><a href="/sitemap.xml">Sitemap</a></div>
    </div>
    <div class="shell footer-floor"><span>Apache-2.0 open source. No product or website telemetry.</span><span>acmemux.com</span></div>
  </footer>`;
}

function dogfoodDock() {
  return `<aside class="dogfood-dock" aria-label="Live dogfood certificate" data-dogfood-dock data-state="loading">
    <button class="dogfood-toggle" type="button" aria-expanded="false" aria-controls="dogfood-panel" data-dock-toggle>
      <span class="status-light" aria-hidden="true"></span>
      <span><small>Live dogfood</small><strong data-dogfood-summary>Loading public evidence</strong></span>
      <span class="dogfood-chevron" aria-hidden="true">+</span>
    </button>
    <div class="dogfood-panel" id="dogfood-panel" hidden data-dock-panel>
      <div class="dogfood-panel-heading"><div><p class="overline">Expected replacement window</p><strong data-dogfood-countdown>Loading...</strong></div><span class="state-chip" data-dogfood-state>Checking</span></div>
      <p class="dogfood-basis" data-cert-basis>Public certificate metadata only. This is not a renewal-due prediction.</p>
      <dl class="dogfood-evidence"><div><dt>Issued</dt><dd data-cert-issued>Loading</dd></div><div><dt>Expires</dt><dd data-cert-expires>Loading</dd></div><div class="fingerprint-evidence"><dt>SHA-256 fingerprint</dt><dd data-cert-fingerprint>Loading</dd></div></dl>
      <form class="reminder-form" action="/api/renewal-alerts/subscriptions" method="post" data-reminder-form>
        <label for="dogfood-email">One reminder when the window ends</label>
        <div class="reminder-row"><input id="dogfood-email" name="email" type="email" inputmode="email" autocomplete="email" maxlength="254" placeholder="you@example.com" required><button type="submit" data-reminder-submit>Remind me</button></div>
        <div class="honeypot" aria-hidden="true"><label for="dogfood-website">Website</label><input id="dogfood-website" name="website" type="text" tabindex="-1" autocomplete="off"></div>
        <p class="form-note">AWS asks you to confirm. One message only; then the subscription and temporary hashed abuse key are deleted. <a href="/privacy/">Privacy</a>.</p>
        <p class="form-result" role="status" aria-live="polite" data-reminder-result></p>
      </form>
      <a class="dock-detail-link" href="/certificate-status/">Inspect the public evidence <span aria-hidden="true">-&gt;</span></a>
    </div>
  </aside>`;
}

function breadcrumbSchema(page) {
  if (page.route === "/" || page.indexable === false) return null;
  const parts = page.route.split("/").filter(Boolean);
  const items = [
    {
      "@type": "ListItem",
      item: "https://acmemux.com/",
      name: "Home",
      position: 1,
    },
  ];
  let path = "";
  parts.forEach((part, index) => {
    path += `/${part}`;
    items.push({
      "@type": "ListItem",
      item: `https://acmemux.com${path}/`,
      name:
        index === parts.length - 1
          ? page.title.replace(" | AcmeMux", "")
          : part.charAt(0).toUpperCase() + part.slice(1),
      position: index + 2,
    });
  });
  return { "@type": "BreadcrumbList", itemListElement: items };
}

function schemas(page) {
  const graph = [
    organization,
    {
      "@type": "WebSite",
      description:
        "Current AcmeMux product evidence, operator guidance, and certificate lifecycle direction.",
      inLanguage: "en",
      name: "AcmeMux",
      url: "https://acmemux.com/",
    },
  ];
  const breadcrumb = breadcrumbSchema(page);
  if (breadcrumb) graph.push(breadcrumb);
  if (page.schema) graph.push(page.schema);
  return JSON.stringify({
    "@context": "https://schema.org",
    "@graph": graph,
  }).replaceAll("<", "\\u003c");
}

export function renderPage(page) {
  const canonical = `https://acmemux.com${page.route}`;
  const robots =
    page.indexable === false
      ? "noindex,nofollow"
      : "index,follow,max-image-preview:large,max-snippet:-1";
  const type = page.kind === "article" ? "article" : "website";
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${page.title}</title>
  <meta name="description" content="${page.description}">
  <meta name="robots" content="${robots}">
  <meta name="theme-color" content="#071015">
  <link rel="canonical" href="${canonical}">
  <link rel="icon" href="/favicon.svg" type="image/svg+xml">
  <link rel="manifest" href="/site.webmanifest">
  <link rel="stylesheet" href="/assets/styles.css">
  <meta property="og:type" content="${type}">
  <meta property="og:site_name" content="AcmeMux">
  <meta property="og:title" content="${page.title.replace(" | AcmeMux", "")}">
  <meta property="og:description" content="${page.description}">
  <meta property="og:url" content="${canonical}">
  <meta property="og:image" content="https://acmemux.com/assets/social-card.png">
  <meta property="og:image:type" content="image/png">
  <meta property="og:image:width" content="1200">
  <meta property="og:image:height" content="630">
  <meta property="og:image:alt" content="AcmeMux certificate operations and lifecycle direction">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="${page.title.replace(" | AcmeMux", "")}">
  <meta name="twitter:description" content="${page.description}">
  <meta name="twitter:image" content="https://acmemux.com/assets/social-card.png">
  <meta name="twitter:image:alt" content="AcmeMux certificate operations and lifecycle direction">
  <script type="application/ld+json">${schemas(page)}</script>
  <script src="/assets/site.js" defer></script>
</head>
<body class="${page.bodyClass ?? ""}" data-route="${page.route}" data-dogfood-page-state="loading">
  <a class="skip-link" href="#main-content">Skip to content</a>
  ${header(page.nav)}
  <main id="main-content">${page.body}</main>
  ${footer()}
  ${dogfoodDock()}
</body>
</html>
`;
}
