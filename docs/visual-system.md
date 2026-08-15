# Visual system

AcmeMux uses a dark operational visual foundation with restrained cyan and
amber accents. Strong hierarchy, large primary type, generous spacing, and
fast-scanning status treatments keep dense runtime and workspace evidence
legible. Technical detail is progressively disclosed instead of competing
with certificate health and the next safe action.

## Component rules

- Tokens under `web/src/styles/` own color, type, spacing, radius, elevation,
  motion, responsive layout, and focus conventions.
- Semantic components under `web/src/components/` own shared controls, fields,
  dialogs, feedback, loading, status, and error behavior.
- `react-aria-components` supplies headless interaction and accessibility
  behavior. It does not supply the visual theme.
- Every operational state uses text and a distinct mark in addition to color.
- System fonts and repository-authored CSS and SVG are the only visual assets.
  There are no external fonts, external images, or image-based controls.
- Feature screens must represent unavailable or unknown evidence honestly.
  Demonstration data belongs only in the component catalog and is labeled as
  illustrative.

The isolated catalog is available in development at
`/?catalog=components`. Run `make catalog` to open it, `make test-visual` for
the tracked Playwright snapshots, and `make test-accessibility` for WCAG,
keyboard, focus, reflow, reduced-motion, and narrow-viewport checks.

## Operational vocabulary

The shared status system covers normal, loading, success, warning, error,
unsupported, partial, interrupted, and not-attempted outcomes. Components also
demonstrate hover, focus, disabled, pending, empty, and dialog states. Later
feature work extends this vocabulary only when product evidence requires a
genuinely different meaning.
