export function BrandMark({ decorative = false }: { decorative?: boolean }) {
  return (
    <svg
      className="am-brand-mark"
      viewBox="0 0 40 40"
      role={decorative ? undefined : "img"}
      aria-label={decorative ? undefined : "AcmeMux"}
      aria-hidden={decorative || undefined}
    >
      <rect x="1" y="1" width="38" height="38" rx="3" />
      <path d="M10 27V13h5.5l4.5 8 4.5-8H30v14h-4V18l-4.5 8h-3L14 18v9z" />
    </svg>
  );
}
