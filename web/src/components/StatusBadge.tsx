export type StatusTone =
  | "neutral"
  | "info"
  | "success"
  | "warning"
  | "danger"
  | "unsupported"
  | "partial"
  | "interrupted"
  | "not-attempted";

const marks: Record<StatusTone, string> = {
  neutral: "--",
  info: "i",
  success: "OK",
  warning: "!",
  danger: "X",
  unsupported: "?",
  partial: "1/2",
  interrupted: "||",
  "not-attempted": "--",
};

export function StatusBadge({
  tone,
  children,
}: {
  tone: StatusTone;
  children: React.ReactNode;
}) {
  return (
    <span className={`am-status am-status--${tone}`}>
      <span className="am-status__mark" aria-hidden="true">
        {marks[tone]}
      </span>
      <span>{children}</span>
    </span>
  );
}
