import type { StatusTone } from "./StatusBadge";
import { StatusBadge } from "./StatusBadge";

export function FeedbackPanel({
  tone,
  title,
  children,
}: {
  tone: StatusTone;
  title: string;
  children: React.ReactNode;
}) {
  const role = tone === "danger" ? "alert" : "status";
  return (
    <section className={`am-feedback am-feedback--${tone}`} role={role}>
      <StatusBadge tone={tone}>{title}</StatusBadge>
      <div className="am-feedback__body">{children}</div>
    </section>
  );
}
