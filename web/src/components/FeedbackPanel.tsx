import type { StatusTone } from "./StatusBadge";
import { StatusBadge } from "./StatusBadge";

export function FeedbackPanel({
  tone,
  title,
  children,
  announcement = "off",
}: {
  tone: StatusTone;
  title: string;
  children: React.ReactNode;
  announcement?: "off" | "polite" | "assertive";
}) {
  const role =
    announcement === "assertive"
      ? "alert"
      : announcement === "polite"
        ? "status"
        : undefined;
  return (
    <section className={`am-feedback am-feedback--${tone}`} role={role}>
      <StatusBadge tone={tone}>{title}</StatusBadge>
      <div className="am-feedback__body">{children}</div>
    </section>
  );
}
