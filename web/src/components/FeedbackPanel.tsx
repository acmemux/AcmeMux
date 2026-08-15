import type { StatusTone } from "./StatusBadge";
import { StatusBadge } from "./StatusBadge";
import type { Ref } from "react";

export function FeedbackPanel({
  tone,
  title,
  children,
  announcement = "off",
  headingRef,
  headingTabIndex,
}: {
  tone: StatusTone;
  title: string;
  children: React.ReactNode;
  announcement?: "off" | "polite" | "assertive";
  headingRef?: Ref<HTMLHeadingElement>;
  headingTabIndex?: number;
}) {
  const role =
    announcement === "assertive"
      ? "alert"
      : announcement === "polite"
        ? "status"
        : undefined;
  return (
    <section className={`am-feedback am-feedback--${tone}`} role={role}>
      {headingRef ? (
        <h3
          className="am-feedback__heading"
          ref={headingRef}
          tabIndex={headingTabIndex}
        >
          <StatusBadge tone={tone}>{title}</StatusBadge>
        </h3>
      ) : (
        <StatusBadge tone={tone}>{title}</StatusBadge>
      )}
      <div className="am-feedback__body">{children}</div>
    </section>
  );
}
