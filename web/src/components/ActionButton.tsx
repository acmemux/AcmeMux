import {
  Button as AriaButton,
  type ButtonProps as AriaButtonProps,
} from "react-aria-components";
import type { ReactNode } from "react";

type ActionButtonProps = Omit<AriaButtonProps, "children" | "className"> & {
  variant?: "primary" | "secondary" | "quiet" | "danger";
  children: ReactNode;
  demoState?: "hover" | "focus";
};

export function ActionButton({
  variant = "primary",
  children,
  demoState,
  ...props
}: ActionButtonProps) {
  return (
    <AriaButton
      className={`am-button am-button--${variant}${demoState ? ` is-demo-${demoState}` : ""}`}
      {...props}
    >
      {({ isPending }) => (
        <>
          {isPending ? (
            <span className="am-spinner" aria-hidden="true" />
          ) : null}
          {children}
        </>
      )}
    </AriaButton>
  );
}
