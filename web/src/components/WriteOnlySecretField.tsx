import type { ChangeEvent } from "react";

export type SecretDraft =
  | { action: "keep" }
  | { action: "replace"; secret: string }
  | { action: "remove" };

export function WriteOnlySecretField({
  description,
  draft,
  error,
  id,
  isDisabled = false,
  label,
  maxLength,
  onChange,
  presence,
}: {
  description: string;
  draft: SecretDraft;
  error?: string;
  id: string;
  isDisabled?: boolean;
  label: string;
  maxLength?: number;
  onChange(draft: SecretDraft): void;
  presence: "present" | "absent";
}) {
  function selectAction(event: ChangeEvent<HTMLInputElement>) {
    switch (event.currentTarget.value) {
      case "replace":
        onChange({ action: "replace", secret: "" });
        break;
      case "remove":
        onChange({ action: "remove" });
        break;
      default:
        onChange({ action: "keep" });
    }
  }

  return (
    <fieldset className="am-secret-field" disabled={isDisabled} id={id}>
      <legend>{label}</legend>
      <p id={`${id}-description`}>{description}</p>
      <p className="am-secret-field__presence">
        <strong>Stored value:</strong>{" "}
        {presence === "present" ? "Present and hidden" : "Not set"}
      </p>
      <div className="am-secret-field__actions">
        <label>
          <input
            checked={draft.action === "keep"}
            name={`${id}-action`}
            onChange={selectAction}
            type="radio"
            value="keep"
          />
          Keep stored value
        </label>
        <label>
          <input
            checked={draft.action === "replace"}
            name={`${id}-action`}
            onChange={selectAction}
            type="radio"
            value="replace"
          />
          Replace value
        </label>
        <label>
          <input
            checked={draft.action === "remove"}
            disabled={isDisabled || presence === "absent"}
            name={`${id}-action`}
            onChange={selectAction}
            type="radio"
            value="remove"
          />
          Remove value
        </label>
      </div>
      {draft.action === "replace" ? (
        <div className="am-field am-secret-field__replacement">
          <label htmlFor={`${id}-replacement`}>New secret value</label>
          <input
            aria-describedby={`${id}-description ${id}-replacement-description${error ? ` ${id}-replacement-error` : ""}`}
            aria-invalid={Boolean(error)}
            autoCapitalize="none"
            autoComplete="off"
            id={`${id}-replacement`}
            maxLength={maxLength}
            onChange={(event) =>
              onChange({ action: "replace", secret: event.currentTarget.value })
            }
            placeholder="Stored value is never loaded into this field"
            spellCheck={false}
            type="password"
            value={draft.secret}
          />
          <span id={`${id}-replacement-description`}>
            The new value remains write-only and will be omitted from every
            preview and diagnostic.
          </span>
          {error ? (
            <span id={`${id}-replacement-error`} role="alert">
              {error}
            </span>
          ) : null}
        </div>
      ) : null}
    </fieldset>
  );
}
