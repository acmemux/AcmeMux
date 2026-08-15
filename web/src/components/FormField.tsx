import {
  FieldError,
  Input,
  Label,
  Text,
  TextField,
} from "react-aria-components";
import type { HTMLInputTypeAttribute, Ref } from "react";

export function FormField({
  label,
  description,
  autoComplete,
  defaultValue,
  errorMessage,
  inputRef,
  isDisabled = false,
  isInvalid = false,
  isRequired = false,
  name,
  type = "text",
}: {
  label: string;
  description: string;
  autoComplete?: string;
  defaultValue?: string;
  isDisabled?: boolean;
  isInvalid?: boolean;
  errorMessage?: string;
  inputRef?: Ref<HTMLInputElement>;
  isRequired?: boolean;
  name?: string;
  type?: HTMLInputTypeAttribute;
}) {
  return (
    <TextField
      className="am-field"
      defaultValue={defaultValue}
      isDisabled={isDisabled}
      isInvalid={isInvalid}
      isRequired={isRequired}
      name={name}
    >
      <Label>{label}</Label>
      <Input autoComplete={autoComplete} ref={inputRef} type={type} />
      <Text slot="description">{description}</Text>
      {errorMessage ? <FieldError>{errorMessage}</FieldError> : null}
    </TextField>
  );
}
