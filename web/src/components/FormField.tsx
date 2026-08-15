import {
  FieldError,
  Input,
  Label,
  Text,
  TextField,
} from "react-aria-components";

export function FormField({
  label,
  description,
  defaultValue,
  isDisabled = false,
  isInvalid = false,
  errorMessage = "Check this value and try again.",
}: {
  label: string;
  description: string;
  defaultValue?: string;
  isDisabled?: boolean;
  isInvalid?: boolean;
  errorMessage?: string;
}) {
  return (
    <TextField
      className="am-field"
      defaultValue={defaultValue}
      isDisabled={isDisabled}
      isInvalid={isInvalid}
    >
      <Label>{label}</Label>
      <Input />
      <Text slot="description">{description}</Text>
      <FieldError>{errorMessage}</FieldError>
    </TextField>
  );
}
