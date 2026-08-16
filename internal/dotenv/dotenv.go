package dotenv

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/joho/godotenv"
)

const (
	defaultMaximumBytes      = 1 << 20
	maximumAllowedBytes      = 8 << 20
	defaultMaximumLines      = 8192
	maximumAllowedLines      = 32768
	defaultMaximumValueBytes = 64 << 10
	maximumAllowedValueBytes = 1 << 20
)

// Code is a stable, non-secret dotenv failure category.
type Code string

const (
	CodeInvalidPolicy       Code = "invalid_policy"
	CodeInvalidUTF8         Code = "invalid_utf8"
	CodeTooLarge            Code = "too_large"
	CodeTooManyLines        Code = "too_many_lines"
	CodeMalformed           Code = "malformed"
	CodeKeyNotAllowed       Code = "key_not_allowed"
	CodeDuplicateKey        Code = "duplicate_key"
	CodeExpansionNotAllowed Code = "expansion_not_allowed"
	CodeInvalidChange       Code = "invalid_change"
	CodeValueTooLarge       Code = "value_too_large"
)

// Error deliberately omits source text and values.
type Error struct {
	Code  Code
	Key   string
	Cause error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Key != "" {
		return fmt.Sprintf("dotenv %s for key %s", e.Code, e.Key)
	}
	return "dotenv " + string(e.Code)
}

func (e *Error) Unwrap() error { return e.Cause }

// CodeOf returns a stable failure code without exposing parser text.
func CodeOf(err error) Code {
	var dotenvError *Error
	if errors.As(err, &dotenvError) {
		return dotenvError.Code
	}
	return ""
}

// Policy bounds hostile native credential files and submitted values.
type Policy struct {
	MaximumBytes      int
	MaximumLines      int
	MaximumValueBytes int
}

// DefaultPolicy returns the production resource bounds.
func DefaultPolicy() Policy {
	return Policy{
		MaximumBytes:      defaultMaximumBytes,
		MaximumLines:      defaultMaximumLines,
		MaximumValueBytes: defaultMaximumValueBytes,
	}
}

// Presence is the only read projection for a credential key.
type Presence struct {
	Key     string
	Present bool
}

// Action is an exact write-only credential mutation.
type Action string

const (
	ActionReplace Action = "replace"
	ActionRemove  Action = "remove"
)

// Change carries a submitted replacement only toward a candidate file.
// Value is ignored for removal and is never included in errors or summaries.
type Change struct {
	Key    string
	Action Action
	Value  []byte
}

// Summary is safe to persist or render.
type Summary struct {
	Key    string
	Action Action
}

type entry struct {
	key            string
	statementStart int
	statementEnd   int
	valueStart     int
	valueEnd       int
}

// Document owns a bounded copy of confidential native text. Call Clear when
// it is no longer needed.
type Document struct {
	raw          []byte
	allowed      []string
	entries      map[string]entry
	values       map[string][]byte
	unsupported  []string
	policy       Policy
	newline      []byte
	finalNewline bool
}

// Parse validates exact upstream-compatible dotenv syntax, applies stricter
// managed-key and expansion rules, and retains byte spans for surgical edits.
func Parse(data []byte, allowedKeys []string, policy Policy) (*Document, error) {
	if err := validatePolicy(policy); err != nil {
		return nil, err
	}
	allowed, err := validateAllowedKeys(allowedKeys)
	if err != nil {
		return nil, err
	}
	if len(data) > policy.MaximumBytes {
		return nil, &Error{Code: CodeTooLarge}
	}
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return nil, &Error{Code: CodeInvalidUTF8}
	}
	if lineCount(data) > policy.MaximumLines {
		return nil, &Error{Code: CodeTooManyLines}
	}

	entries, unsupported, scanErr := scanEntries(data, allowed)
	if scanErr != nil {
		return nil, scanErr
	}
	values := make(map[string][]byte, len(entries))
	for key, current := range entries {
		// Parse each managed statement with the exact upstream parser. Unsupported
		// statements remain opaque and never enter godotenv's unbounded expansion
		// engine, while the scanner above still proves their bounded structure.
		parsed, parseErr := godotenv.Parse(bytes.NewReader(data[current.statementStart:current.statementEnd]))
		if parseErr != nil {
			clearByteMap(values)
			return nil, &Error{Code: CodeMalformed, Key: key}
		}
		value, present := parsed[key]
		if !present {
			clearStringMap(parsed)
			clearByteMap(values)
			return nil, &Error{Code: CodeMalformed, Key: key}
		}
		if len(value) > policy.MaximumValueBytes {
			clearStringMap(parsed)
			clearByteMap(values)
			return nil, &Error{Code: CodeValueTooLarge, Key: key}
		}
		values[key] = []byte(value)
		clearStringMap(parsed)
	}
	copyOfData := make([]byte, len(data))
	copy(copyOfData, data)
	return &Document{
		raw:          copyOfData,
		allowed:      allowed,
		entries:      entries,
		values:       values,
		unsupported:  unsupported,
		policy:       policy,
		newline:      detectNewline(data),
		finalNewline: hasFinalNewline(data),
	}, nil
}

// UnsupportedKeys returns native keys that are syntactically valid but not
// owned by the selected integration manifest. Their lines remain untouched.
func (document *Document) UnsupportedKeys() []string {
	if document == nil {
		return nil
	}
	return slices.Clone(document.unsupported)
}

// Presence returns every allowlisted key in canonical order without values.
func (document *Document) Presence() []Presence {
	if document == nil {
		return nil
	}
	result := make([]Presence, 0, len(document.allowed))
	for _, key := range document.allowed {
		_, present := document.entries[key]
		result = append(result, Presence{Key: key, Present: present})
	}
	return result
}

// ValidatePresence invokes a trusted validator against the retained decoded
// value without returning or copying it. Missing keys are valid by definition.
func (document *Document) ValidatePresence(key string, validate func([]byte) bool) (bool, bool) {
	if document == nil || validate == nil {
		return false, false
	}
	value, present := document.values[key]
	if !present {
		return false, true
	}
	return true, validate(value)
}

// ValueCopy returns a defensive copy of one allowlisted decoded value for a
// trusted in-process consumer such as the operation redactor. The caller owns
// the returned buffer and must clear it. Values are never suitable for logs,
// persistence, diagnostics, or HTTP presentation.
func (document *Document) ValueCopy(key string) ([]byte, bool) {
	if document == nil {
		return nil, false
	}
	value, present := document.values[key]
	if !present {
		return nil, false
	}
	return slices.Clone(value), true
}

// Apply returns a complete candidate while preserving every unedited byte.
func (document *Document) Apply(changes []Change) ([]byte, []Summary, error) {
	if document == nil || document.raw == nil {
		return nil, nil, &Error{Code: CodeInvalidChange}
	}
	type edit struct {
		start       int
		end         int
		replacement []byte
	}
	seen := make(map[string]struct{}, len(changes))
	edits := make([]edit, 0, len(changes))
	newValues := make(map[string][]byte)
	summaries := make([]Summary, 0, len(changes))

	for _, change := range changes {
		if !slices.Contains(document.allowed, change.Key) {
			return nil, nil, &Error{Code: CodeKeyNotAllowed}
		}
		if _, duplicate := seen[change.Key]; duplicate {
			return nil, nil, &Error{Code: CodeInvalidChange, Key: change.Key}
		}
		seen[change.Key] = struct{}{}
		current, present := document.entries[change.Key]
		switch change.Action {
		case ActionReplace:
			if len(change.Value) > document.policy.MaximumValueBytes {
				return nil, nil, &Error{Code: CodeValueTooLarge, Key: change.Key}
			}
			if !utf8.Valid(change.Value) || bytes.IndexByte(change.Value, 0) >= 0 {
				return nil, nil, &Error{Code: CodeInvalidChange, Key: change.Key}
			}
			encoded, ok := encodeValue(change.Value)
			if !ok {
				return nil, nil, &Error{Code: CodeInvalidChange, Key: change.Key}
			}
			if present {
				edits = append(edits, edit{start: current.valueStart, end: current.valueEnd, replacement: encoded})
			} else {
				newValues[change.Key] = encoded
			}
			summaries = append(summaries, Summary{Key: change.Key, Action: ActionReplace})
		case ActionRemove:
			if present {
				start := current.statementStart
				if current.statementEnd == len(document.raw) && !document.finalNewline {
					start = precedingLineSeparator(document.raw, start)
				}
				edits = append(edits, edit{start: start, end: current.statementEnd})
				summaries = append(summaries, Summary{Key: change.Key, Action: ActionRemove})
			}
		default:
			return nil, nil, &Error{Code: CodeInvalidChange, Key: change.Key}
		}
	}

	sort.Slice(edits, func(left, right int) bool { return edits[left].start < edits[right].start })
	merged := edits[:0]
	for _, current := range edits {
		if len(merged) != 0 && current.start < merged[len(merged)-1].end {
			previous := &merged[len(merged)-1]
			if len(previous.replacement) != 0 || len(current.replacement) != 0 {
				return nil, nil, &Error{Code: CodeInvalidChange}
			}
			if current.end > previous.end {
				previous.end = current.end
			}
			continue
		}
		merged = append(merged, current)
	}
	edits = merged
	var candidate bytes.Buffer
	last := 0
	for _, current := range edits {
		if current.start < last || current.end < current.start || current.end > len(document.raw) {
			return nil, nil, &Error{Code: CodeInvalidChange}
		}
		candidate.Write(document.raw[last:current.start])
		candidate.Write(current.replacement)
		last = current.end
	}
	candidate.Write(document.raw[last:])

	newKeys := make([]string, 0, len(newValues))
	for key := range newValues {
		newKeys = append(newKeys, key)
	}
	sort.Strings(newKeys)
	if len(newKeys) > 0 {
		contents := candidate.Bytes()
		if len(contents) > 0 && !hasFinalNewline(contents) {
			candidate.Write(document.newline)
		}
		for index, key := range newKeys {
			candidate.WriteString(key)
			candidate.WriteByte('=')
			candidate.Write(newValues[key])
			if index+1 < len(newKeys) || document.finalNewline {
				candidate.Write(document.newline)
			}
		}
	}
	result := bytes.Clone(candidate.Bytes())
	if len(result) > document.policy.MaximumBytes {
		clear(result)
		return nil, nil, &Error{Code: CodeTooLarge}
	}
	validated, err := Parse(result, document.allowed, document.policy)
	if err != nil {
		clear(result)
		return nil, nil, err
	}
	validated.Clear()
	sort.Slice(summaries, func(left, right int) bool { return summaries[left].Key < summaries[right].Key })
	return result, summaries, nil
}

func precedingLineSeparator(data []byte, position int) int {
	if position <= 0 || position > len(data) {
		return position
	}
	if data[position-1] == '\n' {
		if position > 1 && data[position-2] == '\r' {
			return position - 2
		}
		return position - 1
	}
	if data[position-1] == '\r' {
		return position - 1
	}
	return position
}

// Clear overwrites the package-owned source copy.
func (document *Document) Clear() {
	if document == nil {
		return
	}
	clear(document.raw)
	document.raw = nil
	clearByteMap(document.values)
	document.values = nil
	document.entries = nil
	document.unsupported = nil
}

func validatePolicy(policy Policy) error {
	if policy.MaximumBytes <= 0 || policy.MaximumBytes > maximumAllowedBytes ||
		policy.MaximumLines <= 0 || policy.MaximumLines > maximumAllowedLines ||
		policy.MaximumValueBytes <= 0 || policy.MaximumValueBytes > maximumAllowedValueBytes {
		return &Error{Code: CodeInvalidPolicy}
	}
	return nil
}

func validateAllowedKeys(keys []string) ([]string, error) {
	result := slices.Clone(keys)
	for _, key := range result {
		if !validKey(key) {
			return nil, &Error{Code: CodeInvalidPolicy}
		}
	}
	sort.Strings(result)
	if len(result) == 0 {
		return result, nil
	}
	for index := 1; index < len(result); index++ {
		if result[index] == result[index-1] {
			return nil, &Error{Code: CodeInvalidPolicy}
		}
	}
	return result, nil
}

func validKey(key string) bool {
	if key == "" || len(key) > 128 {
		return false
	}
	for index, char := range []byte(key) {
		if char >= 'A' && char <= 'Z' || char == '_' || index > 0 && char >= '0' && char <= '9' {
			continue
		}
		return false
	}
	return true
}

func scanEntries(data []byte, allowed []string) (map[string]entry, []string, error) {
	entries := make(map[string]entry)
	seen := make(map[string]struct{})
	unsupportedSet := make(map[string]struct{})
	position := 0
	for position < len(data) {
		position = skipWhitespace(data, position)
		if position >= len(data) {
			break
		}
		if data[position] == '#' {
			position = consumeLine(data, position)
			continue
		}
		statementStart := currentLineStart(data, position)
		keyStart := position
		if bytes.HasPrefix(data[position:], []byte("export")) {
			after := position + len("export")
			if after < len(data) && isHorizontalSpace(data[after]) {
				position = skipHorizontal(data, after)
				keyStart = position
			}
		}
		separator := -1
		for position < len(data) {
			if data[position] == '=' || data[position] == ':' {
				separator = position
				break
			}
			if data[position] == '\n' || data[position] == '\r' {
				return nil, nil, &Error{Code: CodeMalformed}
			}
			position++
		}
		if separator < 0 {
			return nil, nil, &Error{Code: CodeMalformed}
		}
		key := strings.TrimSpace(string(data[keyStart:separator]))
		if !validSourceKey(key) {
			return nil, nil, &Error{Code: CodeMalformed}
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, nil, &Error{Code: CodeDuplicateKey, Key: key}
		}
		seen[key] = struct{}{}
		position = skipHorizontal(data, separator+1)
		valueStart := position
		valueEnd, statementEnd, expansion, err := scanValue(data, position)
		if err != nil {
			return nil, nil, err
		}
		managed := slices.Contains(allowed, key)
		if managed && expansion {
			return nil, nil, &Error{Code: CodeExpansionNotAllowed, Key: key}
		}
		if managed {
			entries[key] = entry{
				key: key, statementStart: statementStart, statementEnd: statementEnd,
				valueStart: valueStart, valueEnd: valueEnd,
			}
		} else {
			unsupportedSet[key] = struct{}{}
		}
		position = statementEnd
	}
	unsupported := make([]string, 0, len(unsupportedSet))
	for key := range unsupportedSet {
		unsupported = append(unsupported, key)
	}
	sort.Strings(unsupported)
	return entries, unsupported, nil
}

func validSourceKey(key string) bool {
	if key == "" || len(key) > 256 {
		return false
	}
	for _, char := range []byte(key) {
		if char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' ||
			char >= '0' && char <= '9' || char == '_' || char == '.' {
			continue
		}
		return false
	}
	return true
}

func scanValue(data []byte, start int) (valueEnd, statementEnd int, expansion bool, err error) {
	if start >= len(data) || data[start] == '\n' || data[start] == '\r' {
		end := consumeLine(data, start)
		return start, end, false, nil
	}
	if data[start] == '\'' || data[start] == '"' {
		quote := data[start]
		position := start + 1
		for position < len(data) {
			if data[position] == quote && data[position-1] != '\\' {
				valueEnd = position + 1
				trailer := valueEnd
				for trailer < len(data) && isHorizontalSpace(data[trailer]) {
					trailer++
				}
				if trailer < len(data) && data[trailer] != '#' && data[trailer] != '\n' && data[trailer] != '\r' {
					return 0, 0, false, &Error{Code: CodeMalformed}
				}
				if quote == '"' {
					expansion = containsExpansion(data[start+1 : position])
				}
				return valueEnd, consumeLine(data, trailer), expansion, nil
			}
			position++
		}
		return 0, 0, false, &Error{Code: CodeMalformed}
	}
	lineEnd := start
	for lineEnd < len(data) && data[lineEnd] != '\n' && data[lineEnd] != '\r' {
		lineEnd++
	}
	valueEnd = lineEnd
	for position := start; position < lineEnd; position++ {
		if data[position] == '#' && position > start && isHorizontalSpace(data[position-1]) {
			valueEnd = position
			break
		}
	}
	for valueEnd > start && isHorizontalSpace(data[valueEnd-1]) {
		valueEnd--
	}
	return valueEnd, consumeLine(data, lineEnd), containsExpansion(data[start:valueEnd]), nil
}

func containsExpansion(value []byte) bool {
	for index, char := range value {
		if char != '$' {
			continue
		}
		backslashes := 0
		for previous := index - 1; previous >= 0 && value[previous] == '\\'; previous-- {
			backslashes++
		}
		if backslashes%2 == 0 {
			return true
		}
	}
	return false
}

func encodeValue(value []byte) ([]byte, bool) {
	// Prefer literal single quotes. They avoid upstream variable expansion and
	// preserve backslashes exactly. Fall back to the upstream double-quoted
	// grammar when the value itself contains a single quote. godotenv has edge
	// cases around terminal escaped characters, so every encoding is parsed
	// back and compared before it may reach a candidate file.
	if !bytes.Contains(value, []byte{'\''}) {
		encoded := make([]byte, 0, len(value)+2)
		encoded = append(encoded, '\'')
		encoded = append(encoded, value...)
		encoded = append(encoded, '\'')
		if encodedValueRoundTrips(value, encoded) {
			return encoded, true
		}
		clear(encoded)
	}

	result := make([]byte, 0, len(value)+2)
	result = append(result, '"')
	for _, char := range value {
		switch char {
		case '\\':
			result = append(result, '\\', '\\')
		case '"':
			result = append(result, '\\', '"')
		case '$':
			result = append(result, '\\', '$')
		case '\n':
			result = append(result, '\\', 'n')
		case '\r':
			result = append(result, '\\', 'r')
		default:
			result = append(result, char)
		}
	}
	result = append(result, '"')
	if encodedValueRoundTrips(value, result) {
		return result, true
	}
	clear(result)
	return nil, false
}

func encodedValueRoundTrips(value, encoded []byte) bool {
	line := make([]byte, 0, len(encoded)+len("ACMEMUX_VALUE="))
	line = append(line, "ACMEMUX_VALUE="...)
	line = append(line, encoded...)
	parsed, err := godotenv.Parse(bytes.NewReader(line))
	clear(line)
	if err != nil {
		return false
	}
	parsedValue, present := parsed["ACMEMUX_VALUE"]
	matches := present && parsedValue == string(value)
	clearStringMap(parsed)
	return matches
}

func detectNewline(data []byte) []byte {
	if index := bytes.IndexByte(data, '\n'); index >= 0 && index > 0 && data[index-1] == '\r' {
		return []byte("\r\n")
	}
	if bytes.IndexByte(data, '\r') >= 0 && bytes.IndexByte(data, '\n') < 0 {
		return []byte("\r")
	}
	return []byte("\n")
}

func hasFinalNewline(data []byte) bool {
	return len(data) > 0 && (data[len(data)-1] == '\n' || data[len(data)-1] == '\r')
}

func lineCount(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	count := 1
	for index := 0; index < len(data); index++ {
		switch data[index] {
		case '\n':
			count++
		case '\r':
			count++
			if index+1 < len(data) && data[index+1] == '\n' {
				index++
			}
		}
	}
	if hasFinalNewline(data) {
		count--
	}
	return count
}

func currentLineStart(data []byte, position int) int {
	for position > 0 && data[position-1] != '\n' && data[position-1] != '\r' {
		position--
	}
	return position
}

func skipWhitespace(data []byte, position int) int {
	for position < len(data) {
		switch data[position] {
		case ' ', '\t', '\v', '\f', '\r', '\n':
			position++
		default:
			return position
		}
	}
	return position
}

func skipHorizontal(data []byte, position int) int {
	for position < len(data) && isHorizontalSpace(data[position]) {
		position++
	}
	return position
}

func isHorizontalSpace(char byte) bool {
	return char == ' ' || char == '\t' || char == '\v' || char == '\f'
}

func consumeLine(data []byte, position int) int {
	for position < len(data) && data[position] != '\n' && data[position] != '\r' {
		position++
	}
	if position < len(data) && data[position] == '\r' {
		position++
		if position < len(data) && data[position] == '\n' {
			position++
		}
	} else if position < len(data) && data[position] == '\n' {
		position++
	}
	return position
}

func clearStringMap(values map[string]string) {
	for key, value := range values {
		values[key] = strings.Repeat("\x00", len(value))
		delete(values, key)
	}
}

func clearByteMap(values map[string][]byte) {
	for key, value := range values {
		clear(value)
		delete(values, key)
	}
}
