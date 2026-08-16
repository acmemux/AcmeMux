package dotenv

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/joho/godotenv"
)

func TestParseProjectsPresenceWithoutValues(t *testing.T) {
	t.Parallel()
	secret := "TASK06_DOTENV_SECRET_CANARY"
	document, err := Parse([]byte("# credential\nexport API_TOKEN='"+secret+"'\nZONE_ID: zone\n"), []string{"API_TOKEN", "ZONE_ID"}, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer document.Clear()
	want := []Presence{{Key: "API_TOKEN", Present: true}, {Key: "ZONE_ID", Present: true}}
	if got := document.Presence(); !slicesEqual(got, want) {
		t.Fatalf("Presence() = %#v, want %#v", got, want)
	}
	if bytes.Contains([]byte(documentError(document)), []byte(secret)) {
		t.Fatal("secret appeared in document diagnostic surface")
	}
}

func TestApplyPreservesUneditedTextAndNewlineConvention(t *testing.T) {
	t.Parallel()
	source := []byte("# retained\r\nexport API_TOKEN = 'old' # style\r\nZONE_ID: old-zone\r\n")
	document, err := Parse(source, []string{"API_TOKEN", "ZONE_ID"}, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer document.Clear()
	replacement := []byte("new$token\nwith\\quote\"")
	candidate, summary, err := document.Apply([]Change{{Key: "API_TOKEN", Action: ActionReplace, Value: replacement}})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(candidate)
	if !bytes.Contains(candidate, []byte("# retained\r\n")) || !bytes.Contains(candidate, []byte("ZONE_ID: old-zone\r\n")) {
		t.Fatalf("unedited text changed: %q", candidate)
	}
	if !bytes.Contains(candidate, []byte("export API_TOKEN = 'new$token\nwith\\quote\"' # style\r\n")) {
		t.Fatalf("replacement was not canonical and style-preserving: %q", candidate)
	}
	parsed, err := godotenv.Parse(bytes.NewReader(candidate))
	if err != nil {
		t.Fatal(err)
	}
	if parsed["API_TOKEN"] != string(replacement) {
		t.Fatalf("replacement value = %q", parsed["API_TOKEN"])
	}
	if len(summary) != 1 || summary[0].Key != "API_TOKEN" || summary[0].Action != ActionReplace {
		t.Fatalf("summary = %#v", summary)
	}
}

func TestApplyUsesVerifiedDoubleQuotedFallback(t *testing.T) {
	t.Parallel()
	document, err := Parse(nil, []string{"API_TOKEN"}, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer document.Clear()
	value := []byte("single'quote and $DOLLAR")
	candidate, _, err := document.Apply([]Change{{Key: "API_TOKEN", Action: ActionReplace, Value: value}})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(candidate)
	parsed, err := godotenv.Parse(bytes.NewReader(candidate))
	if err != nil {
		t.Fatal(err)
	}
	if parsed["API_TOKEN"] != string(value) {
		t.Fatalf("replacement value = %q", parsed["API_TOKEN"])
	}
}

func TestApplyRejectsValueUpstreamCannotRepresentExactly(t *testing.T) {
	t.Parallel()
	document, err := Parse(nil, []string{"API_TOKEN"}, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer document.Clear()
	// A single quote forces double quoting, while godotenv cannot round-trip a
	// terminal escaped quote. Reject it instead of silently changing a secret.
	value := []byte("both'quotes\"")
	if _, _, err := document.Apply([]Change{{Key: "API_TOKEN", Action: ActionReplace, Value: value}}); CodeOf(err) != CodeInvalidChange {
		t.Fatalf("Apply() error = %v", err)
	}
}

func TestApplyAddsAndRemovesWithoutChangingFinalNewline(t *testing.T) {
	t.Parallel()
	document, err := Parse([]byte("API_TOKEN=old"), []string{"API_TOKEN", "ZONE_ID"}, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer document.Clear()
	candidate, summary, err := document.Apply([]Change{
		{Key: "API_TOKEN", Action: ActionRemove},
		{Key: "ZONE_ID", Action: ActionReplace, Value: []byte("zone")},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(candidate)
	if string(candidate) != "ZONE_ID='zone'" {
		t.Fatalf("candidate = %q", candidate)
	}
	if len(summary) != 2 || summary[0].Key != "API_TOKEN" || summary[1].Key != "ZONE_ID" {
		t.Fatalf("summary = %#v", summary)
	}
}

func TestApplyRemoveLastEntryPreservesMissingFinalNewline(t *testing.T) {
	t.Parallel()
	for _, separator := range []string{"\n", "\r\n", "\r"} {
		separator := separator
		t.Run(fmt.Sprintf("separator_%x", separator), func(t *testing.T) {
			t.Parallel()
			source := []byte("API_TOKEN='keep'" + separator + "ZONE_ID='remove'")
			document, err := Parse(source, []string{"API_TOKEN", "ZONE_ID"}, DefaultPolicy())
			if err != nil {
				t.Fatal(err)
			}
			defer document.Clear()
			candidate, summary, err := document.Apply([]Change{{Key: "ZONE_ID", Action: ActionRemove}})
			if err != nil {
				t.Fatal(err)
			}
			defer clear(candidate)
			if string(candidate) != "API_TOKEN='keep'" || len(summary) != 1 {
				t.Fatalf("remove-last candidate = %q, summary %#v", candidate, summary)
			}
		})
	}
}

func TestApplyCoalescesAdjacentRemovalsWithoutFinalNewline(t *testing.T) {
	t.Parallel()
	for _, separator := range []string{"\n", "\r\n", "\r"} {
		separator := separator
		t.Run(fmt.Sprintf("separator_%x", separator), func(t *testing.T) {
			t.Parallel()
			source := []byte("API_TOKEN='one'" + separator + "ZONE_ID='two'")
			document, err := Parse(source, []string{"API_TOKEN", "ZONE_ID"}, DefaultPolicy())
			if err != nil {
				t.Fatal(err)
			}
			defer document.Clear()
			candidate, summary, err := document.Apply([]Change{
				{Key: "API_TOKEN", Action: ActionRemove},
				{Key: "ZONE_ID", Action: ActionRemove},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer clear(candidate)
			if len(candidate) != 0 || len(summary) != 2 {
				t.Fatalf("adjacent removal candidate = %q, summary %#v", candidate, summary)
			}
		})
	}
}

func TestParseAcceptsStaticMultilineAndPreservesIt(t *testing.T) {
	t.Parallel()
	source := []byte("API_TOKEN=\"first\nsecond\"\n")
	document, err := Parse(source, []string{"API_TOKEN"}, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer document.Clear()
	candidate, summary, err := document.Apply(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(candidate)
	if !bytes.Equal(candidate, source) || len(summary) != 0 {
		t.Fatalf("no-op changed source: %q", candidate)
	}
}

func TestApplyDoesNotRevealSecretEquality(t *testing.T) {
	t.Parallel()
	for _, source := range []string{
		"API_TOKEN=same\n",
		"API_TOKEN='same'\n",
		"API_TOKEN=\"same\"\n",
		"API_TOKEN=\"line\\nvalue\"\n",
	} {
		document, err := Parse([]byte(source), []string{"API_TOKEN"}, DefaultPolicy())
		if err != nil {
			t.Fatal(err)
		}
		value := []byte("same")
		if strings.Contains(source, `\n`) {
			value = []byte("line\nvalue")
		}
		candidate, summary, err := document.Apply([]Change{{
			Key: "API_TOKEN", Action: ActionReplace, Value: value,
		}})
		document.Clear()
		if err != nil {
			t.Fatal(err)
		}
		if len(summary) != 1 || summary[0].Action != ActionReplace {
			t.Fatalf("secret replacement summary = %#v, source %q, candidate %q", summary, source, candidate)
		}
		clear(candidate)
	}
}

func TestParseBoundsUnsupportedExpansionWithoutEvaluatingIt(t *testing.T) {
	t.Parallel()
	large := strings.Repeat("x", 32<<10)
	source := []byte("UNMANAGED_A='" + large + "'\nUNMANAGED_B=$UNMANAGED_A$UNMANAGED_A$UNMANAGED_A\nAPI_TOKEN='safe'\n")
	document, err := Parse(source, []string{"API_TOKEN"}, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer document.Clear()
	if got := document.UnsupportedKeys(); len(got) != 2 {
		t.Fatalf("UnsupportedKeys() = %#v", got)
	}
}

func TestParseRejectsUnsafeOrAmbiguousInputsWithoutEcho(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data []byte
		keys []string
		code Code
	}{
		{name: "duplicate", data: []byte("API_TOKEN=one\nAPI_TOKEN=two\n"), keys: []string{"API_TOKEN"}, code: CodeDuplicateKey},
		{name: "expansion", data: []byte("API_TOKEN=${OTHER}\n"), keys: []string{"API_TOKEN"}, code: CodeExpansionNotAllowed},
		{name: "quoted expansion", data: []byte("API_TOKEN=\"$OTHER\"\n"), keys: []string{"API_TOKEN"}, code: CodeExpansionNotAllowed},
		{name: "nul", data: []byte("API_TOKEN=bad\x00value"), keys: []string{"API_TOKEN"}, code: CodeInvalidUTF8},
		{name: "malformed", data: []byte("API_TOKEN=\"unterminated"), keys: []string{"API_TOKEN"}, code: CodeMalformed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse(test.data, test.keys, DefaultPolicy())
			if CodeOf(err) != test.code {
				t.Fatalf("Parse() error = %v, want %s", err, test.code)
			}
			if err != nil && bytes.Contains([]byte(err.Error()), []byte("secret")) {
				t.Fatalf("error reflected source: %v", err)
			}
		})
	}
}

func TestParseEnforcesDecodedManagedValueBound(t *testing.T) {
	t.Parallel()
	policy := DefaultPolicy()
	policy.MaximumValueBytes = 4
	for _, source := range [][]byte{
		[]byte("API_TOKEN='12345'\n"),
		[]byte("API_TOKEN=\"12\\n345\"\n"),
		[]byte("API_TOKEN=\"12\n345\"\n"),
	} {
		_, err := Parse(source, []string{"API_TOKEN"}, policy)
		if CodeOf(err) != CodeValueTooLarge {
			t.Fatalf("Parse(%q) error = %v", source, err)
		}
		if err != nil && strings.Contains(err.Error(), "12345") {
			t.Fatalf("error reflected managed value: %v", err)
		}
	}
}

func TestUnsupportedKeysRemainOpaqueAndPreserved(t *testing.T) {
	t.Parallel()
	source := []byte("OTHER=${NATIVE_VALUE}\nAPI_TOKEN=old\n")
	document, err := Parse(source, []string{"API_TOKEN"}, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer document.Clear()
	if got := document.UnsupportedKeys(); len(got) != 1 || got[0] != "OTHER" {
		t.Fatalf("UnsupportedKeys() = %#v", got)
	}
	candidate, _, err := document.Apply([]Change{{Key: "API_TOKEN", Action: ActionReplace, Value: []byte("new")}})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(candidate)
	if !bytes.Contains(candidate, []byte("OTHER=${NATIVE_VALUE}\n")) {
		t.Fatalf("unsupported line changed: %q", candidate)
	}
}

func TestApplyRejectsUnallowlistedDuplicateAndOversizeChanges(t *testing.T) {
	t.Parallel()
	policy := DefaultPolicy()
	policy.MaximumValueBytes = 4
	document, err := Parse(nil, []string{"API_TOKEN"}, policy)
	if err != nil {
		t.Fatal(err)
	}
	defer document.Clear()
	for _, changes := range [][]Change{
		{{Key: "OTHER", Action: ActionReplace, Value: []byte("x")}},
		{{Key: "API_TOKEN", Action: ActionReplace, Value: []byte("one")}, {Key: "API_TOKEN", Action: ActionRemove}},
		{{Key: "API_TOKEN", Action: ActionReplace, Value: []byte("large")}},
	} {
		if _, _, err := document.Apply(changes); err == nil {
			t.Fatalf("Apply(%#v) succeeded", changes)
		}
	}
}

func TestParseRejectsInvalidPolicyAndBounds(t *testing.T) {
	t.Parallel()
	if _, err := Parse(nil, nil, Policy{}); CodeOf(err) != CodeInvalidPolicy {
		t.Fatalf("invalid policy error = %v", err)
	}
	policy := DefaultPolicy()
	policy.MaximumBytes = 3
	if _, err := Parse([]byte("A=12"), []string{"A"}, policy); CodeOf(err) != CodeTooLarge {
		t.Fatalf("size error = %v", err)
	}
	if _, err := Parse(nil, []string{"bad-key"}, DefaultPolicy()); CodeOf(err) != CodeInvalidPolicy {
		t.Fatalf("key policy error = %v", err)
	}
}

func slicesEqual(left, right []Presence) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func documentError(_ *Document) string { return "dotenv document ready" }
