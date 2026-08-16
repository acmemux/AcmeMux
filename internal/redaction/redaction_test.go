package redaction

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestFilterRedactsObservedValueEncodings(t *testing.T) {
	t.Parallel()
	secret := []byte("TASK06 secret/$canary")
	filter, err := New([][]byte{secret, []byte("secret")}, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer filter.Clear()
	input := strings.Join([]string{
		string(secret),
		url.QueryEscape(string(secret)),
		url.PathEscape(string(secret)),
		base64.StdEncoding.EncodeToString(secret),
		base64.RawURLEncoding.EncodeToString(secret),
		`TASK06 secret\/$canary`,
	}, " ")
	result := filter.String(input)
	if strings.Contains(result, string(secret)) || strings.Contains(result, base64.StdEncoding.EncodeToString(secret)) ||
		strings.Contains(result, `TASK06 secret\/$canary`) {
		t.Fatalf("redaction leaked a secret encoding: %q", result)
	}
	if len(result) > len(input) {
		t.Fatalf("redaction amplified output: %d > %d", len(result), len(input))
	}
}

func TestFilterRedactsEscapedSolidusWithoutSubstringMasking(t *testing.T) {
	t.Parallel()
	secret := []byte("opaque/value")
	filter, err := New([][]byte{secret}, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer filter.Clear()
	if result := filter.String(`opaque\/value`); strings.Contains(result, `opaque\/value`) {
		t.Fatalf("escaped-solidus secret survived: %q", result)
	}
}

func TestFilterCannotReconstructSecretAcrossRemovedMatch(t *testing.T) {
	t.Parallel()
	secret := []byte("a<x>b")
	filter, err := New([][]byte{secret}, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer filter.Clear()
	result := filter.Bytes([]byte("aa<x>bb"))
	if bytes.Contains(result, secret) {
		t.Fatalf("redaction boundary reconstructed secret: %q", result)
	}
}

func TestFilterUsesLongestValueFirst(t *testing.T) {
	t.Parallel()
	filter, err := New([][]byte{[]byte("token"), []byte("token-long")}, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer filter.Clear()
	if got := filter.String("token-long token"); strings.Contains(got, "token") || len(got) > len("token-long token") {
		t.Fatalf("String() leaked or amplified = %q", got)
	}
}

func TestFieldsUsesExactCuratedKeysAndValueRedaction(t *testing.T) {
	t.Parallel()
	filter, err := New([][]byte{[]byte("canary")}, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer filter.Clear()
	result := filter.Fields(map[string]string{
		"password": "not-secret-by-guess",
		"token":    "anything",
		"message":  "contains canary",
	}, []string{"token"})
	if result["password"] != "not-secret-by-guess" || result["token"] == "anything" ||
		strings.Contains(result["message"], "canary") {
		t.Fatalf("Fields() = %#v", result)
	}
}

func TestFilterHandlesMarkerCollisionsAndShortSecretsWithoutAmplification(t *testing.T) {
	t.Parallel()
	values := [][]byte{[]byte("[REDACTED]"), []byte("REDACTED"), []byte("*"), []byte("x")}
	filter, err := New(values, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer filter.Clear()
	input := []byte("[REDACTED] REDACTED * x xxxxx")
	result := filter.Bytes(input)
	for _, value := range values {
		if bytes.Contains(result, value) {
			t.Fatalf("redaction retained %q in %q", value, result)
		}
	}
	if len(result) > len(input) {
		t.Fatalf("redaction amplified output: %d > %d", len(result), len(input))
	}
}

func TestFilterIndexesNonMatchingInputByFirstByte(t *testing.T) {
	t.Parallel()
	values := make([][]byte, 128)
	for index := range values {
		values[index] = []byte(fmt.Sprintf("secret-%03d-long-value", index))
	}
	filter, err := New(values, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer filter.Clear()
	input := bytes.Repeat([]byte{'z'}, 1<<20)
	result := filter.Bytes(input)
	if !bytes.Equal(result, input) {
		t.Fatal("non-matching input changed")
	}
}

func TestFilterBoundsSharedPrefixMatching(t *testing.T) {
	t.Parallel()
	values := make([][]byte, 128)
	prefix := strings.Repeat("a", 256)
	for index := range values {
		values[index] = []byte(prefix + fmt.Sprintf("-%03d", index))
	}
	policy := DefaultPolicy()
	policy.MaximumAggregateBytes = 1 << 20
	filter, err := New(values, policy)
	if err != nil {
		t.Fatal(err)
	}
	defer filter.Clear()
	input := bytes.Repeat([]byte{'a'}, 1<<20)
	result := filter.Bytes(input)
	if !bytes.Equal(result, input) {
		t.Fatal("shared-prefix nonmatch changed")
	}
}

func TestFilterRejectsInvalidBounds(t *testing.T) {
	t.Parallel()
	if _, err := New(nil, Policy{}); err == nil {
		t.Fatal("New() accepted an invalid policy")
	}
	policy := DefaultPolicy()
	policy.MaximumValues = 1
	if _, err := New([][]byte{[]byte("one"), []byte("two")}, policy); err == nil {
		t.Fatal("New() accepted too many values")
	}
	policy = DefaultPolicy()
	policy.MaximumValueBytes = 2
	if _, err := New([][]byte{[]byte("long")}, policy); err == nil {
		t.Fatal("New() accepted an oversized value")
	}
	policy = DefaultPolicy()
	policy.MaximumAggregateBytes = 8
	if _, err := New([][]byte{[]byte("aggregate-secret")}, policy); err == nil {
		t.Fatal("New() accepted oversized aggregate variants")
	}
}

func TestNilFilterStillReturnsCopies(t *testing.T) {
	t.Parallel()
	input := []byte("plain")
	var filter *Filter
	result := filter.Bytes(input)
	result[0] = 'P'
	if string(input) != "plain" {
		t.Fatal("Bytes() mutated input")
	}
}
