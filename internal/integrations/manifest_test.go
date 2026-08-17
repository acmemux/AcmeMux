package integrations

import (
	"reflect"
	"strings"
	"testing"

	"github.com/acmemux/AcmeMux/internal/compatibility"
)

func TestBaseManifestIsExactAndDefensive(t *testing.T) {
	manifest, ok := BaseManifest(compatibility.ManifestLegoV531)
	if !ok || manifest.ID() != BaseManifestID || len(manifest.Fields()) != 1 {
		t.Fatalf("BaseManifest() = %#v, %v", manifest, ok)
	}
	if _, ok := BaseManifest("unknown"); ok {
		t.Fatal("unknown runtime received base manifest")
	}
	storage, ok := manifest.Field(FieldWorkspaceStorage)
	if !ok || storage.Kind() != FieldString || !storage.Editable() || storage.Sensitivity() != SensitivityPublic {
		t.Fatalf("storage spec = %#v, %v", storage, ok)
	}
	value, ok := storage.Default()
	text, stringOK := value.String()
	if !ok || !stringOK || text != ".lego" {
		t.Fatalf("storage default = %#v, %v", value, ok)
	}

	selector := storage.Selector()
	selector[0] = YAMLKey("mutated")
	fresh, _ := manifest.Field(FieldWorkspaceStorage)
	if reflect.DeepEqual(selector, fresh.Selector()) {
		t.Fatal("selector mutation escaped defensive copy")
	}
}

func TestLogicalBindingsResolveAndMatchWithoutBrowserPaths(t *testing.T) {
	spec, err := NewFieldSpec(FieldDefinition{
		ID:          "certificate.domains",
		Label:       "Certificate domains",
		Kind:        FieldStringList,
		Target:      TargetYAML,
		Sensitivity: SensitivityPublic,
		Disposition: DispositionManaged,
		Selector: []SelectorSegment{
			YAMLKey("certificates"), YAMLBinding("certificate"), YAMLKey("domains"),
		},
		Rules: Rules{MinItems: 1, MaxItems: 100, MaxBytes: 253},
	})
	if err != nil {
		t.Fatal(err)
	}
	path, err := spec.Resolve(map[BindingID]string{"certificate": "gateway"})
	if err != nil || !reflect.DeepEqual(path, []string{"certificates", "gateway", "domains"}) {
		t.Fatalf("Resolve() = %v, %v", path, err)
	}
	bindings, ok := spec.Match(path)
	if !ok || bindings["certificate"] != "gateway" {
		t.Fatalf("Match() = %v, %v", bindings, ok)
	}
	if _, err := spec.Resolve(map[BindingID]string{"certificate": "bad\nkey"}); err == nil {
		t.Fatal("unsafe logical binding resolved")
	}
	if _, ok := spec.Match([]string{"certificates", "bad\nkey", "domains"}); ok {
		t.Fatal("unsafe native entity key projected as a logical binding")
	}
}

func TestManifestRejectsInvalidAndDuplicateContracts(t *testing.T) {
	valid, err := NewFieldSpec(FieldDefinition{
		ID: "workspace.storage", Label: "Storage", Kind: FieldString,
		Target:      TargetYAML,
		Sensitivity: SensitivityPublic, Disposition: DispositionManaged,
		Selector: []SelectorSegment{YAMLKey("storage")}, Rules: Rules{MaxBytes: 10},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewManifest("test", []compatibility.ManifestID{compatibility.ManifestLegoV531}, valid, valid); err == nil {
		t.Fatal("duplicate fields accepted")
	}
	definition := FieldDefinition{
		ID: "invalid", Label: "Invalid", Kind: FieldString,
		Target:      TargetYAML,
		Sensitivity: SensitivityPublic, Disposition: DispositionManaged,
		Selector: []SelectorSegment{YAMLKey("storage")},
	}
	if _, err := NewFieldSpec(definition); err == nil {
		t.Fatal("invalid field ID accepted")
	}
	invalidDefinitions := []FieldDefinition{
		{
			ID: FieldID("workspace." + strings.Repeat("a", 128)), Label: "Too long", Kind: FieldString,
			Target: TargetYAML, Sensitivity: SensitivityPublic, Disposition: DispositionManaged,
			Selector: []SelectorSegment{YAMLKey("storage")},
		},
		{
			ID: "workspace.control_label", Label: "Bad\tlabel", Kind: FieldString,
			Target: TargetYAML, Sensitivity: SensitivityPublic, Disposition: DispositionManaged,
			Selector: []SelectorSegment{YAMLKey("storage")},
		},
		{
			ID: "workspace.long_binding", Label: "Long binding", Kind: FieldString,
			Target: TargetYAML, Sensitivity: SensitivityPublic, Disposition: DispositionManaged,
			Selector: []SelectorSegment{YAMLKey("accounts"), YAMLBinding(BindingID(strings.Repeat("a", 65)))},
		},
		{
			ID: "workspace.long_environment", Label: "Long environment", Kind: FieldString,
			Target: TargetDotenv, Sensitivity: SensitivitySecret, Disposition: DispositionManaged,
			Selector:       []SelectorSegment{YAMLKey("challenges"), YAMLBinding("challenge"), YAMLKey("dns"), YAMLKey("envFile")},
			EnvironmentKey: "A" + strings.Repeat("B", 128),
		},
		{
			ID: "workspace.boolean_secret", Label: "Boolean secret", Kind: FieldBoolean,
			Target: TargetYAML, Sensitivity: SensitivitySecret, Disposition: DispositionManaged,
			Selector: []SelectorSegment{YAMLKey("secret")}, Rules: Rules{},
		},
	}
	for index, invalid := range invalidDefinitions {
		if _, err := NewFieldSpec(invalid); err == nil {
			t.Fatalf("invalid definition %d accepted", index)
		}
	}
}

func TestLogicalBindingsRejectAllControlCharacters(t *testing.T) {
	spec, err := NewFieldSpec(FieldDefinition{
		ID: "certificate.domains", Label: "Certificate domains", Kind: FieldStringList,
		Target: TargetYAML, Sensitivity: SensitivityPublic, Disposition: DispositionManaged,
		Selector: []SelectorSegment{YAMLKey("certificates"), YAMLBinding("certificate"), YAMLKey("domains")},
		Rules:    Rules{MinItems: 1, MaxItems: 100, MaxBytes: 253},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"bad\tkey", "bad\x1fkey", "bad\x7fkey"} {
		if _, err := spec.Resolve(map[BindingID]string{"certificate": value}); err == nil {
			t.Fatalf("Resolve(%q) accepted a control-bearing key", value)
		}
		if _, ok := spec.Match([]string{"certificates", value, "domains"}); ok {
			t.Fatalf("Match(%q) accepted a control-bearing key", value)
		}
	}
}

func TestFieldValueBoundsDoNotEchoRejectedValue(t *testing.T) {
	spec, err := NewFieldSpec(FieldDefinition{
		ID: "workspace.storage", Label: "Storage", Kind: FieldString,
		Target:      TargetYAML,
		Sensitivity: SensitivityPublic, Disposition: DispositionManaged,
		Selector: []SelectorSegment{YAMLKey("storage")}, Rules: Rules{MaxBytes: 4},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = spec.ValidateValue(StringValue("sensitive-value"))
	if err == nil || err.Error() == "sensitive-value" {
		t.Fatalf("ValidateValue() = %v", err)
	}
}

func TestDotenvFieldBindsReferenceAndExactKey(t *testing.T) {
	spec, err := NewFieldSpec(FieldDefinition{
		ID: "cloudflare.api_token", Label: "Cloudflare API token", Kind: FieldString,
		Target: TargetDotenv, Sensitivity: SensitivitySecret, Disposition: DispositionManaged,
		Selector: []SelectorSegment{
			YAMLKey("challenges"), YAMLBinding("challenge"), YAMLKey("dns"), YAMLKey("envFile"),
		},
		EnvironmentKey: "CLOUDFLARE_DNS_API_TOKEN",
		Rules:          Rules{MaxBytes: 4096},
	})
	if err != nil {
		t.Fatal(err)
	}
	key, ok := spec.EnvironmentKey()
	if !ok || spec.Target() != TargetDotenv || key != "CLOUDFLARE_DNS_API_TOKEN" {
		t.Fatalf("dotenv binding = %q, %v, %q", spec.Target(), ok, key)
	}
	path, err := spec.Resolve(map[BindingID]string{"challenge": "dns-home"})
	if err != nil || !reflect.DeepEqual(path, []string{"challenges", "dns-home", "dns", "envFile"}) {
		t.Fatalf("Resolve() = %v, %v", path, err)
	}
}
