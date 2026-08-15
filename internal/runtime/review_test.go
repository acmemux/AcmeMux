package runtime

import (
	"reflect"
	"testing"
	"time"
)

func TestReviewFingerprintChangesForEveryMaterialObservationField(t *testing.T) {
	t.Parallel()

	base := selectionFixture()
	baseline := ReviewFingerprint(base.Observation, base.ManifestID)
	const wantFingerprint = "a6ee18321212e79e48dc29f9af5936dc0a20cadaa0b5457abed906a0c01088f1"
	if baseline != wantFingerprint {
		t.Fatalf("ReviewFingerprint() = %q, want stable fixture %q", baseline, wantFingerprint)
	}
	if len(baseline) != 64 {
		t.Fatalf("ReviewFingerprint() length = %d, want 64", len(baseline))
	}
	if repeated := ReviewFingerprint(base.Observation, base.ManifestID); repeated != baseline {
		t.Fatalf("ReviewFingerprint() is not stable: got %q, want %q", repeated, baseline)
	}

	tests := []struct {
		name   string
		mutate func(*Observation, *string)
	}{
		{name: "manifest ID", mutate: func(_ *Observation, manifestID *string) { *manifestID += "-changed" }},
		{name: "canonical path", mutate: func(value *Observation, _ *string) { value.File.CanonicalPath += ".changed" }},
		{name: "device", mutate: func(value *Observation, _ *string) { value.File.Device-- }},
		{name: "inode", mutate: func(value *Observation, _ *string) { value.File.Inode-- }},
		{name: "mode", mutate: func(value *Observation, _ *string) { value.File.Mode ^= 0o100 }},
		{name: "capabilities", mutate: func(value *Observation, _ *string) { value.File.Capabilities = "" }},
		{name: "uid", mutate: func(value *Observation, _ *string) { value.File.UID-- }},
		{name: "gid", mutate: func(value *Observation, _ *string) { value.File.GID-- }},
		{name: "size", mutate: func(value *Observation, _ *string) { value.File.Size++ }},
		{name: "modified time", mutate: func(value *Observation, _ *string) {
			value.File.ModifiedAt = value.File.ModifiedAt.Add(time.Nanosecond)
		}},
		{name: "changed time", mutate: func(value *Observation, _ *string) { value.File.ChangedAt = value.File.ChangedAt.Add(time.Nanosecond) }},
		{name: "file digest", mutate: func(value *Observation, _ *string) { value.File.SHA256 = "b" + value.File.SHA256[1:] }},
		{name: "version kind", mutate: func(value *Observation, _ *string) { value.Version.Kind = VersionRelease }},
		{name: "version value", mutate: func(value *Observation, _ *string) { value.Version.Value += "0" }},
		{name: "platform OS", mutate: func(value *Observation, _ *string) { value.Platform.OS += "2" }},
		{name: "platform architecture", mutate: func(value *Observation, _ *string) { value.Platform.Arch += "2" }},
		{name: "build available", mutate: func(value *Observation, _ *string) { value.Build.Available = !value.Build.Available }},
		{name: "build provenance complete", mutate: func(value *Observation, _ *string) { value.Build.ProvenanceComplete = !value.Build.ProvenanceComplete }},
		{name: "Go version", mutate: func(value *Observation, _ *string) { value.Build.GoVersion += ".1" }},
		{name: "command path", mutate: func(value *Observation, _ *string) { value.Build.CommandPath += "/changed" }},
		{name: "main path", mutate: func(value *Observation, _ *string) { value.Build.MainPath += "/changed" }},
		{name: "main version", mutate: func(value *Observation, _ *string) { value.Build.MainVersion += ".1" }},
		{name: "dependency graph digest", mutate: func(value *Observation, _ *string) {
			value.Build.DependencyGraphSHA256 = "d" + value.Build.DependencyGraphSHA256[1:]
		}},
		{name: "build OS", mutate: func(value *Observation, _ *string) { value.Build.GOOS += "2" }},
		{name: "build architecture", mutate: func(value *Observation, _ *string) { value.Build.GOARCH += "2" }},
		{name: "VCS revision", mutate: func(value *Observation, _ *string) { value.Build.VCSRevision = "b" + value.Build.VCSRevision[1:] }},
		{name: "VCS modified known", mutate: func(value *Observation, _ *string) { value.Build.VCSModifiedKnown = !value.Build.VCSModifiedKnown }},
		{name: "VCS modified valid", mutate: func(value *Observation, _ *string) { value.Build.VCSModifiedValid = !value.Build.VCSModifiedValid }},
		{name: "VCS modified", mutate: func(value *Observation, _ *string) { value.Build.VCSModified = !value.Build.VCSModified }},
		{name: "version output", mutate: func(value *Observation, _ *string) { value.VersionOutput += " " }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation := base.Observation
			manifestID := base.ManifestID
			test.mutate(&observation, &manifestID)
			if got := ReviewFingerprint(observation, manifestID); got == baseline {
				t.Fatalf("ReviewFingerprint() = %q after changing %s, want a different value", got, test.name)
			}
		})
	}
}

func TestReviewFingerprintIgnoresObservationTime(t *testing.T) {
	t.Parallel()

	base := selectionFixture()
	want := ReviewFingerprint(base.Observation, base.ManifestID)
	base.Observation.ObservedAt = base.Observation.ObservedAt.Add(24 * time.Hour)
	if got := ReviewFingerprint(base.Observation, base.ManifestID); got != want {
		t.Fatalf("ReviewFingerprint() changed with ObservedAt: got %q, want %q", got, want)
	}
}

func TestReviewFingerprintCoverageGuardTracksObservationShape(t *testing.T) {
	t.Parallel()

	assertFieldNames(t, reflect.TypeFor[Observation](), []string{
		"File", "Version", "Platform", "Build", "VersionOutput", "ObservedAt",
	})
	assertFieldNames(t, reflect.TypeFor[FileIdentity](), []string{
		"CanonicalPath", "Device", "Inode", "Mode", "Capabilities", "UID", "GID", "Size", "ModifiedAt", "ChangedAt", "SHA256",
	})
	assertFieldNames(t, reflect.TypeFor[VersionIdentity](), []string{"Kind", "Value"})
	assertFieldNames(t, reflect.TypeFor[Platform](), []string{"OS", "Arch"})
	assertFieldNames(t, reflect.TypeFor[BuildEvidence](), []string{
		"Available", "ProvenanceComplete", "GoVersion", "CommandPath", "MainPath", "MainVersion", "DependencyGraphSHA256",
		"GOOS", "GOARCH", "VCSRevision", "VCSModifiedKnown", "VCSModifiedValid", "VCSModified",
	})
}

func assertFieldNames(t *testing.T, value reflect.Type, want []string) {
	t.Helper()
	if value.NumField() != len(want) {
		t.Fatalf("%s field count = %d, want %d; update ReviewFingerprint coverage", value.Name(), value.NumField(), len(want))
	}
	for index, name := range want {
		if got := value.Field(index).Name; got != name {
			t.Fatalf("%s field %d = %q, want %q; update ReviewFingerprint coverage", value.Name(), index, got, name)
		}
	}
}
