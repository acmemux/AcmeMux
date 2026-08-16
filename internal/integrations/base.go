package integrations

import (
	"sync"

	"github.com/sgurden-certleap/AcmeMux/internal/compatibility"
)

const (
	// BaseManifestID is intentionally narrow. Feature delivery tasks extend it
	// with reviewed account, challenge, certificate, and provider fields.
	BaseManifestID ManifestID = "native-base-v1"

	FieldWorkspaceStorage FieldID = "workspace.storage"
)

var (
	baseOnce     sync.Once
	baseManifest Manifest
)

func buildBaseManifest() Manifest {
	defaultStorage := StringValue(".lego")
	storage, err := NewFieldSpec(FieldDefinition{
		ID:          FieldWorkspaceStorage,
		Label:       "Workspace storage",
		Kind:        FieldString,
		Target:      TargetYAML,
		Sensitivity: SensitivityPublic,
		Disposition: DispositionManaged,
		Selector:    []SelectorSegment{YAMLKey("storage")},
		Default:     &defaultStorage,
		Rules:       Rules{MaxBytes: 4095},
	})
	if err != nil {
		panic("invalid base storage field: " + err.Error())
	}
	manifest, err := NewManifest(BaseManifestID, []compatibility.ManifestID{
		compatibility.ManifestLegoRevision2A58,
		compatibility.ManifestLegoV531,
	}, storage)
	if err != nil {
		panic("invalid base integration manifest: " + err.Error())
	}
	return manifest
}

// BaseManifest returns the deliberately small production configuration
// contract for an exact admitted runtime identity.
func BaseManifest(runtimeID compatibility.ManifestID) (Manifest, bool) {
	baseOnce.Do(func() { baseManifest = buildBaseManifest() })
	if !baseManifest.SupportsRuntime(runtimeID) {
		return Manifest{}, false
	}
	return baseManifest, true
}
