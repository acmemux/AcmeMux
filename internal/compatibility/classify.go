package compatibility

import (
	"fmt"
	"slices"

	acmeruntime "github.com/sgurden-certleap/AcmeMux/internal/runtime"
)

// Classify applies the exact source-backed allowlist to an already audited
// runtime observation. It performs no I/O and fails closed on missing or
// sparse Go build evidence.
func Classify(observation acmeruntime.Observation) Result {
	manifest, found := manifestForVersion(observation.Version)
	if !found {
		return Result{Code: CodeUnknownIdentity, Detail: "no exact compatibility manifest matches the reported identity"}
	}
	result := Result{ManifestID: manifest.ID}
	if !hex64Pattern.MatchString(observation.File.SHA256) {
		result.Code = CodeObservationInvalid
		result.Detail = "the audited executable fingerprint is missing or malformed"
		return result
	}
	if !slices.Contains(manifest.Platforms, observation.Platform) {
		result.Code = CodeUnsupportedPlatform
		result.Detail = fmt.Sprintf("platform %s/%s is not admitted by the exact manifest", observation.Platform.OS, observation.Platform.Arch)
		return result
	}
	executable, found := qualifiedExecutable(manifest, observation.Platform, observation.File.SHA256)
	if !found {
		result.Code = CodeExecutableDigestMismatch
		result.Detail = "the executable bytes are not an independently qualified artifact for this manifest and platform"
		return result
	}
	if observation.VersionOutput != executable.VersionOutput {
		result.Code = CodeVersionOutputMismatch
		result.Detail = "version output is not an exact reviewed form for the manifest and platform"
		return result
	}
	build := observation.Build
	if !build.Available {
		result.Code = CodeBuildEvidenceMissing
		result.Detail = "embedded Go build evidence is required"
		return result
	}
	if !build.ProvenanceComplete || build.GoVersion == "" || build.CommandPath == "" || build.MainPath == "" || build.MainVersion == "" ||
		build.DependencyGraphSHA256 == "" || build.GOOS == "" || build.GOARCH == "" ||
		build.VCSRevision == "" || !build.VCSModifiedKnown || !build.VCSModifiedValid {
		result.Code = CodeBuildEvidenceIncomplete
		result.Detail = "embedded Go build evidence is incomplete"
		return result
	}
	if build.CommandPath != manifest.Runtime.CommandPath || build.MainPath != manifest.Runtime.ModulePath {
		result.Code = CodeBuildModuleMismatch
		result.Detail = "embedded main module does not match upstream lego"
		return result
	}
	if build.GoVersion != executable.GoVersion {
		result.Code = CodeBuildToolchainMismatch
		result.Detail = "embedded Go toolchain does not match the qualified artifact"
		return result
	}
	if build.MainVersion != manifest.Runtime.ModuleVersion {
		result.Code = CodeBuildVersionMismatch
		result.Detail = "embedded main module version does not match the exact manifest"
		return result
	}
	if build.DependencyGraphSHA256 != manifest.Runtime.DependencyGraphSHA256 {
		result.Code = CodeBuildDependencyMismatch
		result.Detail = "embedded dependency graph does not match the exact manifest"
		return result
	}
	if build.GOOS != observation.Platform.OS || build.GOARCH != observation.Platform.Arch {
		result.Code = CodeBuildPlatformMismatch
		result.Detail = "embedded build platform disagrees with version output"
		return result
	}
	if build.VCSRevision != manifest.Runtime.VCSRevision {
		result.Code = CodeBuildRevisionMismatch
		result.Detail = "embedded VCS revision does not match the exact manifest"
		return result
	}
	if manifest.Runtime.RequireClean && build.VCSModified {
		result.Code = CodeBuildModified
		result.Detail = "modified source builds are not compatible"
		return result
	}
	result.Code = CodeCompatible
	result.Detail = "the audited executable matches the exact source-backed manifest"
	return result
}

func manifestForVersion(version acmeruntime.VersionIdentity) (Manifest, bool) {
	for _, manifest := range exactManifests {
		if manifest.Runtime.Version == version {
			return manifest, true
		}
	}
	return Manifest{}, false
}

func qualifiedExecutable(manifest Manifest, platform acmeruntime.Platform, digest string) (ExecutableEvidence, bool) {
	for _, executable := range manifest.Evidence.Executables {
		if executable.Executed && executable.Platform == platform && executable.SHA256 == digest {
			return executable, true
		}
	}
	return ExecutableEvidence{}, false
}
