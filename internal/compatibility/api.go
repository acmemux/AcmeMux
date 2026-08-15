package compatibility

import (
	"slices"
	"sort"
)

// List returns defensive copies of every exact compatibility manifest.
func List() []Manifest {
	result := make([]Manifest, len(exactManifests))
	for index, manifest := range exactManifests {
		result[index] = cloneManifest(manifest)
	}
	return result
}

// Lookup returns a defensive copy of an exact manifest by stable ID.
func Lookup(id ManifestID) (Manifest, bool) {
	for _, manifest := range exactManifests {
		if manifest.ID == id {
			return cloneManifest(manifest), true
		}
	}
	return Manifest{}, false
}

// QualifiedExecutableSHA256s returns the exact independently reviewed binary
// digests that may be executed for an identity probe. Callers must still apply
// the matching manifest after the probe; this allowlist only establishes the
// byte-level pre-execution boundary.
func QualifiedExecutableSHA256s() []string {
	unique := make(map[string]struct{})
	for _, manifest := range exactManifests {
		for _, executable := range manifest.Evidence.Executables {
			if executable.Executed {
				unique[executable.SHA256] = struct{}{}
			}
		}
	}
	result := make([]string, 0, len(unique))
	for digest := range unique {
		result = append(result, digest)
	}
	sort.Strings(result)
	return result
}

// Schema returns a defensive copy of the exact bundled upstream JSON Schema
// associated with a manifest. Its digest is checked before every return.
func Schema(id ManifestID) ([]byte, error) {
	manifest, ok := Lookup(id)
	if !ok {
		return nil, &Error{ManifestID: id, Detail: "unknown manifest"}
	}
	if digest(bundledSchema) != manifest.Schema.SHA256 {
		return nil, &Error{ManifestID: id, Detail: "schema digest mismatch"}
	}
	return slices.Clone(bundledSchema), nil
}

// License returns a defensive copy of the bundled upstream MIT license. The
// package initialization invariant verifies its immutable digest.
func License() []byte {
	return slices.Clone(bundledLicense)
}

func cloneManifest(manifest Manifest) Manifest {
	clone := manifest
	clone.Runtime.VersionTokens = slices.Clone(manifest.Runtime.VersionTokens)
	clone.Platforms = slices.Clone(manifest.Platforms)
	clone.Compiled.CertificateAuthorities = slices.Clone(manifest.Compiled.CertificateAuthorities)
	clone.Compiled.ChallengeModes = slices.Clone(manifest.Compiled.ChallengeModes)
	clone.Compiled.DNSProviderCodes = slices.Clone(manifest.Compiled.DNSProviderCodes)
	clone.Supported = cloneSupported(manifest.Supported)
	clone.Evidence.SupportedProviders = slices.Clone(manifest.Evidence.SupportedProviders)
	clone.Evidence.Executables = slices.Clone(manifest.Evidence.Executables)
	return clone
}

func cloneSupported(supported SupportedCatalog) SupportedCatalog {
	clone := supported
	clone.CertificateAuthorities = slices.Clone(supported.CertificateAuthorities)
	clone.ChallengeModes = slices.Clone(supported.ChallengeModes)
	clone.DNSProviderCodes = slices.Clone(supported.DNSProviderCodes)
	return clone
}
