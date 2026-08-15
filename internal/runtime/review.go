package runtime

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"time"
)

const reviewFingerprintDomain = "acmemux-runtime-review-v1"

// ReviewFingerprint returns a stable digest of the exact runtime evidence and
// compatibility manifest presented for administrator review. ObservedAt is
// deliberately excluded: a fresh inspection of unchanged evidence must retain
// the same review identity.
func ReviewFingerprint(observation Observation, manifestID string) string {
	fields := []struct {
		name  string
		value string
	}{
		{name: "manifest_id", value: manifestID},
		{name: "file.canonical_path", value: observation.File.CanonicalPath},
		{name: "file.device", value: strconv.FormatUint(observation.File.Device, 10)},
		{name: "file.inode", value: strconv.FormatUint(observation.File.Inode, 10)},
		{name: "file.mode", value: strconv.FormatUint(uint64(observation.File.Mode), 10)},
		{name: "file.capabilities", value: observation.File.Capabilities},
		{name: "file.uid", value: strconv.FormatUint(uint64(observation.File.UID), 10)},
		{name: "file.gid", value: strconv.FormatUint(uint64(observation.File.GID), 10)},
		{name: "file.size", value: strconv.FormatInt(observation.File.Size, 10)},
		{name: "file.modified_at", value: fingerprintTime(observation.File.ModifiedAt)},
		{name: "file.changed_at", value: fingerprintTime(observation.File.ChangedAt)},
		{name: "file.sha256", value: observation.File.SHA256},
		{name: "version.kind", value: string(observation.Version.Kind)},
		{name: "version.value", value: observation.Version.Value},
		{name: "platform.os", value: observation.Platform.OS},
		{name: "platform.arch", value: observation.Platform.Arch},
		{name: "build.available", value: strconv.FormatBool(observation.Build.Available)},
		{name: "build.provenance_complete", value: strconv.FormatBool(observation.Build.ProvenanceComplete)},
		{name: "build.go_version", value: observation.Build.GoVersion},
		{name: "build.command_path", value: observation.Build.CommandPath},
		{name: "build.main_path", value: observation.Build.MainPath},
		{name: "build.main_version", value: observation.Build.MainVersion},
		{name: "build.dependency_graph_sha256", value: observation.Build.DependencyGraphSHA256},
		{name: "build.goos", value: observation.Build.GOOS},
		{name: "build.goarch", value: observation.Build.GOARCH},
		{name: "build.vcs_revision", value: observation.Build.VCSRevision},
		{name: "build.vcs_modified_known", value: strconv.FormatBool(observation.Build.VCSModifiedKnown)},
		{name: "build.vcs_modified_valid", value: strconv.FormatBool(observation.Build.VCSModifiedValid)},
		{name: "build.vcs_modified", value: strconv.FormatBool(observation.Build.VCSModified)},
		{name: "version_output", value: observation.VersionOutput},
	}

	digest := sha256.New()
	writeFingerprintValue(digest, reviewFingerprintDomain)
	for _, field := range fields {
		writeFingerprintValue(digest, field.name)
		writeFingerprintValue(digest, field.value)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

type fingerprintWriter interface {
	Write([]byte) (int, error)
}

func writeFingerprintValue(writer fingerprintWriter, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write([]byte(value))
}

func fingerprintTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}
