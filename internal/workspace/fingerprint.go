package workspace

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"time"
)

const reviewFingerprintDomain = "acmemux-workspace-review-v2"

// ReviewFingerprint returns a stable digest of all administrator-visible
// evidence except observation time and the digest field itself.
func ReviewFingerprint(review Review) string {
	return reviewFingerprint(review, reviewFingerprintDomain, writePathFingerprint)
}

func legacyReviewFingerprintV1(review Review) string {
	return reviewFingerprint(review, "acmemux-workspace-review-v1", writePathFingerprintV1)
}

// BootstrapFingerprint binds every no-follow creation observation without
// exposing native content. The configuration service keys and shortens this
// digest before it crosses the HTTP boundary.
func BootstrapFingerprint(audit BootstrapAudit) string {
	digest := sha256.New()
	writeFingerprintValue(digest, "acmemux-workspace-bootstrap-v1")
	writeFingerprintValue(digest, string(audit.ConfigurationSource))
	writePathFingerprint(digest, audit.WorkingDirectory)
	writeCandidatePathFingerprint(digest, audit.Configuration)
	writeCandidatePathFingerprint(digest, audit.AlternateConfiguration)
	writePathFingerprint(digest, audit.ConfigurationParent)
	writePathFingerprint(digest, audit.Storage)
	writeFingerprintValue(digest, strconv.Itoa(len(audit.Dotenv)))
	for _, path := range audit.Dotenv {
		writeCandidatePathFingerprint(digest, path)
	}
	writeFingerprintValue(digest, strconv.Itoa(len(audit.Webroots)))
	for _, path := range audit.Webroots {
		writePathFingerprint(digest, path)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func writeCandidatePathFingerprint(digest fingerprintWriter, path CandidatePath) {
	writeFingerprintValue(digest, string(path.Role))
	writeFingerprintValue(digest, path.Reference)
	writeFingerprintValue(digest, path.Path)
	writeFingerprintValue(digest, strconv.FormatBool(path.Exists))
	writeFingerprintValue(digest, strconv.FormatBool(path.WillCreate))
	writePathFingerprint(digest, path.Evidence)
}

func reviewFingerprint(review Review, domain string, writePath func(fingerprintWriter, PathEvidence)) string {
	digest := sha256.New()
	writeFingerprintValue(digest, domain)
	writeFingerprintValue(digest, string(review.ConfigurationSource))
	writeFingerprintValue(digest, strconv.FormatBool(review.Adoptable))
	paths := review.AllPaths()
	writeFingerprintValue(digest, strconv.Itoa(len(paths)))
	for _, evidence := range paths {
		writePath(digest, evidence)
	}
	writeFingerprintValue(digest, strconv.Itoa(len(review.Diagnostics)))
	for _, diagnostic := range review.Diagnostics {
		writeFingerprintValue(digest, string(diagnostic.Code))
		writeFingerprintValue(digest, string(diagnostic.Severity))
		writeFingerprintValue(digest, string(diagnostic.Role))
		writeFingerprintValue(digest, diagnostic.Path)
		writeFingerprintValue(digest, diagnostic.Component)
		writeFingerprintValue(digest, diagnostic.Detail)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func writePathFingerprintV1(digest fingerprintWriter, evidence PathEvidence) {
	writePathFingerprintPrefix(digest, evidence)
	writeFingerprintValue(digest, strconv.FormatInt(evidence.Size, 10))
	writeFingerprintValue(digest, fingerprintTime(evidence.ModifiedAt))
	writeFingerprintValue(digest, fingerprintTime(evidence.ChangedAt))
	writePathFingerprintSuffix(digest, evidence)
}

func writePathFingerprint(digest fingerprintWriter, evidence PathEvidence) {
	writePathFingerprintPrefix(digest, evidence)
	if evidence.Type == PathTypeDirectory {
		writeFingerprintValue(digest, "0")
		writeFingerprintValue(digest, "")
		writeFingerprintValue(digest, "")
	} else {
		writeFingerprintValue(digest, strconv.FormatInt(evidence.Size, 10))
		writeFingerprintValue(digest, fingerprintTime(evidence.ModifiedAt))
		writeFingerprintValue(digest, fingerprintTime(evidence.ChangedAt))
	}
	writePathFingerprintSuffix(digest, evidence)
}

func writePathFingerprintPrefix(digest fingerprintWriter, evidence PathEvidence) {
	writeFingerprintValue(digest, string(evidence.Role))
	writeFingerprintValue(digest, evidence.Reference)
	writeFingerprintValue(digest, evidence.Path)
	writeFingerprintValue(digest, strconv.FormatBool(evidence.Exists))
	writeFingerprintValue(digest, string(evidence.Type))
	writeFingerprintValue(digest, strconv.FormatUint(evidence.Device, 10))
	writeFingerprintValue(digest, strconv.FormatUint(evidence.Inode, 10))
	writeFingerprintValue(digest, strconv.FormatUint(uint64(evidence.Mode), 10))
	writeFingerprintValue(digest, strconv.FormatUint(uint64(evidence.UID), 10))
	writeFingerprintValue(digest, strconv.FormatUint(uint64(evidence.GID), 10))
	writeFingerprintValue(digest, strconv.FormatUint(evidence.NLink, 10))
}

func writePathFingerprintSuffix(digest fingerprintWriter, evidence PathEvidence) {
	writeAccessFingerprint(digest, evidence.Access)
	writeFingerprintValue(digest, strconv.FormatBool(evidence.Safe))
	writeFingerprintValue(digest, strconv.Itoa(len(evidence.Components)))
	for _, component := range evidence.Components {
		writeFingerprintValue(digest, component.Path)
		writeFingerprintValue(digest, string(component.Type))
		writeFingerprintValue(digest, strconv.FormatUint(component.Device, 10))
		writeFingerprintValue(digest, strconv.FormatUint(component.Inode, 10))
		writeFingerprintValue(digest, strconv.FormatUint(uint64(component.Mode), 10))
		writeFingerprintValue(digest, strconv.FormatUint(uint64(component.UID), 10))
		writeFingerprintValue(digest, strconv.FormatUint(uint64(component.GID), 10))
		writeAccessFingerprint(digest, component.Access)
	}
}

func writeAccessFingerprint(digest fingerprintWriter, access AccessEvidence) {
	writeFingerprintValue(digest, strconv.FormatBool(access.Readable))
	writeFingerprintValue(digest, strconv.FormatBool(access.Writable))
	writeFingerprintValue(digest, strconv.FormatBool(access.Searchable))
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
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
