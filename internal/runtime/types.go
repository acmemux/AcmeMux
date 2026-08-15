package runtime

import (
	"os"
	goruntime "runtime"
	"slices"
	"time"
)

const (
	maximumPathLength        = 4095
	maximumExecutableSize    = 512 << 20
	maximumVersionOutput     = 256
	defaultProbeOutputLimit  = 4096
	defaultProbeTimeout      = 5 * time.Second
	defaultInspectionTimeout = 30 * time.Second
	maximumProbeTimeout      = 30 * time.Second
	maximumInspectionTimeout = 2 * time.Minute
)

// AuditPolicy describes the operating-system identity allowed to use the
// executable. Owners are restricted to this effective UID or root; group and
// other write permission is never accepted.
type AuditPolicy struct {
	EffectiveUID  uint32
	EffectiveGIDs []uint32
}

// CurrentAuditPolicy returns the effective process identity used by the
// service. Callers should reject running the service itself as root at the
// deployment boundary; root ownership of a selected executable remains safe.
func CurrentAuditPolicy() AuditPolicy {
	groups, err := os.Getgroups()
	if err != nil {
		groups = []int{os.Getegid()}
	}
	gids := make([]uint32, 0, len(groups)+1)
	gids = append(gids, uint32(os.Getegid()))
	for _, group := range groups {
		gid := uint32(group)
		if !slices.Contains(gids, gid) {
			gids = append(gids, gid)
		}
	}
	return AuditPolicy{EffectiveUID: uint32(os.Geteuid()), EffectiveGIDs: gids}
}

// ProbePolicy bounds the non-mutating identity probe. Zero-value fields are
// invalid so security-sensitive defaults remain an explicit choice.
type ProbePolicy struct {
	Audit               AuditPolicy
	Timeout             time.Duration
	InspectionTimeout   time.Duration
	OutputLimit         int
	HostOS              string
	HostArch            string
	RequireTrustedBuild bool
	TrustedSHA256       []string
}

// DefaultProbePolicy is suitable for the native service process.
func DefaultProbePolicy() ProbePolicy {
	return ProbePolicy{
		Audit:               CurrentAuditPolicy(),
		Timeout:             defaultProbeTimeout,
		InspectionTimeout:   defaultInspectionTimeout,
		OutputLimit:         defaultProbeOutputLimit,
		HostOS:              goruntime.GOOS,
		HostArch:            goruntime.GOARCH,
		RequireTrustedBuild: true,
	}
}

// FileIdentity is the durable, non-secret fingerprint of the exact opened
// executable. Times are UTC and retain nanosecond precision where supported.
type FileIdentity struct {
	CanonicalPath string
	Device        uint64
	Inode         uint64
	Mode          uint32
	Capabilities  string
	UID           uint32
	GID           uint32
	Size          int64
	ModifiedAt    time.Time
	ChangedAt     time.Time
	SHA256        string
}

// VersionKind distinguishes an official release from a source revision.
type VersionKind string

const (
	VersionRelease  VersionKind = "release"
	VersionRevision VersionKind = "revision"
)

// VersionIdentity is the strictly parsed identity printed by lego --version.
// Release values are normalized with a leading v; revisions are lowercase
// forty-character Git object names.
type VersionIdentity struct {
	Kind  VersionKind
	Value string
}

// Platform is the platform claimed by the probed upstream executable.
type Platform struct {
	OS   string
	Arch string
}

// BuildEvidence records independently embedded Go build information when it
// is available. A false Available value is explicit evidence and is left for
// the exact compatibility manifest to classify.
type BuildEvidence struct {
	Available             bool
	ProvenanceComplete    bool
	GoVersion             string
	CommandPath           string
	MainPath              string
	MainVersion           string
	DependencyGraphSHA256 string
	GOOS                  string
	GOARCH                string
	VCSRevision           string
	VCSModifiedKnown      bool
	VCSModifiedValid      bool
	VCSModified           bool
}

// Supported reports the native MVP platform policy independently of any
// exact-version compatibility decision.
func (p Platform) Supported() bool {
	return p.OS == "linux" && (p.Arch == "amd64" || p.Arch == "arm64")
}

// Observation contains evidence only. It intentionally does not claim that
// the exact release or source revision is compatible with AcmeMux.
type Observation struct {
	File          FileIdentity
	Version       VersionIdentity
	Platform      Platform
	Build         BuildEvidence
	VersionOutput string
	ObservedAt    time.Time
}
