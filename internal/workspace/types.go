package workspace

import (
	"os"
	"slices"
	"time"
)

const (
	maximumPathBytes              = 4095
	defaultConfigurationBytes     = int64(1 << 20)
	maximumConfigurationBytes     = int64(8 << 20)
	defaultMaximumReferencedPath  = 128
	maximumReferencedPaths        = 256
	maximumRecordedPathComponents = 64
	maximumComponentPathTextBytes = 32 << 10
	maximumYAMLNodes              = 32768
	maximumYAMLDepth              = 64
	maximumReviewDiagnostics      = 256
)

// Policy is the service identity and resource boundary used for inspection.
// Zero values are deliberately invalid for the security-sensitive limits.
type Policy struct {
	EffectiveUID          uint32
	EffectiveGIDs         []uint32
	MaxConfigurationBytes int64
	MaxReferencedPaths    int
	trustedRootUID        uint32
}

// DefaultPolicy returns the policy for the current non-root service process.
func DefaultPolicy() Policy {
	groups, err := os.Getgroups()
	if err != nil {
		groups = []int{os.Getegid()}
	}
	gids := []uint32{uint32(os.Getegid())}
	for _, group := range groups {
		gid := uint32(group)
		if !slices.Contains(gids, gid) {
			gids = append(gids, gid)
		}
	}
	return Policy{
		EffectiveUID:          uint32(os.Geteuid()),
		EffectiveGIDs:         gids,
		MaxConfigurationBytes: defaultConfigurationBytes,
		MaxReferencedPaths:    defaultMaximumReferencedPath,
	}
}

// Request identifies the effective working directory and, optionally, an
// explicit native configuration. An empty ConfigurationPath applies lego's
// .lego.yml-before-.lego.yaml discovery order.
type Request struct {
	WorkingDirectory  string
	ConfigurationPath string
}

// ConfigurationSource records how lego would select the configuration.
type ConfigurationSource string

const (
	ConfigurationExplicit         ConfigurationSource = "explicit"
	ConfigurationConventionalYML  ConfigurationSource = "conventional_yml"
	ConfigurationConventionalYAML ConfigurationSource = "conventional_yaml"
)

// PathRole states why a native path is part of the adopted set.
type PathRole string

const (
	RoleWorkingDirectory PathRole = "working_directory"
	RoleConfiguration    PathRole = "configuration"
	RoleStorage          PathRole = "storage"
	RoleDotenv           PathRole = "dotenv"
	RoleWebroot          PathRole = "webroot"
	RoleWorkspace        PathRole = "workspace"
	RoleCloudCredential  PathRole = "cloud_credential"
	RoleCloudHelper      PathRole = "cloud_helper"
	RoleCloudDirectory   PathRole = "cloud_directory"
)

// PathType is the no-follow type observed for a path component.
type PathType string

const (
	PathTypeUnknown   PathType = "unknown"
	PathTypeMissing   PathType = "missing"
	PathTypeDirectory PathType = "directory"
	PathTypeRegular   PathType = "regular"
	PathTypeSymlink   PathType = "symlink"
	PathTypeOther     PathType = "other"
)

// AccessEvidence is the access granted to the configured service identity by
// the observed Unix owner, group, and permission bits.
type AccessEvidence struct {
	Readable   bool
	Writable   bool
	Searchable bool
}

// ComponentEvidence records every absolute component traversed with
// O_PATH|O_NOFOLLOW, including the filesystem root and final object.
type ComponentEvidence struct {
	Path   string
	Type   PathType
	Device uint64
	Inode  uint64
	Mode   uint32
	UID    uint32
	GID    uint32
	// NLink is live audit context only. Directory link counts change with
	// unrelated sibling churn, so this field is not fingerprinted or persisted.
	NLink  uint64
	Access AccessEvidence
}

// PathEvidence is bounded, non-content filesystem evidence for one native
// path. Reference is the YAML spelling for referenced paths and empty for
// administrator-selected paths.
type PathEvidence struct {
	Role       PathRole
	Reference  string
	Path       string
	Exists     bool
	Type       PathType
	Device     uint64
	Inode      uint64
	Mode       uint32
	UID        uint32
	GID        uint32
	NLink      uint64
	Size       int64
	ModifiedAt time.Time
	ChangedAt  time.Time
	Access     AccessEvidence
	Components []ComponentEvidence
	Safe       bool
}

// DiagnosticSeverity distinguishes an adoption blocker from explanatory
// evidence such as conventional-name precedence.
type DiagnosticSeverity string

const (
	SeverityBlocking DiagnosticSeverity = "blocking"
	SeverityNotice   DiagnosticSeverity = "notice"
)

// Diagnostic is a stable, non-secret explanation of inspected evidence.
type Diagnostic struct {
	Code      ErrorCode
	Severity  DiagnosticSeverity
	Role      PathRole
	Path      string
	Component string
	Detail    string
}

// Review is the complete bounded workspace candidate evidence. Configuration
// and credential bytes are never retained here.
type Review struct {
	ConfigurationSource    ConfigurationSource
	WorkingDirectory       PathEvidence
	Configuration          PathEvidence
	Storage                PathEvidence
	DotenvFiles            []PathEvidence
	Webroots               []PathEvidence
	Diagnostics            []Diagnostic
	Adoptable              bool
	ReviewedEvidenceSHA256 string
	ObservedAt             time.Time
}

// AllPaths returns the reviewed paths in stable fingerprint order.
func (review Review) AllPaths() []PathEvidence {
	paths := make([]PathEvidence, 0, 3+len(review.DotenvFiles)+len(review.Webroots))
	paths = append(paths, review.WorkingDirectory, review.Configuration, review.Storage)
	paths = append(paths, review.DotenvFiles...)
	paths = append(paths, review.Webroots...)
	return paths
}
