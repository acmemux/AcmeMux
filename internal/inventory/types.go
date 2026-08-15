package inventory

import (
	"context"
	"os"
	"os/exec"
	"slices"
	"time"
)

const (
	defaultTimeout             = 20 * time.Second
	defaultStandardOutputLimit = 4 << 20
	defaultErrorOutputLimit    = 64 << 10
	defaultMaximumCertificates = 2048
	defaultMaximumTreeEntries  = 16384
	defaultMaximumTreeDepth    = 32
)

// PreparedExecutable is the one-shot trusted runtime handle needed by Reader.
// The concrete runtime.PreparedExecutable satisfies this interface.
type PreparedExecutable interface {
	StartContext(context.Context, func(*exec.Cmd) error, ...string) (*exec.Cmd, error)
	Close() error
}

// Policy bounds an inventory read and identifies the service account whose
// filesystem access is being brokered. NeutralDirectory must be an existing,
// canonical, service-owned private directory used only as a command cwd.
type Policy struct {
	EffectiveUID  uint32
	EffectiveGIDs []uint32

	NeutralDirectory string
	Timeout          time.Duration
	StdoutLimit      int
	StderrLimit      int

	MaximumCertificates int
	MaximumTreeEntries  int
	MaximumTreeDepth    int
}

// DefaultPolicy returns explicit native-service bounds for neutralDirectory.
func DefaultPolicy(neutralDirectory string) Policy {
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
		EffectiveUID:        uint32(os.Geteuid()),
		EffectiveGIDs:       gids,
		NeutralDirectory:    neutralDirectory,
		Timeout:             defaultTimeout,
		StdoutLimit:         defaultStandardOutputLimit,
		StderrLimit:         defaultErrorOutputLimit,
		MaximumCertificates: defaultMaximumCertificates,
		MaximumTreeEntries:  defaultMaximumTreeEntries,
		MaximumTreeDepth:    defaultMaximumTreeDepth,
	}
}

// FileMetadata is non-secret evidence for one native certificate artifact.
// Times are UTC and retain filesystem nanosecond precision when available.
type FileMetadata struct {
	Device     uint64
	Inode      uint64
	Mode       uint32
	UID        uint32
	GID        uint32
	LinkCount  uint64
	Size       int64
	ModifiedAt time.Time
	ChangedAt  time.Time
}

// Certificate is the bounded inventory projection exposed to AcmeMux. No
// certificate, resource, account, or key bytes are retained here.
type Certificate struct {
	Name       string
	DNSNames   []string
	Issuer     string
	ExpiresAt  time.Time
	NativePath string
	Artifact   FileMetadata
}
