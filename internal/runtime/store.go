package runtime

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	selectionID            = 1
	maximumManifestIDBytes = 128
	rfc3339MaximumYear     = 9999
)

var (
	// ErrNoSelection reports that no runtime has been adopted yet.
	ErrNoSelection = errors.New("runtime executable is not selected")
	// ErrInvalidSelection identifies incomplete, inconsistent, or corrupted
	// reviewed evidence. Callers must not use such evidence for execution.
	ErrInvalidSelection = errors.New("runtime selection is invalid")
)

// Selection is the complete immutable evidence reviewed when an
// administrator adopts one exact executable. ManifestID identifies the exact
// compatibility statement used for that review; it is never inferred again
// from the version label alone.
type Selection struct {
	Observation Observation
	ManifestID  string
	ReviewedAt  time.Time
}

// SelectionDatabase is the application-state surface needed by the runtime
// selection store. state.DB implements it without exposing SQLite directly.
type SelectionDatabase interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// SelectionStore persists only non-secret executable identity metadata. The
// singleton record never contains executable bytes, credentials, provider
// configuration, certificate material, or private keys.
type SelectionStore struct {
	database SelectionDatabase
}

// NewSelectionStore constructs the singleton runtime selection store.
func NewSelectionStore(database SelectionDatabase) (*SelectionStore, error) {
	if database == nil {
		return nil, errors.New("runtime selection database is required")
	}
	return &SelectionStore{database: database}, nil
}

// Load reconstructs the complete reviewed selection without loss of unsigned
// filesystem identity values or timestamp precision. Corrupted rows fail
// closed as ErrInvalidSelection.
func (store *SelectionStore) Load(ctx context.Context) (Selection, error) {
	if store == nil || store.database == nil {
		return Selection{}, errors.New("runtime selection store is not initialized")
	}
	if ctx == nil {
		return Selection{}, errors.New("runtime selection context is required")
	}

	var persisted persistedSelection
	err := store.database.QueryRowContext(ctx, loadSelectionSQL, selectionID).Scan(
		&persisted.canonicalPath,
		&persisted.device,
		&persisted.inode,
		&persisted.mode,
		&persisted.capabilities,
		&persisted.uid,
		&persisted.gid,
		&persisted.size,
		&persisted.modifiedAt,
		&persisted.changedAt,
		&persisted.sha256,
		&persisted.versionKind,
		&persisted.versionValue,
		&persisted.platformOS,
		&persisted.platformArch,
		&persisted.buildAvailable,
		&persisted.buildProvenanceComplete,
		&persisted.buildGoVersion,
		&persisted.buildCommandPath,
		&persisted.buildMainPath,
		&persisted.buildMainVersion,
		&persisted.buildDependencyGraphSHA256,
		&persisted.buildGOOS,
		&persisted.buildGOARCH,
		&persisted.buildVCSRevision,
		&persisted.buildVCSModifiedKnown,
		&persisted.buildVCSModifiedValid,
		&persisted.buildVCSModified,
		&persisted.versionOutput,
		&persisted.observedAt,
		&persisted.manifestID,
		&persisted.reviewedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Selection{}, ErrNoSelection
	}
	if err != nil {
		return Selection{}, fmt.Errorf("load runtime selection: %w", err)
	}

	selection, err := persisted.selection()
	if err != nil {
		return Selection{}, fmt.Errorf("%w: persisted metadata: %v", ErrInvalidSelection, err)
	}
	return selection, nil
}

// Save atomically creates or replaces the one reviewed runtime selection.
func (store *SelectionStore) Save(ctx context.Context, selection Selection) error {
	if store == nil || store.database == nil {
		return errors.New("runtime selection store is not initialized")
	}
	if ctx == nil {
		return errors.New("runtime selection context is required")
	}
	if err := validateSelection(selection); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSelection, err)
	}

	observation := selection.Observation
	_, err := store.database.ExecContext(
		ctx,
		saveSelectionSQL,
		selectionID,
		observation.File.CanonicalPath,
		strconv.FormatUint(observation.File.Device, 10),
		strconv.FormatUint(observation.File.Inode, 10),
		int64(observation.File.Mode),
		observation.File.Capabilities,
		int64(observation.File.UID),
		int64(observation.File.GID),
		observation.File.Size,
		formatStoredTime(observation.File.ModifiedAt),
		formatStoredTime(observation.File.ChangedAt),
		observation.File.SHA256,
		string(observation.Version.Kind),
		observation.Version.Value,
		observation.Platform.OS,
		observation.Platform.Arch,
		boolInteger(observation.Build.Available),
		boolInteger(observation.Build.ProvenanceComplete),
		observation.Build.GoVersion,
		observation.Build.CommandPath,
		observation.Build.MainPath,
		observation.Build.MainVersion,
		observation.Build.DependencyGraphSHA256,
		observation.Build.GOOS,
		observation.Build.GOARCH,
		observation.Build.VCSRevision,
		boolInteger(observation.Build.VCSModifiedKnown),
		boolInteger(observation.Build.VCSModifiedValid),
		boolInteger(observation.Build.VCSModified),
		observation.VersionOutput,
		formatStoredTime(observation.ObservedAt),
		selection.ManifestID,
		formatStoredTime(selection.ReviewedAt),
	)
	if err != nil {
		return fmt.Errorf("save runtime selection: %w", err)
	}
	return nil
}

// Clear atomically removes the selected runtime. It is idempotent.
func (store *SelectionStore) Clear(ctx context.Context) error {
	if store == nil || store.database == nil {
		return errors.New("runtime selection store is not initialized")
	}
	if ctx == nil {
		return errors.New("runtime selection context is required")
	}
	if _, err := store.database.ExecContext(ctx, "DELETE FROM runtime_selection WHERE singleton_id = ?", selectionID); err != nil {
		return fmt.Errorf("clear runtime selection: %w", err)
	}
	return nil
}

type persistedSelection struct {
	canonicalPath              string
	device                     string
	inode                      string
	mode                       int64
	capabilities               string
	uid                        int64
	gid                        int64
	size                       int64
	modifiedAt                 string
	changedAt                  string
	sha256                     string
	versionKind                string
	versionValue               string
	platformOS                 string
	platformArch               string
	buildAvailable             int64
	buildProvenanceComplete    int64
	buildGoVersion             string
	buildCommandPath           string
	buildMainPath              string
	buildMainVersion           string
	buildDependencyGraphSHA256 string
	buildGOOS                  string
	buildGOARCH                string
	buildVCSRevision           string
	buildVCSModifiedKnown      int64
	buildVCSModifiedValid      int64
	buildVCSModified           int64
	versionOutput              string
	observedAt                 string
	manifestID                 string
	reviewedAt                 string
}

func (persisted persistedSelection) selection() (Selection, error) {
	device, err := strconv.ParseUint(persisted.device, 10, 64)
	if err != nil || strconv.FormatUint(device, 10) != persisted.device {
		return Selection{}, errors.New("device is not canonical unsigned decimal")
	}
	inode, err := strconv.ParseUint(persisted.inode, 10, 64)
	if err != nil || strconv.FormatUint(inode, 10) != persisted.inode {
		return Selection{}, errors.New("inode is not canonical unsigned decimal")
	}
	mode, err := storedUint32(persisted.mode, "mode")
	if err != nil {
		return Selection{}, err
	}
	uid, err := storedUint32(persisted.uid, "uid")
	if err != nil {
		return Selection{}, err
	}
	gid, err := storedUint32(persisted.gid, "gid")
	if err != nil {
		return Selection{}, err
	}
	modifiedAt, err := parseStoredTime(persisted.modifiedAt)
	if err != nil {
		return Selection{}, fmt.Errorf("modified time: %w", err)
	}
	changedAt, err := parseStoredTime(persisted.changedAt)
	if err != nil {
		return Selection{}, fmt.Errorf("changed time: %w", err)
	}
	observedAt, err := parseStoredTime(persisted.observedAt)
	if err != nil {
		return Selection{}, fmt.Errorf("observation time: %w", err)
	}
	reviewedAt, err := parseStoredTime(persisted.reviewedAt)
	if err != nil {
		return Selection{}, fmt.Errorf("review time: %w", err)
	}
	buildAvailable, err := storedBoolean(persisted.buildAvailable, "build available")
	if err != nil {
		return Selection{}, err
	}
	buildProvenanceComplete, err := storedBoolean(persisted.buildProvenanceComplete, "build provenance complete")
	if err != nil {
		return Selection{}, err
	}
	buildModifiedKnown, err := storedBoolean(persisted.buildVCSModifiedKnown, "build VCS modified known")
	if err != nil {
		return Selection{}, err
	}
	buildModifiedValid, err := storedBoolean(persisted.buildVCSModifiedValid, "build VCS modified valid")
	if err != nil {
		return Selection{}, err
	}
	buildModified, err := storedBoolean(persisted.buildVCSModified, "build VCS modified")
	if err != nil {
		return Selection{}, err
	}

	selection := Selection{
		Observation: Observation{
			File: FileIdentity{
				CanonicalPath: persisted.canonicalPath,
				Device:        device,
				Inode:         inode,
				Mode:          mode,
				Capabilities:  persisted.capabilities,
				UID:           uid,
				GID:           gid,
				Size:          persisted.size,
				ModifiedAt:    modifiedAt,
				ChangedAt:     changedAt,
				SHA256:        persisted.sha256,
			},
			Version: VersionIdentity{
				Kind:  VersionKind(persisted.versionKind),
				Value: persisted.versionValue,
			},
			Platform: Platform{OS: persisted.platformOS, Arch: persisted.platformArch},
			Build: BuildEvidence{
				Available:             buildAvailable,
				ProvenanceComplete:    buildProvenanceComplete,
				GoVersion:             persisted.buildGoVersion,
				CommandPath:           persisted.buildCommandPath,
				MainPath:              persisted.buildMainPath,
				MainVersion:           persisted.buildMainVersion,
				DependencyGraphSHA256: persisted.buildDependencyGraphSHA256,
				GOOS:                  persisted.buildGOOS,
				GOARCH:                persisted.buildGOARCH,
				VCSRevision:           persisted.buildVCSRevision,
				VCSModifiedKnown:      buildModifiedKnown,
				VCSModifiedValid:      buildModifiedValid,
				VCSModified:           buildModified,
			},
			VersionOutput: persisted.versionOutput,
			ObservedAt:    observedAt,
		},
		ManifestID: persisted.manifestID,
		ReviewedAt: reviewedAt,
	}
	if err := validateSelection(selection); err != nil {
		return Selection{}, err
	}
	return selection, nil
}

func validateSelection(selection Selection) error {
	observation := selection.Observation
	if err := validateStoredPath(observation.File.CanonicalPath); err != nil {
		return err
	}
	if observation.File.Mode&0o170000 != 0o100000 {
		return errors.New("file mode does not identify a regular file")
	}
	if observation.File.Mode&0o022 != 0 {
		return errors.New("file mode permits group or other writes")
	}
	if observation.File.Mode&0o7000 != 0 {
		return errors.New("file mode contains a special permission bit")
	}
	if observation.File.Mode&0o111 == 0 {
		return errors.New("file mode has no execute permission")
	}
	if observation.File.Capabilities != "" && observation.File.Capabilities != "cap_net_bind_service=ep" {
		return errors.New("file capabilities are outside the executable policy")
	}
	if observation.File.Size <= 0 || observation.File.Size > maximumExecutableSize {
		return errors.New("file size is outside the executable policy")
	}
	if !canonicalSHA256(observation.File.SHA256) {
		return errors.New("SHA-256 fingerprint is not canonical lowercase hexadecimal")
	}
	for name, value := range map[string]time.Time{
		"modified time":    observation.File.ModifiedAt,
		"changed time":     observation.File.ChangedAt,
		"observation time": observation.ObservedAt,
		"review time":      selection.ReviewedAt,
	} {
		if err := validateStoredTime(value); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	switch observation.Version.Kind {
	case VersionRelease:
		match := releasePattern.FindStringSubmatch(observation.Version.Value)
		if match == nil || !strings.HasPrefix(observation.Version.Value, "v") {
			return errors.New("release identity is not canonical")
		}
		for _, component := range match[1:] {
			if len(component) > 1 && component[0] == '0' {
				return errors.New("release identity is not canonical")
			}
		}
	case VersionRevision:
		if !revisionPattern.MatchString(observation.Version.Value) {
			return errors.New("source revision is not canonical")
		}
	default:
		return errors.New("version kind is unknown")
	}
	if !observation.Platform.Supported() {
		return errors.New("platform is outside the native runtime policy")
	}
	parsedVersion, parsedPlatform, parsedOutput, err := ParseVersionOutput([]byte(observation.VersionOutput + "\n"))
	if err != nil || parsedVersion != observation.Version || parsedPlatform != observation.Platform || parsedOutput != observation.VersionOutput {
		return errors.New("version output disagrees with the parsed identity")
	}
	if err := validateStoredBuildEvidence(observation.Build, observation.Version, observation.Platform); err != nil {
		return err
	}
	if err := validateManifestID(selection.ManifestID); err != nil {
		return err
	}
	return nil
}

func validateStoredBuildEvidence(build BuildEvidence, version VersionIdentity, platform Platform) error {
	if !build.Available {
		if build != (BuildEvidence{}) {
			return errors.New("unavailable build evidence contains values")
		}
		return errors.New("embedded Go build evidence is required")
	}
	if !build.ProvenanceComplete {
		return errors.New("embedded Go build provenance is incomplete")
	}
	for name, field := range map[string]struct {
		value   string
		maximum int
	}{
		"Go version":   {build.GoVersion, 128},
		"command path": {build.CommandPath, 256},
		"main path":    {build.MainPath, 256},
		"main version": {build.MainVersion, 256},
		"build OS":     {build.GOOS, 32},
		"build arch":   {build.GOARCH, 32},
		"VCS revision": {build.VCSRevision, 40},
	} {
		if field.value == "" || !boundedPrintableBuildField(field.value, field.maximum) {
			return fmt.Errorf("%s is malformed", name)
		}
	}
	if build.CommandPath != "github.com/go-acme/lego/v5" {
		return errors.New("build command path is not upstream lego")
	}
	if !canonicalSHA256(build.DependencyGraphSHA256) {
		return errors.New("build dependency graph SHA-256 is not canonical lowercase hexadecimal")
	}
	if build.MainPath != "github.com/go-acme/lego/v5" {
		return errors.New("build main path is not upstream lego")
	}
	if !platformPattern.MatchString(build.GOOS) || build.GOOS != platform.OS {
		return errors.New("build operating system disagrees with the runtime platform")
	}
	if !platformPattern.MatchString(build.GOARCH) || build.GOARCH != platform.Arch {
		return errors.New("build architecture disagrees with the runtime platform")
	}
	if !revisionPattern.MatchString(build.VCSRevision) {
		return errors.New("build VCS revision is malformed")
	}
	if version.Kind == VersionRevision && build.VCSRevision != version.Value {
		return errors.New("build VCS revision disagrees with the reported revision")
	}
	if !build.VCSModifiedKnown || !build.VCSModifiedValid {
		return errors.New("build VCS modified evidence is incomplete or malformed")
	}
	if build.VCSModified {
		return errors.New("build VCS evidence reports modified source")
	}
	return nil
}

func canonicalSHA256(value string) bool {
	return len(value) == 64 && strings.IndexFunc(value, func(character rune) bool {
		return (character < '0' || character > '9') && (character < 'a' || character > 'f')
	}) < 0
}

func validateStoredPath(value string) error {
	if value == "" || len(value) > maximumPathLength {
		return errors.New("canonical path has an invalid length")
	}
	if !utf8.ValidString(value) || strings.IndexFunc(value, func(character rune) bool {
		return character < 0x20 || character == 0x7f
	}) >= 0 {
		return errors.New("canonical path contains invalid text")
	}
	if value[0] != '/' || value == "/" || path.Clean(value) != value {
		return errors.New("executable path is not canonical and absolute")
	}
	return nil
}

func validateManifestID(value string) error {
	if value == "" || len(value) > maximumManifestIDBytes || !utf8.ValidString(value) {
		return errors.New("compatibility manifest ID has an invalid length or encoding")
	}
	for index, character := range value {
		lowercaseOrDigit := character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
		if !lowercaseOrDigit && (index == 0 || character != '.' && character != '_' && character != '-') {
			return errors.New("compatibility manifest ID is not canonical")
		}
	}
	return nil
}

func validateStoredTime(value time.Time) error {
	if value.IsZero() || value.Location() != time.UTC || value.Year() < 1 || value.Year() > rfc3339MaximumYear {
		return errors.New("timestamp must be nonzero UTC RFC 3339 time")
	}
	if value != value.Round(0) {
		return errors.New("timestamp contains non-persistable monotonic data")
	}
	return nil
}

func formatStoredTime(value time.Time) string {
	return value.Format(time.RFC3339Nano)
}

func parseStoredTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.New("timestamp is not canonical UTC RFC 3339 nanosecond text")
	}
	if err := validateStoredTime(parsed); err != nil {
		return time.Time{}, err
	}
	return parsed, nil
}

func storedUint32(value int64, name string) (uint32, error) {
	if value < 0 || value > int64(^uint32(0)) {
		return 0, fmt.Errorf("%s is outside unsigned 32-bit range", name)
	}
	return uint32(value), nil
}

func storedBoolean(value int64, name string) (bool, error) {
	switch value {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, fmt.Errorf("%s is not a Boolean", name)
	}
}

func boolInteger(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

const loadSelectionSQL = `
SELECT
    canonical_path,
    device_decimal,
    inode_decimal,
    mode,
    capabilities,
    uid,
    gid,
    size_bytes,
    modified_at_utc,
    changed_at_utc,
    sha256,
    version_kind,
    version_value,
    platform_os,
    platform_arch,
    build_available,
    build_provenance_complete,
    build_go_version,
    build_command_path,
    build_main_path,
    build_main_version,
    build_dependency_graph_sha256,
    build_goos,
    build_goarch,
    build_vcs_revision,
    build_vcs_modified_known,
    build_vcs_modified_valid,
    build_vcs_modified,
    version_output,
    observed_at_utc,
    compatibility_manifest_id,
    reviewed_at_utc
FROM runtime_selection
WHERE singleton_id = ?`

const saveSelectionSQL = `
INSERT INTO runtime_selection (
    singleton_id,
    canonical_path,
    device_decimal,
    inode_decimal,
    mode,
    capabilities,
    uid,
    gid,
    size_bytes,
    modified_at_utc,
    changed_at_utc,
    sha256,
    version_kind,
    version_value,
    platform_os,
    platform_arch,
    build_available,
    build_provenance_complete,
    build_go_version,
    build_command_path,
    build_main_path,
    build_main_version,
    build_dependency_graph_sha256,
    build_goos,
    build_goarch,
    build_vcs_revision,
    build_vcs_modified_known,
    build_vcs_modified_valid,
    build_vcs_modified,
    version_output,
    observed_at_utc,
    compatibility_manifest_id,
    reviewed_at_utc
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(singleton_id) DO UPDATE SET
    canonical_path = excluded.canonical_path,
    device_decimal = excluded.device_decimal,
    inode_decimal = excluded.inode_decimal,
    mode = excluded.mode,
    capabilities = excluded.capabilities,
    uid = excluded.uid,
    gid = excluded.gid,
    size_bytes = excluded.size_bytes,
    modified_at_utc = excluded.modified_at_utc,
    changed_at_utc = excluded.changed_at_utc,
    sha256 = excluded.sha256,
    version_kind = excluded.version_kind,
    version_value = excluded.version_value,
    platform_os = excluded.platform_os,
    platform_arch = excluded.platform_arch,
    build_available = excluded.build_available,
    build_provenance_complete = excluded.build_provenance_complete,
    build_go_version = excluded.build_go_version,
    build_command_path = excluded.build_command_path,
    build_main_path = excluded.build_main_path,
    build_main_version = excluded.build_main_version,
    build_dependency_graph_sha256 = excluded.build_dependency_graph_sha256,
    build_goos = excluded.build_goos,
    build_goarch = excluded.build_goarch,
    build_vcs_revision = excluded.build_vcs_revision,
    build_vcs_modified_known = excluded.build_vcs_modified_known,
    build_vcs_modified_valid = excluded.build_vcs_modified_valid,
    build_vcs_modified = excluded.build_vcs_modified,
    version_output = excluded.version_output,
    observed_at_utc = excluded.observed_at_utc,
    compatibility_manifest_id = excluded.compatibility_manifest_id,
    reviewed_at_utc = excluded.reviewed_at_utc`
