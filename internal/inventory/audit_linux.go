//go:build linux

package inventory

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const (
	maximumPathLength              = 4095
	maximumCertificateArtifactSize = 4 << 20
)

type fileSnapshot struct {
	Device         uint64
	Inode          uint64
	Mode           uint32
	UID            uint32
	GID            uint32
	LinkCount      uint64
	Size           int64
	ModifiedSecond int64
	ModifiedNano   int64
	ChangedSecond  int64
	ChangedNano    int64
}

type treeAudit struct {
	storage      fileSnapshot
	certificates *fileSnapshot
	entries      map[string]fileSnapshot
	resources    map[string]fileSnapshot
	expected     map[string]fileSnapshot
}

func validateCanonicalPath(path string) error {
	if path == "" {
		return &Error{Code: CodePathRequired}
	}
	if len(path) > maximumPathLength {
		return &Error{Code: CodePathTooLong}
	}
	if !utf8.ValidString(path) || strings.IndexFunc(path, invalidPathCharacter) >= 0 {
		return &Error{Code: CodePathNotCanonical, Detail: "path contains invalid text"}
	}
	if !filepath.IsAbs(path) {
		return &Error{Code: CodePathNotAbsolute, Path: path}
	}
	if filepath.Clean(path) != path || path == string(filepath.Separator) {
		return &Error{Code: CodePathNotCanonical, Path: path}
	}
	return nil
}

func invalidPathCharacter(character rune) bool {
	return character < 0x20 || character == 0x7f
}

func openDirectoryPath(path string) (*os.File, fileSnapshot, error) {
	if err := validateCanonicalPath(path); err != nil {
		return nil, fileSnapshot{}, err
	}
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	directoryFD, err := unix.Open(string(filepath.Separator), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fileSnapshot{}, &Error{Code: CodePathUnavailable, Path: path, Cause: err}
	}

	prefix := string(filepath.Separator)
	for index, component := range components {
		flags := unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if index == len(components)-1 {
			flags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		}
		nextFD, openErr := unix.Openat(directoryFD, component, flags, 0)
		_ = unix.Close(directoryFD)
		prefix = filepath.Join(prefix, component)
		if openErr != nil {
			return nil, fileSnapshot{}, classifyDirectoryOpenError(path, prefix, openErr)
		}
		directoryFD = nextFD
	}

	file := os.NewFile(uintptr(directoryFD), path)
	if file == nil {
		_ = unix.Close(directoryFD)
		return nil, fileSnapshot{}, &Error{Code: CodePathUnavailable, Path: path, Detail: "could not retain directory"}
	}
	stat, err := statFile(file, path)
	if err != nil {
		_ = file.Close()
		return nil, fileSnapshot{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		_ = file.Close()
		return nil, fileSnapshot{}, &Error{Code: CodeNotDirectory, Path: path}
	}
	return file, snapshotFromStat(stat), nil
}

func classifyDirectoryOpenError(selectedPath, componentPath string, err error) error {
	if errors.Is(err, unix.ELOOP) {
		return &Error{Code: CodeSymlink, Path: componentPath, Cause: err}
	}
	if info, statErr := os.Lstat(componentPath); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return &Error{Code: CodeSymlink, Path: componentPath, Cause: err}
		}
		if !info.IsDir() {
			return &Error{Code: CodeNotDirectory, Path: componentPath, Cause: err}
		}
	}
	if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
		return &Error{Code: CodeNotReadable, Path: selectedPath, Cause: err}
	}
	return &Error{Code: CodePathUnavailable, Path: selectedPath, Cause: err}
}

func statFile(file *os.File, path string) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return unix.Stat_t{}, &Error{Code: CodePathUnavailable, Path: path, Cause: err}
	}
	return stat, nil
}

func snapshotFromStat(stat unix.Stat_t) fileSnapshot {
	return fileSnapshot{
		Device:         uint64(stat.Dev),
		Inode:          stat.Ino,
		Mode:           stat.Mode,
		UID:            stat.Uid,
		GID:            stat.Gid,
		LinkCount:      stat.Nlink,
		Size:           stat.Size,
		ModifiedSecond: stat.Mtim.Sec,
		ModifiedNano:   stat.Mtim.Nsec,
		ChangedSecond:  stat.Ctim.Sec,
		ChangedNano:    stat.Ctim.Nsec,
	}
}

func (snapshot fileSnapshot) metadata() FileMetadata {
	return FileMetadata{
		Device:     snapshot.Device,
		Inode:      snapshot.Inode,
		Mode:       snapshot.Mode,
		UID:        snapshot.UID,
		GID:        snapshot.GID,
		LinkCount:  snapshot.LinkCount,
		Size:       snapshot.Size,
		ModifiedAt: time.Unix(snapshot.ModifiedSecond, snapshot.ModifiedNano).UTC(),
		ChangedAt:  time.Unix(snapshot.ChangedSecond, snapshot.ChangedNano).UTC(),
	}
}

func (reader *Reader) auditNeutralDirectory(ctx context.Context) (fileSnapshot, error) {
	if err := checkContext(ctx); err != nil {
		return fileSnapshot{}, err
	}
	directory, snapshot, err := openDirectoryPath(reader.policy.NeutralDirectory)
	if err != nil {
		return fileSnapshot{}, err
	}
	defer directory.Close()

	if snapshot.UID != reader.policy.EffectiveUID {
		return fileSnapshot{}, &Error{Code: CodeNeutralNotPrivate, Path: reader.policy.NeutralDirectory, Detail: "neutral directory must be owned by the service uid"}
	}
	if snapshot.Mode&0o7000 != 0 || snapshot.Mode&0o077 != 0 || snapshot.Mode&0o500 != 0o500 {
		return fileSnapshot{}, &Error{Code: CodeNeutralNotPrivate, Path: reader.policy.NeutralDirectory, Detail: "neutral directory must grant only its owner read and search access"}
	}
	if err := rejectConventionalConfiguration(directory, reader.policy.NeutralDirectory); err != nil {
		return fileSnapshot{}, err
	}
	return snapshot, nil
}

func rejectConventionalConfiguration(directory *os.File, path string) error {
	for _, name := range []string{".lego.yml", ".lego.yaml"} {
		var stat unix.Stat_t
		err := unix.Fstatat(int(directory.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW)
		if err == nil {
			return &Error{Code: CodeConfigurationPresent, Path: filepath.Join(path, name), Detail: "conventional lego configuration is not allowed in the neutral directory"}
		}
		if !errors.Is(err, unix.ENOENT) {
			return &Error{Code: CodePathUnavailable, Path: filepath.Join(path, name), Cause: err}
		}
	}
	return nil
}

func (reader *Reader) auditStorage(ctx context.Context, storagePath string) (treeAudit, error) {
	if err := checkContext(ctx); err != nil {
		return treeAudit{}, err
	}
	storage, storageSnapshot, err := openDirectoryPath(storagePath)
	if err != nil {
		return treeAudit{}, err
	}
	defer storage.Close()
	if err := reader.validateDirectory(storageSnapshot, storagePath); err != nil {
		return treeAudit{}, err
	}

	audit := treeAudit{
		storage:   storageSnapshot,
		entries:   make(map[string]fileSnapshot),
		resources: make(map[string]fileSnapshot),
		expected:  make(map[string]fileSnapshot),
	}
	certificatesPath := filepath.Join(storagePath, "certificates")
	certificates, certificatesSnapshot, err := reader.openChildDirectory(storage, "certificates", certificatesPath)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOENT) {
		return audit, nil
	}
	if err != nil {
		return treeAudit{}, err
	}
	defer certificates.Close()
	if err := reader.validateDirectory(certificatesSnapshot, certificatesPath); err != nil {
		return treeAudit{}, err
	}
	audit.certificates = &certificatesSnapshot

	entryCount := 0
	if err := reader.walkCertificates(ctx, certificates, certificatesPath, "", 0, &entryCount, &audit); err != nil {
		return treeAudit{}, err
	}
	if len(audit.resources) > reader.policy.MaximumCertificates {
		return treeAudit{}, &Error{Code: CodeCertificateLimit, Path: certificatesPath, Detail: "certificate resource count exceeds the configured limit"}
	}
	for relativeResource, resource := range audit.resources {
		resourcePath := filepath.Join(certificatesPath, relativeResource)
		if !reader.serviceCanRead(resource) {
			return treeAudit{}, &Error{Code: CodeNotReadable, Path: resourcePath, Detail: "certificate resource is not readable by the service identity"}
		}
		relativeCertificate := strings.TrimSuffix(relativeResource, ".json") + ".crt"
		certificate, ok := audit.entries[relativeCertificate]
		certificatePath := filepath.Join(certificatesPath, relativeCertificate)
		if !ok {
			return treeAudit{}, &Error{Code: CodePathUnavailable, Path: certificatePath, Detail: "certificate resource has no matching certificate artifact"}
		}
		if certificate.Mode&unix.S_IFMT != unix.S_IFREG {
			return treeAudit{}, &Error{Code: CodeNotRegular, Path: certificatePath}
		}
		if !reader.serviceCanRead(certificate) {
			return treeAudit{}, &Error{Code: CodeNotReadable, Path: certificatePath, Detail: "certificate artifact is not readable by the service identity"}
		}
		if certificate.Size <= 0 || certificate.Size > maximumCertificateArtifactSize {
			return treeAudit{}, &Error{Code: CodeArtifactSize, Path: certificatePath, Detail: "certificate artifact must be non-empty and no larger than 4 MiB"}
		}
		audit.expected[certificatePath] = certificate
	}
	return audit, nil
}

func (reader *Reader) openChildDirectory(parent *os.File, name, path string) (*os.File, fileSnapshot, error) {
	var before unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, fileSnapshot{}, os.ErrNotExist
		}
		return nil, fileSnapshot{}, &Error{Code: CodePathUnavailable, Path: path, Cause: err}
	}
	if before.Mode&unix.S_IFMT == unix.S_IFLNK {
		return nil, fileSnapshot{}, &Error{Code: CodeSymlink, Path: path}
	}
	if before.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, fileSnapshot{}, &Error{Code: CodeNotDirectory, Path: path}
	}
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fileSnapshot{}, &Error{Code: CodeSymlink, Path: path, Cause: err}
		}
		if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
			return nil, fileSnapshot{}, &Error{Code: CodeNotReadable, Path: path, Cause: err}
		}
		return nil, fileSnapshot{}, &Error{Code: CodePathUnavailable, Path: path, Cause: err}
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fileSnapshot{}, &Error{Code: CodePathUnavailable, Path: path, Detail: "could not retain directory"}
	}
	after, err := statFile(file, path)
	if err != nil {
		_ = file.Close()
		return nil, fileSnapshot{}, err
	}
	if before.Dev != after.Dev || before.Ino != after.Ino {
		_ = file.Close()
		return nil, fileSnapshot{}, &Error{Code: CodeArtifactsChanged, Path: path, Detail: "directory changed while it was opened"}
	}
	return file, snapshotFromStat(after), nil
}

func (reader *Reader) walkCertificates(
	ctx context.Context,
	directory *os.File,
	directoryPath string,
	relativeDirectory string,
	depth int,
	entryCount *int,
	audit *treeAudit,
) error {
	for {
		if err := checkContext(ctx); err != nil {
			return err
		}
		remaining := reader.policy.MaximumTreeEntries - *entryCount
		batchSize := 128
		if remaining < batchSize {
			batchSize = remaining + 1
		}
		entries, readErr := directory.ReadDir(batchSize)
		for _, entry := range entries {
			*entryCount++
			if *entryCount > reader.policy.MaximumTreeEntries {
				return &Error{Code: CodeTreeEntryLimit, Path: directoryPath, Detail: "certificate tree entry count exceeds the configured limit"}
			}
			name := entry.Name()
			if !utf8.ValidString(name) || strings.IndexFunc(name, invalidPathCharacter) >= 0 {
				return &Error{Code: CodePathNotCanonical, Path: directoryPath, Detail: "certificate tree contains an invalid native name"}
			}
			relativePath := filepath.Join(relativeDirectory, name)
			path := filepath.Join(directoryPath, name)
			if len(path) > maximumPathLength {
				return &Error{Code: CodePathTooLong, Path: path}
			}
			var stat unix.Stat_t
			if err := unix.Fstatat(int(directory.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return &Error{Code: CodePathUnavailable, Path: path, Cause: err}
			}
			kind := stat.Mode & unix.S_IFMT
			if kind == unix.S_IFLNK {
				return &Error{Code: CodeSymlink, Path: path}
			}
			snapshot := snapshotFromStat(stat)
			switch kind {
			case unix.S_IFDIR:
				if depth+1 > reader.policy.MaximumTreeDepth {
					return &Error{Code: CodeTreeDepthLimit, Path: path, Detail: "certificate tree depth exceeds the configured limit"}
				}
				if err := reader.validateDirectory(snapshot, path); err != nil {
					return err
				}
				child, opened, err := reader.openChildDirectory(directory, name, path)
				if err != nil {
					return err
				}
				if snapshot != opened {
					_ = child.Close()
					return &Error{Code: CodeArtifactsChanged, Path: path, Detail: "directory changed while it was opened"}
				}
				audit.entries[relativePath] = opened
				err = reader.walkCertificates(ctx, child, path, relativePath, depth+1, entryCount, audit)
				closeErr := child.Close()
				if err != nil {
					return err
				}
				if closeErr != nil {
					return &Error{Code: CodePathUnavailable, Path: path, Cause: closeErr}
				}
			case unix.S_IFREG:
				if err := reader.validateRegularFile(snapshot, path); err != nil {
					return err
				}
				if !reader.serviceCanRead(snapshot) {
					return &Error{Code: CodeNotReadable, Path: path, Detail: "native artifact is not readable by the service identity"}
				}
				if isPrivateArtifact(name) && snapshot.Mode&0o077 != 0 {
					return &Error{Code: CodeUnsafePermissions, Path: path, Detail: "private-key artifacts must not grant group or other permissions"}
				}
				audit.entries[relativePath] = snapshot
				if strings.HasSuffix(name, ".json") {
					audit.resources[relativePath] = snapshot
				}
			default:
				return &Error{Code: CodeNotRegular, Path: path, Detail: "special entries are not allowed in the certificate tree"}
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return &Error{Code: CodePathUnavailable, Path: directoryPath, Cause: readErr}
		}
	}
}

func isPrivateArtifact(name string) bool {
	return strings.HasSuffix(name, ".key") || strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".pfx")
}

func (reader *Reader) validateDirectory(snapshot fileSnapshot, path string) error {
	if snapshot.Mode&unix.S_IFMT != unix.S_IFDIR {
		return &Error{Code: CodeNotDirectory, Path: path}
	}
	if snapshot.UID != 0 && snapshot.UID != reader.policy.EffectiveUID {
		return &Error{Code: CodeUntrustedOwner, Path: path, Detail: fmt.Sprintf("owner uid %d is neither root nor the service uid", snapshot.UID)}
	}
	if snapshot.Mode&0o022 != 0 || snapshot.Mode&0o7000 != 0 {
		return &Error{Code: CodeUnsafePermissions, Path: path, Detail: "group/other write and special mode bits are not allowed"}
	}
	if !reader.serviceCanRead(snapshot) || !reader.serviceCanSearch(snapshot) {
		return &Error{Code: CodeNotReadable, Path: path, Detail: "directory is not readable and searchable by the service identity"}
	}
	return nil
}

func (reader *Reader) validateRegularFile(snapshot fileSnapshot, path string) error {
	if snapshot.Mode&unix.S_IFMT != unix.S_IFREG {
		return &Error{Code: CodeNotRegular, Path: path}
	}
	if snapshot.UID != 0 && snapshot.UID != reader.policy.EffectiveUID {
		return &Error{Code: CodeUntrustedOwner, Path: path, Detail: fmt.Sprintf("owner uid %d is neither root nor the service uid", snapshot.UID)}
	}
	if snapshot.Mode&0o022 != 0 || snapshot.Mode&0o7000 != 0 {
		return &Error{Code: CodeUnsafePermissions, Path: path, Detail: "group/other write and special mode bits are not allowed"}
	}
	if snapshot.LinkCount != 1 {
		return &Error{Code: CodeHardLink, Path: path, Detail: "native artifact must have exactly one hard link"}
	}
	return nil
}

func (reader *Reader) serviceCanRead(snapshot fileSnapshot) bool {
	return reader.serviceHasPermission(snapshot, 0o400, 0o040, 0o004)
}

func (reader *Reader) serviceCanSearch(snapshot fileSnapshot) bool {
	return reader.serviceHasPermission(snapshot, 0o100, 0o010, 0o001)
}

func (reader *Reader) serviceHasPermission(snapshot fileSnapshot, owner, group, other uint32) bool {
	if reader.policy.EffectiveUID == 0 {
		return true
	}
	if snapshot.UID == reader.policy.EffectiveUID {
		return snapshot.Mode&owner != 0
	}
	if slices.Contains(reader.policy.EffectiveGIDs, snapshot.GID) {
		return snapshot.Mode&group != 0
	}
	return snapshot.Mode&other != 0
}

func sameTree(first, second treeAudit) bool {
	if first.storage != second.storage {
		return false
	}
	if (first.certificates == nil) != (second.certificates == nil) {
		return false
	}
	if first.certificates != nil && *first.certificates != *second.certificates {
		return false
	}
	return sameSnapshotMap(first.entries, second.entries) &&
		sameSnapshotMap(first.resources, second.resources) &&
		sameSnapshotMap(first.expected, second.expected)
}

func sameSnapshotMap(first, second map[string]fileSnapshot) bool {
	if len(first) != len(second) {
		return false
	}
	for path, snapshot := range first {
		if current, ok := second[path]; !ok || current != snapshot {
			return false
		}
	}
	return true
}
