//go:build linux

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// O_PATH is Linux-specific and intentionally used for directory traversal and
// the final candidate. That lets us reject a special file before opening it
// for reading, while still supporting executables below search-only
// directories.
const linuxOPath = 0x200000

const (
	allowedLinuxFileCapability   = "cap_net_bind_service=ep"
	linuxCapabilityRevision2     = 0x02000000
	linuxCapabilityEffective     = 0x00000001
	linuxCapabilityRevision2Size = 20
)

type openedExecutable struct {
	file     *os.File
	identity FileIdentity
}

// AuditExecutable audits and fingerprints an executable without running it.
func AuditExecutable(path string, policy AuditPolicy) (FileIdentity, error) {
	opened, err := openExecutableContext(context.Background(), path, policy)
	if err != nil {
		return FileIdentity{}, err
	}
	defer opened.file.Close()
	return opened.identity, nil
}

func openExecutableContext(ctx context.Context, path string, policy AuditPolicy) (openedExecutable, error) {
	if err := validateSelectedPath(path); err != nil {
		return openedExecutable{}, err
	}

	file, err := openWithoutSymlinks(path, policy)
	if err != nil {
		return openedExecutable{}, err
	}
	identity, err := fingerprintOpenedFileContext(ctx, file, path, policy)
	if err != nil {
		file.Close()
		return openedExecutable{}, err
	}
	return openedExecutable{file: file, identity: identity}, nil
}

func validateSelectedPath(path string) error {
	if path == "" {
		return &Error{Code: CodePathRequired}
	}
	if len(path) > maximumPathLength {
		return &Error{Code: CodePathTooLong}
	}
	if !utf8.ValidString(path) || strings.IndexFunc(path, func(character rune) bool { return character < 0x20 || character == 0x7f }) >= 0 {
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

func openWithoutSymlinks(path string, policy AuditPolicy) (*os.File, error) {
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	directoryFD, err := syscall.Open(string(filepath.Separator), linuxOPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &Error{Code: CodePathUnavailable, Path: path, Cause: err}
	}

	prefix := string(filepath.Separator)
	for _, component := range components[:len(components)-1] {
		nextFD, openErr := syscall.Openat(directoryFD, component, linuxOPath|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(directoryFD)
		prefix = filepath.Join(prefix, component)
		if openErr != nil {
			return nil, classifyOpenError(path, prefix, openErr)
		}
		directoryFD = nextFD
	}

	name := components[len(components)-1]
	pathFD, openErr := syscall.Openat(directoryFD, name, linuxOPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	syscall.Close(directoryFD)
	if openErr != nil {
		return nil, classifyOpenError(path, path, openErr)
	}
	pathFile := os.NewFile(uintptr(pathFD), path)
	if pathFile == nil {
		syscall.Close(pathFD)
		return nil, &Error{Code: CodePathUnavailable, Path: path, Detail: "could not retain the opened executable"}
	}
	defer pathFile.Close()

	pinned, err := statOpenedFile(pathFile, path)
	if err != nil {
		return nil, err
	}
	if pinned.Mode&syscall.S_IFMT == syscall.S_IFLNK {
		return nil, &Error{Code: CodeSymlink, Path: path}
	}
	if err := validateMetadata(pinned, path, policy); err != nil {
		return nil, err
	}

	// Reopen the exact object held by the O_PATH descriptor. The selected path
	// is never resolved again, so a concurrent rename cannot redirect the read
	// or the later execution. O_NOCTTY is defense in depth: the type check above
	// has already rejected terminal devices before this read open.
	procPath := "/proc/self/fd/" + strconv.Itoa(pathFD)
	readFD, openErr := syscall.Open(procPath, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if openErr != nil {
		return nil, &Error{Code: CodePathUnavailable, Path: path, Detail: "could not reopen the pinned executable", Cause: openErr}
	}
	file := os.NewFile(uintptr(readFD), path)
	if file == nil {
		syscall.Close(readFD)
		return nil, &Error{Code: CodePathUnavailable, Path: path, Detail: "could not retain the reopened executable"}
	}
	reopened, err := statOpenedFile(file, path)
	if err != nil {
		file.Close()
		return nil, err
	}
	if !sameStableMetadata(pinned, reopened) {
		file.Close()
		return nil, &Error{Code: CodeChangedDuringInspection, Path: path, Detail: "file metadata changed while reopening the pinned executable"}
	}
	return file, nil
}

func classifyOpenError(selectedPath, componentPath string, err error) error {
	if errors.Is(err, syscall.ELOOP) {
		return &Error{Code: CodeSymlink, Path: componentPath, Cause: err}
	}
	// O_NOFOLLOW|O_DIRECTORY reports a symbolic-link directory as ENOTDIR on
	// Linux. Lstat is used only to improve the diagnostic after the safe open
	// has already failed; it is never used to authorize access.
	if info, statErr := os.Lstat(componentPath); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return &Error{Code: CodeSymlink, Path: componentPath, Cause: err}
	}
	return &Error{Code: CodePathUnavailable, Path: selectedPath, Cause: err}
}

func fingerprintOpenedFileContext(ctx context.Context, file *os.File, path string, policy AuditPolicy) (FileIdentity, error) {
	before, err := statOpenedFile(file, path)
	if err != nil {
		return FileIdentity{}, err
	}
	if err := validateMetadata(before, path, policy); err != nil {
		return FileIdentity{}, err
	}
	capabilitiesBefore, err := readLinuxFileCapabilities(file, path)
	if err != nil {
		return FileIdentity{}, err
	}
	digest, bytesRead, err := hashOpenedFile(ctx, file)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return FileIdentity{}, &Error{Code: CodeInspectionTimeout, Path: path, Cause: err}
		}
		if errors.Is(err, context.Canceled) {
			return FileIdentity{}, &Error{Code: CodeInspectionCanceled, Path: path, Cause: err}
		}
		return FileIdentity{}, &Error{Code: CodeFingerprintFailed, Path: path, Cause: err}
	}
	after, err := statOpenedFile(file, path)
	if err != nil {
		return FileIdentity{}, err
	}
	capabilitiesAfter, err := readLinuxFileCapabilities(file, path)
	if err != nil {
		return FileIdentity{}, err
	}
	if !sameStableMetadata(before, after) || capabilitiesBefore != capabilitiesAfter || bytesRead != before.Size {
		return FileIdentity{}, &Error{Code: CodeChangedDuringInspection, Path: path, Detail: "file metadata changed while hashing"}
	}

	return identityFromStat(path, before, digest, capabilitiesBefore), nil
}

func statOpenedFile(file *os.File, path string) (syscall.Stat_t, error) {
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &stat); err != nil {
		return syscall.Stat_t{}, &Error{Code: CodePathUnavailable, Path: path, Cause: err}
	}
	return stat, nil
}

func validateMetadata(stat syscall.Stat_t, path string, policy AuditPolicy) error {
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return &Error{Code: CodeNotRegular, Path: path}
	}
	if stat.Size == 0 {
		return &Error{Code: CodeEmptyExecutable, Path: path}
	}
	if stat.Size < 0 || stat.Size > maximumExecutableSize {
		return &Error{Code: CodeExecutableTooLarge, Path: path}
	}
	if stat.Uid != 0 && stat.Uid != policy.EffectiveUID {
		return &Error{Code: CodeUntrustedOwner, Path: path, Detail: fmt.Sprintf("owner uid %d is neither root nor the service uid", stat.Uid)}
	}
	if stat.Mode&0o022 != 0 {
		return &Error{Code: CodeUnsafePermissions, Path: path, Detail: "group or other write permission is set"}
	}
	if stat.Mode&0o7000 != 0 {
		return &Error{Code: CodeUnsafePermissions, Path: path, Detail: "setuid, setgid, or sticky mode bits are not allowed"}
	}
	if !serviceCanExecute(stat, policy) {
		return &Error{Code: CodeNotExecutable, Path: path, Detail: "the service identity has no execute permission"}
	}
	return nil
}

func serviceCanExecute(stat syscall.Stat_t, policy AuditPolicy) bool {
	permissions := stat.Mode & 0o777
	if policy.EffectiveUID == 0 {
		return permissions&0o111 != 0
	}
	if stat.Uid == policy.EffectiveUID {
		return permissions&0o100 != 0
	}
	if slices.Contains(policy.EffectiveGIDs, stat.Gid) {
		return permissions&0o010 != 0
	}
	return permissions&0o001 != 0
}

func hashOpenedFile(ctx context.Context, file *os.File) (string, int64, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", 0, err
	}
	hash := sha256.New()
	buffer := make([]byte, 128<<10)
	var read int64
	for read <= maximumExecutableSize {
		if err := ctx.Err(); err != nil {
			return "", read, err
		}
		remaining := maximumExecutableSize + 1 - read
		chunk := buffer
		if int64(len(chunk)) > remaining {
			chunk = chunk[:remaining]
		}
		count, err := file.Read(chunk)
		if count > 0 {
			_, _ = hash.Write(chunk[:count])
			read += int64(count)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", read, err
		}
		if count == 0 {
			return "", read, io.ErrNoProgress
		}
	}
	if read > maximumExecutableSize {
		return "", read, &Error{Code: CodeExecutableTooLarge}
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", read, err
	}
	return hex.EncodeToString(hash.Sum(nil)), read, nil
}

func identityFromStat(path string, stat syscall.Stat_t, digest, capabilities string) FileIdentity {
	return FileIdentity{
		CanonicalPath: path,
		Device:        stat.Dev,
		Inode:         stat.Ino,
		Mode:          stat.Mode,
		Capabilities:  capabilities,
		UID:           stat.Uid,
		GID:           stat.Gid,
		Size:          stat.Size,
		ModifiedAt:    time.Unix(stat.Mtim.Sec, stat.Mtim.Nsec).UTC(),
		ChangedAt:     time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec).UTC(),
		SHA256:        digest,
	}
}

func readLinuxFileCapabilities(file *os.File, path string) (string, error) {
	buffer := make([]byte, 64)
	size, err := unix.Fgetxattr(int(file.Fd()), "security.capability", buffer)
	if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) {
		return "", nil
	}
	if err != nil {
		return "", &Error{Code: CodeUnsafeCapabilities, Path: path, Detail: "file capabilities could not be inspected", Cause: err}
	}
	return parseLinuxFileCapabilities(buffer[:size], path)
}

func parseLinuxFileCapabilities(value []byte, path string) (string, error) {
	if len(value) != linuxCapabilityRevision2Size {
		return "", &Error{Code: CodeUnsafeCapabilities, Path: path, Detail: "file capability metadata has an unsupported format"}
	}
	magic := binary.LittleEndian.Uint32(value[0:4])
	permittedLow := binary.LittleEndian.Uint32(value[4:8])
	inheritableLow := binary.LittleEndian.Uint32(value[8:12])
	permittedHigh := binary.LittleEndian.Uint32(value[12:16])
	inheritableHigh := binary.LittleEndian.Uint32(value[16:20])
	if magic != linuxCapabilityRevision2|linuxCapabilityEffective ||
		permittedLow != uint32(1)<<unix.CAP_NET_BIND_SERVICE ||
		inheritableLow != 0 || permittedHigh != 0 || inheritableHigh != 0 {
		return "", &Error{Code: CodeUnsafeCapabilities, Path: path, Detail: "only cap_net_bind_service=ep is allowed"}
	}
	return allowedLinuxFileCapability, nil
}

func sameStableMetadata(left, right syscall.Stat_t) bool {
	return left.Dev == right.Dev &&
		left.Ino == right.Ino &&
		left.Mode == right.Mode &&
		left.Uid == right.Uid &&
		left.Gid == right.Gid &&
		left.Size == right.Size &&
		left.Mtim == right.Mtim &&
		left.Ctim == right.Ctim
}

func sameFileIdentity(left, right FileIdentity) bool {
	return left == right
}
