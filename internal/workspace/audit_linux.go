//go:build linux

package workspace

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const linuxOPath = 0x200000

type pathRequirements struct {
	expected          PathType
	confidential      bool
	requireRead       bool
	requireWrite      bool
	requireSearch     bool
	requireParentSwap bool
	readHandle        bool
}

type auditedPath struct {
	evidence    PathEvidence
	diagnostics []Diagnostic
	file        *os.File
}

func auditPath(ctx context.Context, path string, role PathRole, reference string, requirements pathRequirements, policy Policy) auditedPath {
	result := auditedPath{evidence: PathEvidence{
		Role: role, Reference: reference, Path: path, Type: PathTypeUnknown,
	}}
	if err := ctx.Err(); err != nil {
		result.diagnostics = append(result.diagnostics, diagnostic(CodeInspectionCanceled, role, path, "", "inspection was canceled"))
		return result
	}
	if !boundedComponentEvidence(path) {
		result.diagnostics = append(result.diagnostics, diagnostic(CodePathTooDeep, role, path, "", "path traversal evidence exceeds the bounded component limit"))
		return result
	}

	rootFD, err := unix.Open("/", linuxOPath|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		result.diagnostics = append(result.diagnostics, diagnostic(CodePathUnavailable, role, path, "/", "filesystem root could not be inspected"))
		return result
	}
	currentFD := rootFD
	defer func() { _ = unix.Close(currentFD) }()

	rootStat, err := fstat(currentFD)
	if err != nil {
		result.diagnostics = append(result.diagnostics, diagnostic(CodePathUnavailable, role, path, "/", "filesystem root metadata could not be inspected"))
		return result
	}
	rootEvidence := componentFromStat("/", rootStat, policy)
	result.evidence.Components = append(result.evidence.Components, rootEvidence)
	result.diagnostics = append(result.diagnostics, auditTraversalComponent(rootEvidence, false, role, path, policy)...)

	trimmed := strings.TrimPrefix(path, "/")
	components := []string{}
	if trimmed != "" {
		components = strings.Split(trimmed, "/")
	}
	prefix := "/"
	var finalStat syscall.Stat_t
	if len(components) == 0 {
		finalStat = rootStat
	} else {
		for index, component := range components {
			if err := ctx.Err(); err != nil {
				result.diagnostics = append(result.diagnostics, diagnostic(CodeInspectionCanceled, role, path, prefix, "inspection was canceled"))
				return result
			}
			componentPath := filepath.Join(prefix, component)
			nextFD, openErr := unix.Openat(currentFD, component, linuxOPath|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if openErr != nil {
				code := CodePathUnavailable
				detail := "path component could not be inspected"
				if errors.Is(openErr, unix.ENOENT) {
					code = CodePathMissing
					detail = "path component does not exist"
					result.evidence.Type = PathTypeMissing
				}
				result.diagnostics = append(result.diagnostics, diagnostic(code, role, path, componentPath, detail))
				return result
			}
			_ = unix.Close(currentFD)
			currentFD = nextFD
			stat, statErr := fstat(currentFD)
			if statErr != nil {
				result.diagnostics = append(result.diagnostics, diagnostic(CodePathUnavailable, role, path, componentPath, "path component metadata could not be inspected"))
				return result
			}
			componentEvidence := componentFromStat(componentPath, stat, policy)
			result.evidence.Components = append(result.evidence.Components, componentEvidence)
			final := index == len(components)-1
			result.diagnostics = append(result.diagnostics, auditTraversalComponent(componentEvidence, final, role, path, policy)...)
			if componentEvidence.Type == PathTypeSymlink {
				result.evidence = pathFromFinalStat(result.evidence, stat, policy)
				result.diagnostics = append(result.diagnostics, diagnostic(CodeSymlinkNotAllowed, role, path, componentPath, "symbolic links are not allowed"))
				return result
			}
			if !final && componentEvidence.Type != PathTypeDirectory {
				result.diagnostics = append(result.diagnostics, diagnostic(CodeComponentNotDirectory, role, path, componentPath, "traversal component is not a directory"))
				return result
			}
			prefix = componentPath
			finalStat = stat
		}
	}

	result.evidence = pathFromFinalStat(result.evidence, finalStat, policy)
	result.diagnostics = append(result.diagnostics, auditFinalPath(result.evidence, requirements, policy)...)
	if requirements.requireParentSwap {
		result.diagnostics = append(result.diagnostics, auditReplacementParent(result.evidence, policy)...)
	}
	result.evidence.Safe = !hasBlockingDiagnostics(result.diagnostics)

	if requirements.readHandle && result.evidence.Exists && result.evidence.Type == PathTypeRegular {
		procPath := "/proc/self/fd/" + strconv.Itoa(currentFD)
		readFD, openErr := unix.Open(procPath, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
		if openErr != nil {
			result.diagnostics = append(result.diagnostics, diagnostic(CodePathNotReadable, role, path, path, "file could not be opened for reading"))
			result.evidence.Safe = false
			return result
		}
		file := os.NewFile(uintptr(readFD), path)
		if file == nil {
			_ = unix.Close(readFD)
			result.diagnostics = append(result.diagnostics, diagnostic(CodePathUnavailable, role, path, path, "opened file could not be retained"))
			result.evidence.Safe = false
			return result
		}
		reopened, statErr := fstat(readFD)
		if statErr != nil || !sameStableStat(finalStat, reopened) {
			_ = file.Close()
			result.diagnostics = append(result.diagnostics, diagnostic(CodeChangedDuringInspection, role, path, path, "file identity changed while it was opened"))
			result.evidence.Safe = false
			return result
		}
		result.file = file
	}
	return result
}

func boundedComponentEvidence(path string) bool {
	trimmed := strings.TrimPrefix(path, "/")
	componentCount := 1
	componentTextBytes := 1
	prefixBytes := 0
	if trimmed != "" {
		for _, component := range strings.Split(trimmed, "/") {
			componentCount++
			prefixBytes += 1 + len(component)
			componentTextBytes += prefixBytes
			if componentCount > maximumRecordedPathComponents || componentTextBytes > maximumComponentPathTextBytes {
				return false
			}
		}
	}
	return true
}

func auditTraversalComponent(component ComponentEvidence, final bool, role PathRole, selectedPath string, policy Policy) []Diagnostic {
	var diagnostics []Diagnostic
	if component.UID != policy.trustedRootUID && component.UID != policy.EffectiveUID {
		diagnostics = append(diagnostics, diagnostic(CodePathOwnerUntrusted, role, selectedPath, component.Path, "owner is neither root nor the service identity"))
	}
	permissions := component.Mode & 0o7777
	unsafeWrite := permissions&0o022 != 0
	rootStickyAncestor := !final && component.UID == policy.trustedRootUID && permissions&0o1000 != 0
	if unsafeWrite && !rootStickyAncestor {
		diagnostics = append(diagnostics, diagnostic(CodePathPermissionsUnsafe, role, selectedPath, component.Path, "group or other write permission is set"))
	}
	if permissions&0o6000 != 0 || permissions&0o1000 != 0 && !rootStickyAncestor {
		diagnostics = append(diagnostics, diagnostic(CodePathPermissionsUnsafe, role, selectedPath, component.Path, "special permission bits are set"))
	}
	if component.Type == PathTypeDirectory && !component.Access.Searchable {
		diagnostics = append(diagnostics, diagnostic(CodePathNotSearchable, role, selectedPath, component.Path, "service identity cannot search the directory"))
	}
	return diagnostics
}

func auditFinalPath(evidence PathEvidence, requirements pathRequirements, _ Policy) []Diagnostic {
	var diagnostics []Diagnostic
	if !evidence.Exists {
		return diagnostics
	}
	if evidence.Type != requirements.expected {
		diagnostics = append(diagnostics, diagnostic(CodePathTypeUnsafe, evidence.Role, evidence.Path, evidence.Path,
			fmt.Sprintf("expected %s", requirements.expected)))
	}
	if requirements.confidential && evidence.Mode&0o077 != 0 {
		diagnostics = append(diagnostics, diagnostic(CodePathPermissionsUnsafe, evidence.Role, evidence.Path, evidence.Path,
			"confidential file grants group or other permissions"))
	}
	if requirements.confidential && evidence.Type == PathTypeRegular && evidence.NLink != 1 {
		diagnostics = append(diagnostics, diagnostic(CodePathHardlinkUnsafe, evidence.Role, evidence.Path, evidence.Path,
			"confidential file must have exactly one link"))
	}
	if requirements.requireRead && !evidence.Access.Readable {
		diagnostics = append(diagnostics, diagnostic(CodePathNotReadable, evidence.Role, evidence.Path, evidence.Path,
			"service identity cannot read the path"))
	}
	if requirements.requireWrite && !evidence.Access.Writable {
		diagnostics = append(diagnostics, diagnostic(CodePathReadOnly, evidence.Role, evidence.Path, evidence.Path,
			"service identity cannot write the path"))
	}
	if requirements.requireSearch && !evidence.Access.Searchable {
		diagnostics = append(diagnostics, diagnostic(CodePathNotSearchable, evidence.Role, evidence.Path, evidence.Path,
			"service identity cannot search the path"))
	}
	return diagnostics
}

func auditReplacementParent(evidence PathEvidence, _ Policy) []Diagnostic {
	if len(evidence.Components) < 2 {
		return []Diagnostic{diagnostic(CodePathReadOnly, evidence.Role, evidence.Path, "/", "replacement parent is not writable")}
	}
	parent := evidence.Components[len(evidence.Components)-2]
	var diagnostics []Diagnostic
	if !parent.Access.Writable {
		diagnostics = append(diagnostics, diagnostic(CodePathReadOnly, evidence.Role, evidence.Path, parent.Path,
			"parent directory is not writable for atomic replacement"))
	}
	if !parent.Access.Searchable {
		diagnostics = append(diagnostics, diagnostic(CodePathNotSearchable, evidence.Role, evidence.Path, parent.Path,
			"parent directory is not searchable for atomic replacement"))
	}
	return diagnostics
}

func componentFromStat(path string, stat syscall.Stat_t, policy Policy) ComponentEvidence {
	return ComponentEvidence{
		Path:   path,
		Type:   statPathType(stat.Mode),
		Device: stat.Dev,
		Inode:  stat.Ino,
		Mode:   stat.Mode,
		UID:    stat.Uid,
		GID:    stat.Gid,
		NLink:  stat.Nlink,
		Access: serviceAccess(stat, policy),
	}
}

func pathFromFinalStat(evidence PathEvidence, stat syscall.Stat_t, policy Policy) PathEvidence {
	evidence.Exists = true
	evidence.Type = statPathType(stat.Mode)
	evidence.Device = stat.Dev
	evidence.Inode = stat.Ino
	evidence.Mode = stat.Mode
	evidence.UID = stat.Uid
	evidence.GID = stat.Gid
	evidence.NLink = stat.Nlink
	evidence.Size = stat.Size
	evidence.ModifiedAt = time.Unix(stat.Mtim.Sec, stat.Mtim.Nsec).UTC()
	evidence.ChangedAt = time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec).UTC()
	evidence.Access = serviceAccess(stat, policy)
	return evidence
}

func serviceAccess(stat syscall.Stat_t, policy Policy) AccessEvidence {
	permissions := stat.Mode & 0o777
	bits := uint32(permissions & 0o007)
	if stat.Uid == policy.EffectiveUID {
		bits = uint32((permissions >> 6) & 0o7)
	} else if slices.Contains(policy.EffectiveGIDs, stat.Gid) {
		bits = uint32((permissions >> 3) & 0o7)
	}
	return AccessEvidence{
		Readable:   bits&0o4 != 0,
		Writable:   bits&0o2 != 0,
		Searchable: stat.Mode&syscall.S_IFMT == syscall.S_IFDIR && bits&0o1 != 0,
	}
}

func statPathType(mode uint32) PathType {
	switch mode & syscall.S_IFMT {
	case syscall.S_IFDIR:
		return PathTypeDirectory
	case syscall.S_IFREG:
		return PathTypeRegular
	case syscall.S_IFLNK:
		return PathTypeSymlink
	default:
		return PathTypeOther
	}
}

func fstat(fd int) (syscall.Stat_t, error) {
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return syscall.Stat_t{}, err
	}
	return stat, nil
}

func filesystemRootUID() (uint32, error) {
	fd, err := unix.Open("/", linuxOPath|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	stat, err := fstat(fd)
	if err != nil {
		return 0, err
	}
	return stat.Uid, nil
}

func sameStableStat(left, right syscall.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode &&
		left.Uid == right.Uid && left.Gid == right.Gid && left.Nlink == right.Nlink &&
		left.Size == right.Size && left.Mtim == right.Mtim && left.Ctim == right.Ctim
}

func diagnostic(code ErrorCode, role PathRole, path, component, detail string) Diagnostic {
	return Diagnostic{Code: code, Severity: SeverityBlocking, Role: role, Path: path, Component: component, Detail: detail}
}

func notice(code ErrorCode, role PathRole, path, component, detail string) Diagnostic {
	return Diagnostic{Code: code, Severity: SeverityNotice, Role: role, Path: path, Component: component, Detail: detail}
}

func hasBlockingDiagnostics(diagnostics []Diagnostic) bool {
	return slices.ContainsFunc(diagnostics, func(value Diagnostic) bool { return value.Severity == SeverityBlocking })
}
