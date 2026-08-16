//go:build linux

package broker

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	maximumChildrenFileBytes  = 128 << 10
	maximumProcessEnvironment = 4 << 20
)

type processReference struct {
	pid       int
	startTime uint64
}

type processStatus struct {
	reference processReference
	state     byte
	parentPID int
	groupID   int
	sessionID int
}

// processController follows descendants through procfs in addition to using a
// dedicated process group. Tracking covers a child that changes its process
// group or session before termination. Procfs evidence is identity-bound by
// kernel start time so a recycled PID is never signaled as the old child.
type processController struct {
	grace time.Duration
	guard []byte
	self  processReference

	mu             sync.Mutex
	rootPID        int
	tracked        map[int]processReference
	guardedOrphans map[int]processReference
	uncertain      bool
	requested      bool
	termination    Termination
	trackerStop    chan struct{}
	trackerDone    chan struct{}
	trackerStarted bool

	sequenceMu sync.Mutex
}

func newProcessController(grace time.Duration, guard string) (*processController, error) {
	self, err := readProcessStatus(os.Getpid())
	if err != nil {
		return nil, fmt.Errorf("read broker process identity: %w", err)
	}
	return &processController{
		grace: grace, guard: []byte(guard), self: self.reference,
		tracked: make(map[int]processReference), guardedOrphans: make(map[int]processReference), termination: TerminationNone,
		trackerStop: make(chan struct{}), trackerDone: make(chan struct{}),
	}, nil
}

func (controller *processController) start(pid int) {
	if controller == nil || pid <= 0 {
		return
	}
	controller.mu.Lock()
	if controller.rootPID == 0 {
		controller.rootPID = pid
	}
	if status, err := readProcessStatus(pid); err == nil {
		controller.tracked[pid] = status.reference
	} else if !processGoneError(err) {
		controller.uncertain = true
	}
	if controller.trackerStarted {
		controller.mu.Unlock()
		return
	}
	controller.trackerStarted = true
	controller.mu.Unlock()

	controller.scan()
	go controller.track()
}

func (controller *processController) track() {
	defer close(controller.trackerDone)
	ticker := time.NewTicker(processScanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-controller.trackerStop:
			return
		case <-ticker.C:
			controller.scan()
		}
	}
}

func (controller *processController) cancel(pid int) error {
	if controller == nil {
		return os.ErrProcessDone
	}
	controller.start(pid)
	controller.mu.Lock()
	controller.requested = true
	controller.mu.Unlock()

	controller.sequenceMu.Lock()
	defer controller.sequenceMu.Unlock()
	alive, _ := controller.liveTargets()
	if !alive {
		return os.ErrProcessDone
	}
	controller.terminateSequence(false)
	return nil
}

// finish always cleans the process group after Wait, including a descendant
// left behind by a leader that reported success. Such a survivor makes the
// operation ambiguous even when cleanup ultimately succeeds.
func (controller *processController) finish() bool {
	if controller == nil {
		return true
	}
	controller.sequenceMu.Lock()
	controller.scan()
	alive, _ := controller.liveTargets()
	controller.mu.Lock()
	requested := controller.requested
	if alive && !requested {
		controller.uncertain = true
	}
	controller.mu.Unlock()
	if alive {
		controller.terminateSequence(true)
	}
	controller.sequenceMu.Unlock()

	controller.stopTracker()
	controller.scan()
	controller.reapGuardedOrphans()
	controller.scan()
	alive, scanUncertain := controller.liveTargets()
	controller.mu.Lock()
	if alive || scanUncertain {
		controller.uncertain = true
	}
	uncertain := controller.uncertain
	controller.mu.Unlock()
	return uncertain
}

func (controller *processController) stopTracker() {
	controller.mu.Lock()
	started := controller.trackerStarted
	controller.mu.Unlock()
	if !started {
		return
	}
	select {
	case <-controller.trackerStop:
	default:
		close(controller.trackerStop)
	}
	<-controller.trackerDone
}

func (controller *processController) terminateSequence(afterWait bool) {
	controller.scan()
	alive, _ := controller.liveTargets()
	if !alive {
		return
	}
	if controller.signalTargets(syscall.SIGTERM) {
		controller.setTermination(TerminationGraceful)
	}
	if controller.waitForExit(controller.grace) {
		return
	}
	if controller.signalTargets(syscall.SIGKILL) {
		controller.setTermination(TerminationForced)
	}
	if !controller.waitForExit(forcedCleanupWait) {
		controller.mu.Lock()
		controller.uncertain = true
		controller.mu.Unlock()
	}
	_ = afterWait
}

func (controller *processController) waitForExit(limit time.Duration) bool {
	deadline := time.Now().Add(limit)
	for {
		controller.scan()
		alive, uncertain := controller.liveTargets()
		if !alive {
			if uncertain {
				controller.mu.Lock()
				controller.uncertain = true
				controller.mu.Unlock()
			}
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(min(processScanInterval, time.Until(deadline)))
	}
}

func (controller *processController) signalTargets(signal syscall.Signal) bool {
	controller.scan()
	controller.mu.Lock()
	rootPID := controller.rootPID
	references := make([]processReference, 0, len(controller.tracked))
	for _, reference := range controller.tracked {
		references = append(references, reference)
	}
	controller.mu.Unlock()
	sort.Slice(references, func(left, right int) bool { return references[left].pid > references[right].pid })

	signaled := false
	groupIdentityBound := false
	for _, reference := range references {
		status, err := readProcessStatus(reference.pid)
		if err != nil || status.reference.startTime != reference.startTime || terminalProcessState(status.state) {
			continue
		}
		if status.groupID == rootPID {
			groupIdentityBound = true
			break
		}
	}
	if rootPID > 0 && groupIdentityBound {
		if err := syscall.Kill(-rootPID, signal); err == nil {
			signaled = true
		} else if !errors.Is(err, syscall.ESRCH) {
			controller.markUncertain()
		}
	}
	for _, reference := range references {
		status, err := readProcessStatus(reference.pid)
		if err != nil {
			if !processGoneError(err) {
				controller.markUncertain()
			}
			continue
		}
		if status.reference.startTime != reference.startTime || terminalProcessState(status.state) {
			continue
		}
		if err := syscall.Kill(reference.pid, signal); err == nil {
			signaled = true
		} else if !errors.Is(err, syscall.ESRCH) {
			controller.markUncertain()
		}
	}
	return signaled
}

func (controller *processController) liveTargets() (bool, bool) {
	controller.mu.Lock()
	references := make([]processReference, 0, len(controller.tracked))
	for _, reference := range controller.tracked {
		references = append(references, reference)
	}
	uncertain := controller.uncertain
	controller.mu.Unlock()

	for _, reference := range references {
		status, err := readProcessStatus(reference.pid)
		if err != nil {
			if !processGoneError(err) {
				uncertain = true
			}
			continue
		}
		if status.reference.startTime == reference.startTime && !terminalProcessState(status.state) {
			return true, uncertain
		}
	}
	return false, uncertain
}

func (controller *processController) scan() {
	if controller == nil {
		return
	}
	controller.discoverGuardedOrphans()
	controller.mu.Lock()
	rootPID := controller.rootPID
	queue := make([]processReference, 0, len(controller.tracked)+1)
	if rootPID > 0 {
		if reference, ok := controller.tracked[rootPID]; ok {
			queue = append(queue, reference)
		} else {
			queue = append(queue, processReference{pid: rootPID})
		}
	}
	for pid, reference := range controller.tracked {
		if pid != rootPID {
			queue = append(queue, reference)
		}
	}
	controller.mu.Unlock()

	visited := make(map[int]struct{}, len(queue))
	for position := 0; position < len(queue); position++ {
		reference := queue[position]
		if _, duplicate := visited[reference.pid]; duplicate {
			continue
		}
		visited[reference.pid] = struct{}{}
		status, err := readProcessStatus(reference.pid)
		if err != nil {
			if !processGoneError(err) {
				controller.markUncertain()
			}
			continue
		}
		if reference.startTime != 0 && reference.startTime != status.reference.startTime {
			continue
		}
		controller.mu.Lock()
		if len(controller.tracked) >= maximumTrackedProcesses {
			controller.uncertain = true
			controller.mu.Unlock()
			return
		}
		controller.tracked[status.reference.pid] = status.reference
		controller.mu.Unlock()
		if terminalProcessState(status.state) {
			continue
		}

		children, err := readAllProcessChildren(status.reference)
		if err != nil {
			if !processGoneError(err) {
				controller.markUncertain()
			}
			continue
		}
		for _, childPID := range children {
			child, err := readProcessStatus(childPID)
			if err != nil {
				if !processGoneError(err) {
					controller.markUncertain()
				}
				continue
			}
			if child.parentPID != status.reference.pid {
				continue
			}
			controller.mu.Lock()
			if existing, ok := controller.tracked[childPID]; ok && existing.startTime != child.reference.startTime {
				controller.uncertain = true
			}
			controller.tracked[childPID] = child.reference
			controller.mu.Unlock()
			queue = append(queue, child.reference)
		}
	}
}

// discoverGuardedOrphans closes the race in which a descendant creates a new
// session and its leader exits before the first lineage scan. As a Linux child
// subreaper, AcmeMux becomes that orphan's direct parent. Only an exact,
// operation-random marker (or an identity already proven through lineage) is
// adopted, so concurrent os/exec children remain owned by their callers.
func (controller *processController) discoverGuardedOrphans() {
	children, err := readAllProcessChildren(controller.self)
	if err != nil {
		controller.markUncertain()
		return
	}
	for _, pid := range children {
		controller.mu.Lock()
		rootPID := controller.rootPID
		existing, alreadyTracked := controller.tracked[pid]
		controller.mu.Unlock()
		if pid == rootPID {
			continue
		}

		status, err := readProcessStatus(pid)
		if err != nil {
			if alreadyTracked && !processGoneError(err) {
				controller.markUncertain()
			}
			continue
		}
		if status.parentPID != controller.self.pid {
			continue
		}
		if alreadyTracked {
			if existing.startTime != status.reference.startTime {
				controller.markUncertain()
				continue
			}
			controller.mu.Lock()
			controller.guardedOrphans[pid] = status.reference
			controller.mu.Unlock()
			continue
		}

		matches, err := processEnvironmentContains(pid, controller.guard)
		if err != nil || !matches {
			// An unrelated direct child can have an unreadable or concurrently
			// changing environment. It is intentionally outside this operation.
			continue
		}
		controller.mu.Lock()
		if len(controller.tracked) >= maximumTrackedProcesses {
			controller.uncertain = true
			controller.mu.Unlock()
			return
		}
		controller.tracked[pid] = status.reference
		controller.guardedOrphans[pid] = status.reference
		controller.mu.Unlock()
	}
}

// reapGuardedOrphans waits only for exact direct children whose operation
// ownership has already been proven. It never performs a process-wide wait
// and therefore cannot consume the status of an unrelated os/exec child.
func (controller *processController) reapGuardedOrphans() {
	controller.mu.Lock()
	references := make([]processReference, 0, len(controller.guardedOrphans))
	for _, reference := range controller.guardedOrphans {
		references = append(references, reference)
	}
	controller.mu.Unlock()

	for _, reference := range references {
		status, err := readProcessStatus(reference.pid)
		if err != nil {
			if processGoneError(err) {
				controller.forgetGuardedOrphan(reference)
			} else {
				controller.markUncertain()
			}
			continue
		}
		if status.reference.startTime != reference.startTime {
			controller.forgetGuardedOrphan(reference)
			continue
		}
		if status.parentPID != controller.self.pid || !terminalProcessState(status.state) {
			continue
		}
		var waitStatus syscall.WaitStatus
		reaped, err := syscall.Wait4(reference.pid, &waitStatus, syscall.WNOHANG, nil)
		switch {
		case err == nil && reaped == reference.pid:
			controller.forgetGuardedOrphan(reference)
		case errors.Is(err, syscall.ECHILD):
			if current, readErr := readProcessStatus(reference.pid); processGoneError(readErr) || readErr == nil && current.reference.startTime != reference.startTime {
				controller.forgetGuardedOrphan(reference)
			} else {
				controller.markUncertain()
			}
		case err != nil:
			controller.markUncertain()
		}
	}
}

func (controller *processController) forgetGuardedOrphan(reference processReference) {
	controller.mu.Lock()
	if current, ok := controller.guardedOrphans[reference.pid]; ok && current.startTime == reference.startTime {
		delete(controller.guardedOrphans, reference.pid)
	}
	if current, ok := controller.tracked[reference.pid]; ok && current.startTime == reference.startTime {
		delete(controller.tracked, reference.pid)
	}
	controller.mu.Unlock()
}

func processEnvironmentContains(pid int, expected []byte) (bool, error) {
	file, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "environ"))
	if err != nil {
		return false, err
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, maximumProcessEnvironment+1))
	if err != nil {
		return false, err
	}
	if len(value) > maximumProcessEnvironment {
		return false, errors.New("proc environment exceeds bound")
	}
	for len(value) > 0 {
		end := bytes.IndexByte(value, 0)
		if end < 0 {
			end = len(value)
		}
		if bytes.Equal(value[:end], expected) {
			return true, nil
		}
		if end == len(value) {
			break
		}
		value = value[end+1:]
	}
	return false, nil
}

func (controller *processController) markUncertain() {
	controller.mu.Lock()
	controller.uncertain = true
	controller.mu.Unlock()
}

func (controller *processController) setTermination(value Termination) {
	controller.mu.Lock()
	if value == TerminationForced || controller.termination == TerminationNone {
		controller.termination = value
	}
	controller.mu.Unlock()
}

func (controller *processController) terminationState() Termination {
	if controller == nil {
		return TerminationNone
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return controller.termination
}

func (controller *processController) cancelRequested() bool {
	if controller == nil {
		return false
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return controller.requested
}

func readProcessStatus(pid int) (processStatus, error) {
	value, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return processStatus{}, err
	}
	closing := strings.LastIndexByte(string(value), ')')
	if closing < 2 || closing+2 >= len(value) {
		return processStatus{}, errors.New("malformed proc status")
	}
	fields := strings.Fields(string(value[closing+2:]))
	// fields starts at proc stat field 3 (state); starttime is field 22.
	if len(fields) <= 19 || len(fields[0]) != 1 {
		return processStatus{}, errors.New("malformed proc status")
	}
	parentPID, err := strconv.Atoi(fields[1])
	if err != nil || parentPID < 0 {
		return processStatus{}, errors.New("malformed proc parent")
	}
	groupID, err := strconv.Atoi(fields[2])
	if err != nil || groupID < 0 {
		return processStatus{}, errors.New("malformed proc group")
	}
	sessionID, err := strconv.Atoi(fields[3])
	if err != nil || sessionID < 0 {
		return processStatus{}, errors.New("malformed proc session")
	}
	startTime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || startTime == 0 {
		return processStatus{}, errors.New("malformed proc start time")
	}
	return processStatus{
		reference: processReference{pid: pid, startTime: startTime}, state: fields[0][0],
		parentPID: parentPID, groupID: groupID, sessionID: sessionID,
	}, nil
}

func readAllProcessChildren(reference processReference) ([]int, error) {
	const maximumSnapshotAttempts = 3
	for range maximumSnapshotAttempts {
		before, err := readProcessTaskIDs(reference.pid)
		if err != nil {
			return nil, err
		}
		children := make([]int, 0)
		stable := true
		for _, taskID := range before {
			taskChildren, err := readTaskChildren(reference.pid, taskID)
			if err != nil {
				if processGoneError(err) {
					stable = false
					break
				}
				return nil, err
			}
			if len(children)+len(taskChildren) > maximumTrackedProcesses {
				return nil, errors.New("proc descendants exceed count")
			}
			children = append(children, taskChildren...)
		}
		after, err := readProcessTaskIDs(reference.pid)
		if err != nil {
			return nil, err
		}
		current, err := readProcessStatus(reference.pid)
		if err != nil {
			return nil, err
		}
		if current.reference.startTime != reference.startTime {
			return nil, errors.New("proc process identity changed")
		}
		if stable && slices.Equal(before, after) {
			sort.Ints(children)
			return slices.Compact(children), nil
		}
	}
	return nil, errors.New("proc task snapshot remained unstable")
}

func readProcessTaskIDs(pid int) ([]int, error) {
	directory, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "task"))
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	names, err := directory.Readdirnames(maximumTrackedProcesses + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(names) > maximumTrackedProcesses {
		return nil, errors.New("proc task count exceeds bound")
	}
	tasks := make([]int, 0, len(names))
	for _, name := range names {
		taskID, err := strconv.Atoi(name)
		if err != nil || taskID <= 0 {
			return nil, errors.New("malformed proc task")
		}
		tasks = append(tasks, taskID)
	}
	sort.Ints(tasks)
	tasks = slices.Compact(tasks)
	if len(tasks) == 0 {
		return nil, os.ErrNotExist
	}
	return tasks, nil
}

func readTaskChildren(pid, taskID int) ([]int, error) {
	file, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "task", strconv.Itoa(taskID), "children"))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, maximumChildrenFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(value) > maximumChildrenFileBytes {
		return nil, errors.New("proc children exceeds bound")
	}
	fields := strings.Fields(string(value))
	if len(fields) > maximumTrackedProcesses {
		return nil, errors.New("proc children exceeds count")
	}
	children := make([]int, 0, len(fields))
	for _, field := range fields {
		pid, err := strconv.Atoi(field)
		if err != nil || pid <= 0 {
			return nil, errors.New("malformed proc child")
		}
		children = append(children, pid)
	}
	sort.Ints(children)
	children = slices.Compact(children)
	return children, nil
}

func terminalProcessState(state byte) bool {
	return state == 'Z' || state == 'X' || state == 'x'
}

func processGoneError(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ESRCH)
}
