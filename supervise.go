package wrapped

// Running the sandbox and taking it down again.
//
// wrapped must leave nothing behind: not the sandboxed program, not whatever it
// started, not either of the two bwrap processes, and not pasta. bwrap's own
// --die-with-parent is not used for this, since it is unreliable.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// cgroupRoot is where the cgroup v2 hierarchy is mounted. Paths read out of
// /proc/<pid>/cgroup are relative to the reading process's cgroup namespace, and so
// is this mount, so the two compose.
const cgroupRoot = "/sys/fs/cgroup"

// scopeCgroupTimeout bounds the wait for systemd to move the sandbox into the
// transient scope. Missing it costs the cgroup lever, not the run.
const scopeCgroupTimeout = 10 * time.Second

// runSandbox runs the sandbox chain — bwrap, or pasta with bwrap under it, either
// of them behind systemd-run when a cgroup is to be had — as a child process, and
// does not return until everything that chain started is gone.
//
// Termination has two levers, and both are pulled:
//
//   - cgroup.kill on the transient scope, which the kernel applies to every process
//     in the cgroup at once, whatever its parent, process group or session. This is
//     what holds when a program daemonises, or when one of the processes in the
//     chain is killed outright and the ones below it are orphaned.
//   - SIGKILL to the sandbox's process group, which is all there is without a
//     cgroup, and which a program escapes by calling setsid.
//
// Neither lever helps when wrapped is itself killed with SIGKILL, so a reaper
// process holding the far end of a pipe from wrapped pulls them on wrapped's behalf
// as soon as the pipe reports end-of-file — that is, as soon as wrapped is gone, for
// whatever reason.
//
// env is the environment the whole chain runs with, from sandboxChainEnv, and not
// wrapped's own unless the run is one that passes the environment through.
func runSandbox(path string, args, env []string, cgroup Cgroup) error {
	unit := ""
	if cgroup.Mode != CgroupDisabled {
		unit = scopeUnitName()
	}
	cgroupPrefix, env, err := resolveCgroupPrefix(cgroup, env, unit)
	if err != nil {
		return err
	}
	if len(cgroupPrefix) == 0 {
		// No cgroup, whether because none was asked for or because none could be had.
		// The name goes with it: waiting for a scope that will never exist would only
		// delay the run by the length of the wait.
		unit = ""
	}

	cmdPath, cmdArgs := path, args
	if len(cgroupPrefix) > 0 {
		cmdPath = cgroupPrefix[0]
		cmdArgs = append(append(append([]string{}, cgroupPrefix[1:]...), path), args...)
	}

	// A process group of its own is what makes it possible to signal the sandbox as a
	// whole without signalling whoever ran wrapped along with it. Setpgid makes the
	// child the leader of that group, so the group's id is the child's process id.
	pid, err := syscall.ForkExec(cmdPath, append([]string{cmdPath}, cmdArgs...), &syscall.ProcAttr{
		Env:   env,
		Files: []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd()},
		Sys:   &syscall.SysProcAttr{Setpgid: true},
	})
	if err != nil {
		return fmt.Errorf("failed to start %s: %w", filepath.Base(cmdPath), err)
	}

	// The leader's start time tells it apart from a later process that the kernel
	// happens to give the same process id to.
	startTime, err := processStartTime(pid)
	if err != nil {
		startTime = unknownStartTime
	}

	// Lending the terminal to the sandbox below leaves wrapped in the background,
	// where the terminal ioctls it still has to make would otherwise stop it with
	// SIGTTOU. This has to come after the fork rather than before it: an ignored
	// signal stays ignored across exec, and the sandbox is not to inherit this one.
	signal.Ignore(syscall.SIGTTIN, syscall.SIGTTOU)
	defer signal.Reset(syscall.SIGTTIN, syscall.SIGTTOU)

	// The cgroup is not known until systemd-run has had the scope created, which it
	// does after forking and before exec'ing the sandbox, so it can only be looked up
	// once the child is running. What is registered below sees the final value, since
	// the deferred call closes over the variable.
	var cgroupDir string

	terminal := newTerminalHandover(pid)
	defer terminal.release()
	terminal.take()

	reaper := startReaper(pid, startTime)
	defer reaper.stop()

	defer func() { terminateSandbox(cgroupDir, pid, startTime) }()

	if unit != "" {
		cgroupDir = waitForScopeCgroup(pid, unit)
		reaper.watch(cgroupDir)
	}

	// Signals aimed at wrapped are meant for the program it is running. Terminal
	// signals do not come this way: the sandbox is the foreground process group and
	// the terminal delivers them to it directly.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTSTP)
	var forwarding sync.WaitGroup
	forwarding.Add(1)
	go func() {
		defer forwarding.Done()
		for sig := range sigCh {
			if s, ok := sig.(syscall.Signal); ok {
				_ = syscall.Kill(-pid, s)
			}
		}
	}()
	defer func() {
		// Stop first, close second: signal.Stop guarantees no further sends on the
		// channel once it has returned, so closing it is safe, and closing is what
		// ends the loop above. Wrapped is a library call that returns now rather than
		// replacing the process, so leaving the goroutine parked would cost a caller
		// running one sandbox after another a goroutine and a channel per run.
		//
		// This is the first thing undone on the way out, so that no forwarded signal
		// can still be on its way to a process group that terminateSandbox is about
		// to finish with.
		signal.Stop(sigCh)
		close(sigCh)
		forwarding.Wait()
	}()

	status, err := waitForSandbox(pid, terminal)
	if err != nil {
		return fmt.Errorf("failed to wait for %s: %w", filepath.Base(cmdPath), err)
	}
	if code := waitStatusExitCode(status); code != 0 {
		return &ExitError{Code: code}
	}
	return nil
}

// waitForSandbox waits for the sandbox to finish, relaying job control on the way.
// When the terminal stops the sandbox — Ctrl-Z — wrapped hands the terminal back and
// stops as well, so that the shell sees one suspended job rather than a prompt it
// cannot type at, and picks up where it left off when the job is resumed.
func waitForSandbox(pid int, terminal *terminalHandover) (syscall.WaitStatus, error) {
	for {
		var status syscall.WaitStatus
		_, err := syscall.Wait4(pid, &status, syscall.WUNTRACED|syscall.WCONTINUED, nil)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return 0, err
		}

		switch {
		case status.Stopped():
			terminal.release()
			// Stopping wrapped itself is what tells the shell that the job is
			// suspended. The call returns once the shell has continued wrapped.
			_ = syscall.Kill(os.Getpid(), syscall.SIGSTOP)
			terminal.take()
			_ = syscall.Kill(-pid, syscall.SIGCONT)
		case status.Continued():
			// The sandbox was continued without wrapped being asked; nothing to do.
		default:
			return status, nil
		}
	}
}

// waitStatusExitCode turns the sandbox's wait status into the exit code wrapped
// should exit with. A process killed by a signal has no exit code of its own, so the
// shell convention of 128 plus the signal number is used, which is what makes an
// out-of-memory kill of the sandboxed program tell itself apart from an ordinary
// failure.
func waitStatusExitCode(status syscall.WaitStatus) int {
	if status.Signaled() {
		return 128 + int(status.Signal())
	}
	return status.ExitStatus()
}

// terminateSandbox kills whatever is left of the sandbox. Both levers are pulled: the
// cgroup catches processes that have left the process group behind, and the process
// group is all there is when there is no cgroup.
func terminateSandbox(cgroupDir string, pgid, startTime int) {
	if cgroupDir != "" {
		killCgroup(cgroupDir)
	}
	killProcessGroup(pgid, startTime)
}

// unknownStartTime marks a process start time that could not be read, in which case
// the check it exists for is skipped rather than guessed at.
const unknownStartTime = 0

// killProcessGroup SIGKILLs the sandbox's process group and the process that leads
// it, unless that process has exited and its process id has since been handed to an
// unrelated one — which shows up as a start time other than the one recorded when the
// sandbox started.
//
// A process id that is still in use as a process group id is not reused while the
// group has members, so a leader with no entry under /proc at all cannot have been
// replaced, and whatever is still in its group is the sandbox's.
//
// The leader is signalled by process id as well as through the group, since a process
// that has called setsid has left the group but is still the one wrapped started.
func killProcessGroup(pgid, startTime int) {
	if pgid <= 1 {
		return
	}
	if startTime != unknownStartTime {
		if current, err := processStartTime(pgid); err == nil && current != startTime {
			return
		}
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	_ = syscall.Kill(pgid, syscall.SIGKILL)
}

// processStartTime returns the time a process started, in clock ticks since boot, as
// recorded in field 22 of /proc/<pid>/stat. Together with the process id it names a
// particular process for as long as the system is up, which the process id alone
// does not.
func processStartTime(pid int) (int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	// The second field is the executable name in parentheses, and may contain both
	// spaces and parentheses of its own, so the fields are counted from the last
	// closing parenthesis rather than from the start of the line.
	nameEnd := bytes.LastIndexByte(data, ')')
	if nameEnd < 0 {
		return 0, fmt.Errorf("cannot parse /proc/%d/stat", pid)
	}
	fields := strings.Fields(string(data[nameEnd+1:]))
	// Field 3, the state, is the first one there, so field 22 is 19 further along.
	const startTimeIndex = 22 - 3
	if len(fields) <= startTimeIndex {
		return 0, fmt.Errorf("cannot parse /proc/%d/stat", pid)
	}
	return strconv.Atoi(fields[startTimeIndex])
}

// scopeUnitName names the transient scope. wrapped has to know the name up front in
// order to recognise the scope's cgroup in /proc once systemd has moved the sandbox
// into it, and systemd rejects a name that is already taken, so it also has to be
// one no concurrent run can arrive at.
func scopeUnitName() string {
	return fmt.Sprintf("wrapped-%d-%d.scope", os.Getpid(), time.Now().UnixNano())
}

// waitForScopeCgroup returns the directory of the transient scope's cgroup, once
// systemd-run has had the scope created and moved itself into it, which happens
// before it execs the sandbox. An empty string means the cgroup could not be found,
// leaving the process group as the only lever; a run must not fail over that.
func waitForScopeCgroup(pid int, unit string) string {
	// systemd-run starts out in wrapped's own cgroup and stays there until the scope
	// has been created, so that is what the wait is waiting to see change.
	own, ownErr := processCgroup(os.Getpid())

	deadline := time.Now().Add(scopeCgroupTimeout)
	for {
		path, err := processCgroup(pid)
		if err != nil {
			// The sandbox is already gone, so there is nothing left to kill.
			return ""
		}
		if strings.HasSuffix(path, "/"+unit) {
			dir := filepath.Join(cgroupRoot, path)
			if _, err := os.Stat(dir); err != nil {
				return ""
			}
			return dir
		}
		if ownErr == nil && path != own {
			// The sandbox has been moved somewhere that is not the scope under the
			// name wrapped gave it, which a cgroup namespace between wrapped and
			// systemd will do. Waiting for a name that cannot appear only delays the
			// run, so give up on the cgroup rather than on the sandbox.
			return ""
		}
		if time.Now().After(deadline) {
			return ""
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// processCgroup returns a process's cgroup v2 path as recorded in /proc/<pid>/cgroup,
// which is relative to the root of the reading process's cgroup namespace.
func processCgroup(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		// The unified hierarchy is the entry with an empty controller list.
		if path, ok := strings.CutPrefix(strings.TrimSpace(line), "0::"); ok {
			return path, nil
		}
	}
	return "", fmt.Errorf("no cgroup v2 entry in /proc/%d/cgroup", pid)
}

// killCgroup kills every process in a cgroup and in the cgroups below it.
func killCgroup(dir string) {
	if _, err := os.Stat(dir); err != nil {
		// systemd removes the scope as soon as it falls empty, so a cgroup that is
		// no longer there held nothing to kill.
		return
	}
	// cgroup.kill, from Linux 5.14 on, kills the whole subtree in a single write,
	// and nothing in it can fork its way out in the meantime. The file is opened
	// rather than written through os.WriteFile, which would ask to create and
	// truncate it, neither of which a kernel pseudo-file takes kindly to.
	if file, err := os.OpenFile(filepath.Join(dir, "cgroup.kill"), os.O_WRONLY, 0); err == nil {
		_, err = file.WriteString("1")
		_ = file.Close()
		if err == nil {
			return
		}
	}
	// Older kernels have no such file, and a cgroup that is not delegated to this
	// user cannot be written to at all, so the members have to be signalled one by
	// one — and more than once, since a process not yet killed can still fork.
	for range 10 {
		if killCgroupProcs(dir) == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// cgroupProcs returns the ids of the processes in the cgroup subtree rooted at dir.
func cgroupProcs(dir string) []int {
	var pids []int
	_ = filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || !entry.IsDir() {
			return nil
		}
		procs, err := os.ReadFile(filepath.Join(path, "cgroup.procs"))
		if err != nil {
			return nil
		}
		for _, field := range strings.Fields(string(procs)) {
			pid, err := strconv.Atoi(field)
			// Anything that is not a genuine process id is dropped here rather than
			// passed on. kill(2) reads zero as the caller's own process group, a
			// negative number as another process group, and -1 as every process the
			// caller can signal at all, so a stray entry must never reach it.
			if err != nil || pid <= 0 {
				continue
			}
			pids = append(pids, pid)
		}
		return nil
	})
	return pids
}

// killCgroupProcs SIGKILLs every process in the cgroup subtree rooted at dir and
// reports how many it reached.
func killCgroupProcs(dir string) int {
	killed := 0
	for _, pid := range cgroupProcs(dir) {
		if syscall.Kill(pid, syscall.SIGKILL) == nil {
			killed++
		}
	}
	return killed
}

// reapArg marks an invocation of wrapped as the reaper described in runSandbox.
const reapArg = "__reap"

// reapPipeFd is the descriptor the reaper reads, the first one after the standard
// three. exec.Cmd puts the single ExtraFiles entry exactly there.
const reapPipeFd = 3

// reaper is the process that terminates the sandbox when wrapped cannot: it holds
// the read end of a pipe whose only write end wrapped keeps to itself, and acts when
// that pipe reports end-of-file. A nil reaper is one that could not be started, and
// every method tolerates it — a failure here must not fail the run, it only falls
// back to wrapped doing its own cleanup.
type reaper struct {
	cmd  *exec.Cmd
	pipe *os.File
}

// startReaper spawns the reaper. It must be called after the sandbox has been
// started, so that the pipe cannot be inherited by anything in the sandbox: a
// descriptor held down there would keep the pipe open and the reaper asleep.
func startReaper(pgid, startTime int) *reaper {
	self, err := os.Executable()
	if err != nil {
		return nil
	}
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		return nil
	}
	cmd := exec.Command(self, reapArg, strconv.Itoa(pgid), strconv.Itoa(startTime))
	// The reaper reads a pipe, reads /proc and signals what it finds there; it looks
	// nothing up in the environment, so it is given none. It outlives wrapped by
	// design, and an environment it has no use for is one more copy of the operator's
	// secrets sitting in /proc for as long as the sandbox runs.
	cmd.Env = []string{}
	cmd.ExtraFiles = []*os.File{readEnd}
	cmd.Stderr = os.Stderr
	// A session of its own puts the reaper out of reach of the signals that take
	// wrapped's own process group down, which is precisely when it is needed.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		_ = readEnd.Close()
		_ = writeEnd.Close()
		return nil
	}
	// The reaper now holds the only read end; wrapped holds the only write end.
	_ = readEnd.Close()
	return &reaper{cmd: cmd, pipe: writeEnd}
}

// watch tells the reaper which cgroup the sandbox ended up in. Until it is told, the
// reaper has only the process group to go on.
func (r *reaper) watch(cgroupDir string) {
	if r == nil || cgroupDir == "" {
		return
	}
	_, _ = io.WriteString(r.pipe, cgroupDir+"\n")
}

// stop closes the pipe, which is the reaper's cue to do its work and exit, and waits
// for it so that it does not outlive wrapped as a zombie.
func (r *reaper) stop() {
	if r == nil {
		return
	}
	_ = r.pipe.Close()
	_ = r.cmd.Wait()
}

// runReap is the reaper. It waits for wrapped to close the pipe — which happens when
// wrapped exits, however it exits, SIGKILL included — and then terminates whatever is
// left of the sandbox.
func runReap(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("%s: expected a process group id and a start time", reapArg)
	}
	pgid, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("%s: invalid process group id %q: %w", reapArg, args[0], err)
	}
	startTime, err := strconv.Atoi(args[1])
	if err != nil {
		return fmt.Errorf("%s: invalid start time %q: %w", reapArg, args[1], err)
	}

	// Termination signals are for wrapped and for the sandbox. The reaper has to
	// outlive both of them to clean up after them, so it takes none of them.
	signal.Ignore(syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)

	pipe := os.NewFile(reapPipeFd, "reaper pipe")
	if pipe == nil {
		return fmt.Errorf("%s: no pipe on descriptor %d", reapArg, reapPipeFd)
	}
	// wrapped sends the sandbox's cgroup once it knows it, then holds the pipe open
	// for the rest of the run. Reading to end-of-file therefore blocks until wrapped
	// is gone and yields whatever it had time to say, if anything.
	cgroupDir, err := io.ReadAll(pipe)
	if err != nil {
		return fmt.Errorf("%s: cannot read from descriptor %d: %w", reapArg, reapPipeFd, err)
	}

	terminateSandbox(strings.TrimSpace(string(cgroupDir)), pgid, startTime)
	return nil
}

// terminalHandover lends wrapped's terminal to the sandbox's process group, so that
// the sandboxed program can read from the terminal and is sent Ctrl-C directly, and
// takes it back when the sandbox is suspended or done. A nil handover is one that
// never applied, and every method tolerates it.
type terminalHandover struct {
	fd       uintptr
	previous int
	pgid     int
	held     bool
}

// newTerminalHandover prepares to lend the terminal, and returns nil unless wrapped is
// in the foreground itself: a wrapped running as a background job must not take the
// terminal away from whoever does have it.
func newTerminalHandover(pgid int) *terminalHandover {
	fd, ok := terminalFd()
	if !ok {
		return nil
	}
	previous, err := tcgetpgrp(fd)
	if err != nil || previous != syscall.Getpgrp() {
		return nil
	}
	return &terminalHandover{fd: fd, previous: previous, pgid: pgid}
}

// take makes the sandbox the foreground process group. After a suspension wrapped has
// the terminal to lend only if the shell put the job back in the foreground, so this
// checks rather than assumes.
func (h *terminalHandover) take() {
	if h == nil || h.held {
		return
	}
	if current, err := tcgetpgrp(h.fd); err != nil || current != syscall.Getpgrp() {
		return
	}
	if err := tcsetpgrp(h.fd, h.pgid); err == nil {
		h.held = true
	}
}

// release puts the foreground process group back the way it was.
func (h *terminalHandover) release() {
	if h == nil || !h.held {
		return
	}
	if err := tcsetpgrp(h.fd, h.previous); err == nil {
		h.held = false
	}
}

// terminalFd returns the first of the standard descriptors that is a terminal. When
// none of them is, wrapped has no terminal to hand over, whether or not it still has
// a controlling one behind the redirections.
func terminalFd() (uintptr, bool) {
	for _, file := range []*os.File{os.Stdin, os.Stdout, os.Stderr} {
		fd := file.Fd()
		// The ioctl fails with ENOTTY on anything that is not a terminal, so it
		// doubles as the test for one.
		if _, err := tcgetpgrp(fd); err == nil {
			return fd, true
		}
	}
	return 0, false
}

// tcgetpgrp returns the foreground process group of the terminal on fd.
func tcgetpgrp(fd uintptr) (int, error) {
	var pgrp int32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCGPGRP,
		uintptr(unsafe.Pointer(&pgrp))); errno != 0 {
		return 0, errno
	}
	return int(pgrp), nil
}

// tcsetpgrp makes pgrp the foreground process group of the terminal on fd.
func tcsetpgrp(fd uintptr, pgrp int) error {
	value := int32(pgrp)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCSPGRP,
		uintptr(unsafe.Pointer(&value))); errno != 0 {
		return errno
	}
	return nil
}
