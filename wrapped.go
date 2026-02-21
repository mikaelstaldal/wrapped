// Package wrapped runs a program in a sandbox using bubblewrap.
package wrapped

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

// ExitError indicates that the sandboxed program exited with a non-zero status.
type ExitError struct {
	Code int
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("exit code %d", e.Code)
}

const systemdResolve = "/run/systemd/resolve"

// Environment variables to pass through to the sandbox.
var envPassthrough = []string{
	"LANG",
	"LC_ADDRESS",
	"LC_NAME",
	"LC_MONETARY",
	"LC_PAPER",
	"LC_IDENTIFICATION",
	"LC_TELEPHONE",
	"LC_MEASUREMENT",
	"LC_TIME",
	"LC_NUMERIC",
	"USER",
}

// Network mode constants for the networkMode parameter.
const (
	NetworkNone     = "none"
	NetworkHost     = "host"
	NetworkBridge   = "bridge"
	NetworkFiltered = "filtered"
)

func Wrapped(program string, arguments []string, networkMode string, mountCurrentDir, mountCurrentDirWritable bool,
	mountReadonly, mountWritable, extraEnv []string, workdir, apparmor string, allowedHosts []string,
	allowAllHosts bool, deniedHosts []string, networkLogFile string, networkSandboxOnly bool) error {
	if networkSandboxOnly {
		if mountCurrentDir || mountCurrentDirWritable {
			return fmt.Errorf("--only-network cannot be combined with --current-dir or --current-dir-writable")
		}
		if len(mountReadonly) > 0 {
			return fmt.Errorf("--only-network cannot be combined with --mount")
		}
		if len(mountWritable) > 0 {
			return fmt.Errorf("--only-network cannot be combined with --mount-writable")
		}
		if workdir != "" {
			return fmt.Errorf("--only-network cannot be combined with --workdir")
		}
		if len(extraEnv) > 0 {
			return fmt.Errorf("--only-network cannot be combined with --env")
		}

		switch networkMode {
		case NetworkNone:
			return fmt.Errorf("--only-network cannot be combined with --network none")

		case NetworkHost:
			return fmt.Errorf("--only-network cannot be combined with --network host")

		case NetworkBridge:
			if networkLogFile != "" {
				return fmt.Errorf("--network-log requires --network filtered")
			}
			return wrappedPastaNetworkOnly(program, arguments, apparmor)

		case NetworkFiltered:
			var filter hostFilter
			if len(allowedHosts) > 0 {
				filter = allowListFilter(allowedHosts)
			} else if allowAllHosts {
				filter = denyListFilter(deniedHosts)
			} else {
				return fmt.Errorf("--network filtered requires filter specification")
			}
			return wrappedFiltered(program, arguments, apparmor, filter, networkLogFile, buildNetworkOnlyBwrapArgs)
		}
	}

	if networkMode == NetworkBridge {
		return wrappedPasta(program, arguments, mountCurrentDir, mountCurrentDirWritable,
			mountReadonly, mountWritable, extraEnv, workdir, apparmor)
	}

	if networkMode == NetworkFiltered {
		if len(allowedHosts) > 0 {
			buildArgs := newFullSandboxBwrapArgsBuilder(mountCurrentDir, mountCurrentDirWritable, mountReadonly, mountWritable, extraEnv, workdir)
			return wrappedFiltered(program, arguments, apparmor, allowListFilter(allowedHosts), networkLogFile, buildArgs)
		}
		if allowAllHosts {
			buildArgs := newFullSandboxBwrapArgsBuilder(mountCurrentDir, mountCurrentDirWritable, mountReadonly, mountWritable, extraEnv, workdir)
			return wrappedFiltered(program, arguments, apparmor, denyListFilter(deniedHosts), networkLogFile, buildArgs)
		}
	}

	if networkLogFile != "" {
		return fmt.Errorf("--network-log requires --network filtered")
	}

	bwrapArgs, err := buildBwrapArgs(program, arguments, networkMode == NetworkHost, mountCurrentDir, mountCurrentDirWritable,
		mountReadonly, mountWritable, extraEnv, workdir, apparmor)
	if err != nil {
		return err
	}

	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		return fmt.Errorf("failed to find bwrap: %w", err)
	}

	argv := append([]string{"bwrap"}, bwrapArgs...)
	// exec replaces the current process; if we reach the return, exec failed.
	return fmt.Errorf("failed to exec bwrap: %w", syscall.Exec(bwrapPath, argv, os.Environ()))
}

// filteredBwrapArgsBuilder builds the bwrap command for filtered network mode.
// It receives the Unix socket paths and returns the bwrap path and args.
// The args must NOT include the program/arguments — those are appended by wrappedFiltered.
type filteredBwrapArgsBuilder func(httpSock, socksSock string) (bwrapPath string, args []string, err error)

// newFullSandboxBwrapArgsBuilder returns a builder that uses the full filesystem sandbox.
func newFullSandboxBwrapArgsBuilder(mountCurrentDir, mountCurrentDirWritable bool,
	mountReadonly, mountWritable, extraEnv []string, workdir string) filteredBwrapArgsBuilder {
	return func(httpSock, socksSock string) (string, []string, error) {
		filterConfig := &filteredNetConfig{
			httpSock:  httpSock,
			socksSock: socksSock,
		}
		bwrapArgs, err := buildFilteredBwrapArgs(mountCurrentDir, mountCurrentDirWritable,
			mountReadonly, mountWritable, extraEnv, workdir, filterConfig)
		if err != nil {
			return "", nil, err
		}

		bwrapPath, err := exec.LookPath("bwrap")
		if err != nil {
			return "", nil, fmt.Errorf("failed to find bwrap: %w", err)
		}

		return bwrapPath, bwrapArgs, nil
	}
}

// buildNetworkOnlyBwrapArgs builds bwrap args for network-only sandboxing (no filesystem sandbox).
func buildNetworkOnlyBwrapArgs(httpSock, socksSock string) (string, []string, error) {
	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		return "", nil, fmt.Errorf("failed to find bwrap: %w", err)
	}

	args := []string{
		"--dev-bind", "/", "/",
		"--unshare-user", "--unshare-net",
		"--setenv", "HTTP_PROXY", "http://localhost:3128",
		"--setenv", "HTTPS_PROXY", "http://localhost:3128",
		"--setenv", "http_proxy", "http://localhost:3128",
		"--setenv", "https_proxy", "http://localhost:3128",
		"--setenv", "ALL_PROXY", "socks5h://localhost:1080",
		"--setenv", "all_proxy", "socks5h://localhost:1080",
		"--setenv", "NO_PROXY", "localhost,127.0.0.1,::1",
		"--setenv", "no_proxy", "localhost,127.0.0.1,::1",
	}

	return bwrapPath, args, nil
}

func wrappedFiltered(program string, arguments []string, apparmor string, filter hostFilter,
	networkLogFile string, buildArgs filteredBwrapArgsBuilder) error {
	// Check socat is available.
	if _, err := exec.LookPath("socat"); err != nil {
		return fmt.Errorf("socat is required for filtered network access: %w", err)
	}

	// Set up a network logger if requested.
	var netLog *networkLogger
	if networkLogFile != "" {
		f, err := os.OpenFile(networkLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("failed to open network log file: %w", err)
		}
		defer f.Close()
		netLog = newNetworkLogger(f)
	}

	// Start proxy servers.
	httpPort, httpClose, err := startHTTPProxy(filter, netLog)
	if err != nil {
		return fmt.Errorf("failed to start HTTP proxy: %w", err)
	}
	defer httpClose()

	socksPort, socksClose, err := startSOCKS5Proxy(filter, netLog)
	if err != nil {
		return fmt.Errorf("failed to start SOCKS5 proxy: %w", err)
	}
	defer socksClose()

	// Create temp Unix socket paths.
	httpSock := fmt.Sprintf("/tmp/wrapped-http-%d.sock", os.Getpid())
	socksSock := fmt.Sprintf("/tmp/wrapped-socks-%d.sock", os.Getpid())
	defer os.Remove(httpSock)
	defer os.Remove(socksSock)

	// Start host-side socat bridges.
	// Use Setpgid so forked socat children are in the same process group and can be killed together.
	httpBridge := exec.Command("socat",
		fmt.Sprintf("UNIX-LISTEN:%s,fork,reuseaddr", httpSock),
		fmt.Sprintf("TCP:127.0.0.1:%d", httpPort))
	httpBridge.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := httpBridge.Start(); err != nil {
		return fmt.Errorf("failed to start HTTP socat bridge: %w", err)
	}
	defer func(pid int) {
		err := syscall.Kill(pid, syscall.SIGTERM)
		if err != nil {
			log.Printf("failed to kill socat: %v", err)
		}
	}(-httpBridge.Process.Pid)

	socksBridge := exec.Command("socat",
		fmt.Sprintf("UNIX-LISTEN:%s,fork,reuseaddr", socksSock),
		fmt.Sprintf("TCP:127.0.0.1:%d", socksPort))
	socksBridge.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := socksBridge.Start(); err != nil {
		return fmt.Errorf("failed to start SOCKS5 socat bridge: %w", err)
	}
	defer func(pid int) {
		err := syscall.Kill(pid, syscall.SIGTERM)
		if err != nil {
			log.Printf("failed to kill socat: %v", err)
		}
	}(-socksBridge.Process.Pid)

	// Build bwrap args.
	bwrapPath, bwrapArgs, err := buildArgs(httpSock, socksSock)
	if err != nil {
		return err
	}

	// Build the shell command that runs inside the sandbox.
	// Run socat bridges in the background, then the program as a foreground child.
	// When the program exits, kill the background socat processes and exit with the program's status.
	shellCmd := fmt.Sprintf(
		"socat TCP-LISTEN:3128,fork,reuseaddr UNIX-CONNECT:%s >/dev/null 2>&1 & "+
			"socat TCP-LISTEN:1080,fork,reuseaddr UNIX-CONNECT:%s >/dev/null 2>&1 & ",
		httpSock, socksSock)
	if apparmor != "" {
		shellCmd += fmt.Sprintf("aa-exec -p %s -- ", apparmor)
	}
	shellCmd += `"$0" "$@"; S=$?; kill 0; exit $S`

	bwrapArgs = append(bwrapArgs, "sh", "-c", shellCmd, program)
	bwrapArgs = append(bwrapArgs, arguments...)

	// Run bwrap as a child process.
	cmd := exec.Command(bwrapPath, bwrapArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start bwrap: %w", err)
	}

	// Forward signals to the child.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range sigCh {
			_ = cmd.Process.Signal(sig)
		}
	}()

	err = cmd.Wait()
	signal.Stop(sigCh)

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return &ExitError{Code: exitErr.ExitCode()}
		}
		return fmt.Errorf("bwrap failed: %w", err)
	}
	return nil
}

type filteredNetConfig struct {
	httpSock  string
	socksSock string
}

func resolveProgram(program string) (string, error) {
	var path string
	if filepath.IsAbs(program) {
		path = program
	} else {
		var err error
		path, err = exec.LookPath(program)
		if err != nil {
			return "", err
		}
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(absPath)
}

// isParentOrEqual reports whether parent is a path prefix of (or equal to) child.
func isParentOrEqual(parent, child string) bool {
	if parent == child {
		return true
	}
	prefix := parent
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return strings.HasPrefix(child, prefix)
}

// hasIPv6Route reports whether the host has a non-loopback interface with a global unicast IPv6 address.
func hasIPv6Route() bool {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if ok && ipNet.IP.To4() == nil && ipNet.IP.IsGlobalUnicast() {
				return true
			}
		}
	}
	return false
}

// runPastaCommand runs pasta in command mode, where pasta creates the user+network
// namespace and runs the given command as its child. This avoids the --info-fd/--userns-block-fd
// coordination protocol that causes ECHILD errors with --unshare-pid.
func runPastaCommand(name string, args []string) error {
	pastaPath, err := exec.LookPath("pasta")
	if err != nil {
		return fmt.Errorf("pasta is required: %w", err)
	}

	pastaArgs := []string{
		"--config-net",
		"-t", "none", "-u", "none", // Disable host-to-namespace port forwarding.
		"-T", "none", "-U", "none", // Disable namespace-to-host splice forwarding.
	}
	if !hasIPv6Route() {
		pastaArgs = append(pastaArgs, "-4")
	}

	pastaArgs = append(pastaArgs, "--")
	pastaArgs = append(pastaArgs, name)
	pastaArgs = append(pastaArgs, args...)

	cmd := exec.Command(pastaPath, pastaArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start pasta: %w", err)
	}

	// Forward signals to the child.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range sigCh {
			_ = cmd.Process.Signal(sig)
		}
	}()

	err = cmd.Wait()
	signal.Stop(sigCh)

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return &ExitError{Code: exitErr.ExitCode()}
		}
		return fmt.Errorf("pasta failed: %w", err)
	}
	return nil
}

func wrappedPasta(program string, arguments []string, mountCurrentDir, mountCurrentDirWritable bool,
	mountReadonly, mountWritable, extraEnv []string, workdir, apparmor string) error {
	args, err := buildBaseBwrapArgs(mountCurrentDir, mountCurrentDirWritable, mountReadonly, mountWritable, extraEnv, workdir)
	if err != nil {
		return err
	}

	// Explicitly set UID/GID so that bwrap maps the current user correctly inside
	// the nested user namespace (pasta's user namespace has its own UID mapping).
	args = append(args, "--uid", fmt.Sprintf("%d", os.Getuid()), "--gid", fmt.Sprintf("%d", os.Getgid()))

	resolvedProgram, err := resolveProgram(program)
	if err != nil {
		return err
	}
	programDir := filepath.Dir(resolvedProgram)

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}

	// Bind-mount the program's directory if not already covered.
	if mountCurrentDir && programDir != cwd {
		args = append(args, "--ro-bind", programDir, programDir)
	}
	if !strings.HasPrefix(programDir, "/usr") &&
		!strings.HasPrefix(programDir, "/bin") &&
		!strings.HasPrefix(programDir, "/sbin") &&
		!(mountCurrentDir && cwd == programDir) {
		args = append(args, "--ro-bind", programDir, programDir)
	}

	// No --unshare-net or --unshare-uts: pasta creates the network and uts namespace in command mode.

	// DNS: mount /run/systemd/resolve so the /etc/resolv.conf symlink target exists,
	// then overlay stub-resolv.conf with the non-stub version containing real upstream
	// DNS servers (the stub resolver at 127.0.0.53 is not reachable from pasta's namespace).
	nonStubResolv := systemdResolve + "/resolv.conf"
	if _, statErr := os.Stat(nonStubResolv); statErr == nil {
		args = append(args,
			"--ro-bind", systemdResolve, systemdResolve,
			"--ro-bind", nonStubResolv, systemdResolve+"/stub-resolv.conf")
	}

	if apparmor != "" {
		args = append(args, "aa-exec", "-p", apparmor, "--")
	}
	args = append(args, resolvedProgram)
	args = append(args, arguments...)

	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		return fmt.Errorf("failed to find bwrap: %w", err)
	}

	return runPastaCommand(bwrapPath, args)
}

func wrappedPastaNetworkOnly(program string, arguments []string, apparmor string) error {
	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		return fmt.Errorf("failed to find bwrap: %w", err)
	}

	args := []string{
		"--dev-bind", "/", "/",
		"--unshare-user",
		"--uid", fmt.Sprintf("%d", os.Getuid()),
		"--gid", fmt.Sprintf("%d", os.Getgid()),
	}

	// DNS: bind the non-stub resolv.conf so that DNS works in pasta's network namespace.
	nonStubResolv := systemdResolve + "/resolv.conf"
	if _, statErr := os.Stat(nonStubResolv); statErr == nil {
		args = append(args, "--ro-bind", nonStubResolv, "/etc/resolv.conf")
	}

	if apparmor != "" {
		args = append(args, "aa-exec", "-p", apparmor, "--")
	}
	args = append(args, program)
	args = append(args, arguments...)

	return runPastaCommand(bwrapPath, args)
}

// buildFilteredBwrapArgs builds bwrap args for the full filesystem sandbox with filtered network.
// It returns args up to (but not including) the program command — the caller appends the shell command.
func buildFilteredBwrapArgs(mountCurrentDir, mountCurrentDirWritable bool,
	mountReadonly, mountWritable, extraEnv []string, workdir string, filterCfg *filteredNetConfig) ([]string, error) {
	args, err := buildBaseBwrapArgs(mountCurrentDir, mountCurrentDirWritable, mountReadonly, mountWritable, extraEnv, workdir)
	if err != nil {
		return nil, err
	}

	args = append(args, "--unshare-net", "--unshare-uts")

	// Bind-mount Unix sockets into the sandbox.
	args = append(args, "--bind", filterCfg.httpSock, filterCfg.httpSock)
	args = append(args, "--bind", filterCfg.socksSock, filterCfg.socksSock)

	// Set proxy environment variables.
	args = append(args,
		"--setenv", "HTTP_PROXY", "http://localhost:3128",
		"--setenv", "HTTPS_PROXY", "http://localhost:3128",
		"--setenv", "http_proxy", "http://localhost:3128",
		"--setenv", "https_proxy", "http://localhost:3128",
		"--setenv", "ALL_PROXY", "socks5h://localhost:1080",
		"--setenv", "all_proxy", "socks5h://localhost:1080",
		"--setenv", "NO_PROXY", "localhost,127.0.0.1,::1",
		"--setenv", "no_proxy", "localhost,127.0.0.1,::1",
	)

	// DNS: mount /run/systemd/resolve if present.
	info, err := os.Stat(systemdResolve)
	if err == nil && info.IsDir() {
		args = append(args, "--ro-bind", systemdResolve, systemdResolve)
	}

	return args, nil
}

func buildBwrapArgs(program string, arguments []string, network, mountCurrentDir, mountCurrentDirWritable bool,
	mountReadonly, mountWritable, extraEnv []string, workdir, apparmor string) ([]string, error) {
	args, err := buildBaseBwrapArgs(mountCurrentDir, mountCurrentDirWritable, mountReadonly, mountWritable, extraEnv, workdir)
	if err != nil {
		return nil, err
	}

	resolvedProgram, err := resolveProgram(program)
	if err != nil {
		return nil, err
	}
	programDir := filepath.Dir(resolvedProgram)

	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get current directory: %w", err)
	}

	// Bind-mount the program's directory if not already covered.
	if mountCurrentDir && programDir != cwd {
		args = append(args, "--ro-bind", programDir, programDir)
	}
	if !strings.HasPrefix(programDir, "/usr") &&
		!strings.HasPrefix(programDir, "/bin") &&
		!strings.HasPrefix(programDir, "/sbin") &&
		!(mountCurrentDir && cwd == programDir) {
		args = append(args, "--ro-bind", programDir, programDir)
	}

	if network {
		info, err := os.Stat(systemdResolve)
		if err == nil && info.IsDir() {
			args = append(args, "--ro-bind", systemdResolve, systemdResolve)
		}
	} else {
		args = append(args, "--unshare-net", "--unshare-uts")
	}

	if apparmor != "" {
		args = append(args, "aa-exec", "-p", apparmor, "--")
	}
	args = append(args, resolvedProgram)
	args = append(args, arguments...)

	return args, nil
}

// buildBaseBwrapArgs builds the common bwrap args shared by all full-sandbox modes:
// filesystem mounts, current directory, mount points, environment, and core namespace isolation.
func buildBaseBwrapArgs(mountCurrentDir, mountCurrentDirWritable bool,
	mountReadonly, mountWritable, extraEnv []string, workdir string) ([]string, error) {
	var args []string

	args = append(args,
		"--ro-bind", "/usr", "/usr",
		"--symlink", "/usr/lib", "/lib",
		"--symlink", "/usr/lib64", "/lib64",
		"--symlink", "/usr/bin", "/bin",
		"--symlink", "/usr/sbin", "/sbin",
		"--ro-bind", "/etc", "/etc",
		"--perms", "1777",
		"--tmpfs", "/tmp",
		"--proc", "/proc",
		"--dev", "/dev",
	)

	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get current directory: %w", err)
	}

	if mountCurrentDir {
		homeDir, ok := os.LookupEnv("HOME")
		if !ok {
			return nil, errors.New("HOME not set")
		}
		if cwd == homeDir || isParentOrEqual(cwd, homeDir) {
			return nil, errors.New("cannot run from home directory or its parent directories")
		}

		if mountCurrentDirWritable {
			args = append(args, "--bind")
		} else {
			args = append(args, "--ro-bind")
		}
		args = append(args, cwd, cwd)

		if workdir != "" {
			args = append(args, "--chdir", workdir)
		} else {
			args = append(args, "--chdir", cwd)
		}
	} else if workdir != "" {
		args = append(args, "--chdir", workdir)
	}

	for _, path := range mountReadonly {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return nil, fmt.Errorf("mount point %q not found: %w", path, err)
		}
		args = append(args, "--ro-bind", resolved, resolved)
	}
	for _, path := range mountWritable {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return nil, fmt.Errorf("mount point %q not found: %w", path, err)
		}
		args = append(args, "--bind", resolved, resolved)
	}

	args = append(args, "--clearenv")
	for _, k := range envPassthrough {
		if v, ok := os.LookupEnv(k); ok {
			args = append(args, "--setenv", k, v)
		}
	}
	args = append(args, "--setenv", "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")

	for _, e := range extraEnv {
		if k, v, ok := strings.Cut(e, "="); ok {
			args = append(args, "--setenv", k, v)
		} else {
			v, ok := os.LookupEnv(e)
			if !ok {
				return nil, fmt.Errorf("env var %s is not set", e)
			}
			args = append(args, "--setenv", e, v)
		}
	}

	args = append(args,
		"--unshare-user",
		"--unshare-ipc",
		"--unshare-pid",
		"--unshare-cgroup-try",
	)

	return args, nil
}
