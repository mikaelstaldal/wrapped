// Package wrapped runs a program in a sandbox using bubblewrap.
package wrapped

import (
	"bufio"
	"errors"
	"fmt"
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

type Symlink struct {
	Src  string
	Dest string
}

func Wrapped(program string, arguments []string, networkMode string, mountCurrentDir, mountCurrentDirWritable bool,
	mountReadonly, mountWritable []string, symlinks []Symlink, extraEnv []string, workdir, apparmor string, allowedHosts []string,
	networkSandboxOnly bool, allEnv bool, tmpfs []string) error {
	if networkSandboxOnly {
		if allEnv {
			return fmt.Errorf("--only-network cannot be combined with --all-env")
		}
		if mountCurrentDir || mountCurrentDirWritable {
			return fmt.Errorf("--only-network cannot be combined with --current-dir or --current-dir-writable")
		}
		if len(mountReadonly) > 0 {
			return fmt.Errorf("--only-network cannot be combined with --mount")
		}
		if len(mountWritable) > 0 {
			return fmt.Errorf("--only-network cannot be combined with --mount-writable")
		}
		if len(symlinks) > 0 {
			return fmt.Errorf("--only-network cannot be combined with --symlink")
		}
		if workdir != "" {
			return fmt.Errorf("--only-network cannot be combined with --workdir")
		}
		if len(extraEnv) > 0 {
			return fmt.Errorf("--only-network cannot be combined with --env")
		}
		if len(tmpfs) > 0 {
			return fmt.Errorf("--only-network cannot be combined with --tmpfs")
		}

		switch networkMode {
		case NetworkNone:
			return fmt.Errorf("--only-network cannot be combined with --network none")

		case NetworkHost:
			return fmt.Errorf("--only-network cannot be combined with --network host")

		case NetworkBridge:
			return wrappedPastaNetworkOnly(program, arguments, apparmor)

		case NetworkFiltered:
			return wrappedFilteredNft(program, arguments, apparmor, allowedHosts,
				false, false, nil, nil, nil, nil, "", false, true, nil)
		}
	}

	if networkMode == NetworkBridge {
		return wrappedPasta(program, arguments, mountCurrentDir, mountCurrentDirWritable,
			mountReadonly, mountWritable, symlinks, extraEnv, workdir, apparmor, allEnv, tmpfs)
	}

	if networkMode == NetworkFiltered {
		return wrappedFilteredNft(program, arguments, apparmor, allowedHosts,
			mountCurrentDir, mountCurrentDirWritable, mountReadonly, mountWritable,
			symlinks, extraEnv, workdir, allEnv, false, tmpfs)
	}

	bwrapArgs, err := buildBwrapArgs(program, arguments, networkMode == NetworkHost, mountCurrentDir, mountCurrentDirWritable,
		mountReadonly, mountWritable, symlinks, extraEnv, workdir, apparmor, allEnv, tmpfs)
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

func wrappedFilteredNft(program string, arguments []string, apparmor string, allowedHosts []string,
	mountCurrentDir, mountCurrentDirWritable bool, mountReadonly, mountWritable []string,
	symlinks []Symlink, extraEnv []string, workdir string, allEnv bool, networkSandboxOnly bool, tmpfs []string) error {
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("nft (nftables) is required for filtered network access: %w", err)
	}

	ipv6 := hasIPv6Route()
	allowedIPs, err := resolveHosts(allowedHosts, ipv6)
	if err != nil {
		return err
	}

	resolverIPs := parseResolverIPs()
	nftScript := buildNftRules(allowedIPs, resolverIPs)

	var bwrapArgs []string
	if networkSandboxOnly {
		bwrapArgs = []string{
			"--dev-bind", "/", "/",
			"--unshare-user",
			"--uid", fmt.Sprintf("%d", os.Getuid()),
			"--gid", fmt.Sprintf("%d", os.Getgid()),
		}

		// DNS: bind the non-stub resolv.conf so that DNS works in pasta's network namespace.
		nonStubResolv := systemdResolve + "/resolv.conf"
		if _, statErr := os.Stat(nonStubResolv); statErr == nil {
			bwrapArgs = append(bwrapArgs, "--ro-bind", nonStubResolv, "/etc/resolv.conf")
		}
	} else {
		resolvedProgram, err := resolveProgram(program)
		if err != nil {
			return err
		}

		bwrapArgs, err = buildBaseBwrapArgs(mountCurrentDir, mountCurrentDirWritable, mountReadonly, mountWritable, symlinks, extraEnv, workdir, allEnv, resolvedProgram, tmpfs)
		if err != nil {
			return err
		}

		bwrapArgs = append(bwrapArgs,
			"--uid", fmt.Sprintf("%d", os.Getuid()),
			"--gid", fmt.Sprintf("%d", os.Getgid()),
		)

		// DNS: mount /run/systemd/resolve so the /etc/resolv.conf symlink target exists,
		// then overlay stub-resolv.conf with the non-stub version.
		nonStubResolv := systemdResolve + "/resolv.conf"
		if _, statErr := os.Stat(nonStubResolv); statErr == nil {
			bwrapArgs = append(bwrapArgs,
				"--ro-bind", systemdResolve, systemdResolve,
				"--ro-bind", nonStubResolv, systemdResolve+"/stub-resolv.conf")
		}

		program = resolvedProgram
	}

	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		return fmt.Errorf("failed to find bwrap: %w", err)
	}

	if apparmor != "" {
		bwrapArgs = append(bwrapArgs, "aa-exec", "-p", apparmor, "--")
	}
	bwrapArgs = append(bwrapArgs, program)
	bwrapArgs = append(bwrapArgs, arguments...)

	// Build a shell command that runs nft rules first (inside pasta's namespace,
	// before bwrap), then execs bwrap. This ensures nft has CAP_NET_ADMIN from
	// pasta's user namespace rather than bwrap's.
	shellCmd := nftScript + " && exec " + shellQuote(bwrapPath)
	for _, arg := range bwrapArgs {
		shellCmd += " " + shellQuote(arg)
	}

	return runPastaCommand("sh", []string{"-c", shellCmd})
}

// resolveHosts resolves hostnames to IP addresses, deduplicates, and optionally filters IPv6.
func resolveHosts(hosts []string, ipv6 bool) ([]string, error) {
	seen := make(map[string]bool)
	var ips []string
	for _, host := range hosts {
		addrs, err := net.LookupHost(host)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve host %q: %w", host, err)
		}
		for _, addr := range addrs {
			if seen[addr] {
				continue
			}
			ip := net.ParseIP(addr)
			if ip == nil {
				continue
			}
			if !ipv6 && ip.To4() == nil {
				continue
			}
			seen[addr] = true
			ips = append(ips, addr)
		}
	}
	return ips, nil
}

// parseResolverIPs reads nameserver entries from /run/systemd/resolve/resolv.conf,
// falling back to /etc/resolv.conf, and returns their IP addresses.
func parseResolverIPs() []string {
	paths := []string{systemdResolve + "/resolv.conf", "/etc/resolv.conf"}
	for _, path := range paths {
		ips, err := parseResolvConf(path)
		if err == nil {
			return ips
		}
	}
	return nil
}

// parseResolvConf extracts nameserver IPs from a resolv.conf file.
func parseResolvConf(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var ips []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if ip := net.ParseIP(fields[1]); ip != nil {
			ips = append(ips, fields[1])
		}
	}
	return ips, scanner.Err()
}

// buildNftRules returns a shell script that sets up nftables rules to allow only the given IPs.
// resolverIPs are the DNS resolver addresses that DNS traffic (port 53) is restricted to.
func buildNftRules(allowedIPs []string, resolverIPs []string) string {
	var ipv4, ipv6 []string
	for _, addr := range allowedIPs {
		ip := net.ParseIP(addr)
		if ip.To4() != nil {
			ipv4 = append(ipv4, addr)
		} else {
			ipv6 = append(ipv6, addr)
		}
	}

	var dnsIPv4, dnsIPv6 []string
	for _, addr := range resolverIPs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			dnsIPv4 = append(dnsIPv4, addr)
		} else {
			dnsIPv6 = append(dnsIPv6, addr)
		}
	}

	script := "nft add table inet filter && " +
		"nft add chain inet filter output '{ type filter hook output priority 0; policy drop; }' && " +
		"nft add rule inet filter output ct state established,related accept && " +
		"nft add rule inet filter output oifname lo accept"

	if len(dnsIPv4) > 0 || len(dnsIPv6) > 0 {
		if len(dnsIPv4) > 0 {
			script += " && nft add rule inet filter output ip daddr '{ " + strings.Join(dnsIPv4, ", ") + " }' meta l4proto '{ tcp, udp }' th dport 53 accept"
		}
		if len(dnsIPv6) > 0 {
			script += " && nft add rule inet filter output ip6 daddr '{ " + strings.Join(dnsIPv6, ", ") + " }' meta l4proto '{ tcp, udp }' th dport 53 accept"
		}
	} else {
		// Fallback: allow DNS to any destination if no resolvers were found.
		script += " && nft add rule inet filter output meta l4proto '{ tcp, udp }' th dport 53 accept"
	}

	if len(ipv4) > 0 {
		script += " && nft add rule inet filter output ip daddr '{ " + strings.Join(ipv4, ", ") + " }' accept"
	}
	if len(ipv6) > 0 {
		script += " && nft add rule inet filter output ip6 daddr '{ " + strings.Join(ipv6, ", ") + " }' accept"
	}

	return script
}

// shellQuote returns s wrapped in single quotes, safe for use in a shell command.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
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

func wrappedPasta(program string, arguments []string, mountCurrentDir, mountCurrentDirWritable bool,
	mountReadonly, mountWritable []string, symlinks []Symlink, extraEnv []string, workdir, apparmor string, allEnv bool, tmpfs []string) error {
	resolvedProgram, err := resolveProgram(program)
	if err != nil {
		return err
	}

	args, err := buildBaseBwrapArgs(mountCurrentDir, mountCurrentDirWritable, mountReadonly, mountWritable, symlinks, extraEnv, workdir, allEnv, resolvedProgram, tmpfs)
	if err != nil {
		return err
	}

	// Explicitly set UID/GID so that bwrap maps the current user correctly inside
	// the nested user namespace (pasta's user namespace has its own UID mapping).
	args = append(args, "--uid", fmt.Sprintf("%d", os.Getuid()), "--gid", fmt.Sprintf("%d", os.Getgid()))

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

func buildBwrapArgs(program string, arguments []string, network, mountCurrentDir, mountCurrentDirWritable bool,
	mountReadonly, mountWritable []string, symlinks []Symlink, extraEnv []string, workdir, apparmor string, allEnv bool, tmpfs []string) ([]string, error) {
	resolvedProgram, err := resolveProgram(program)
	if err != nil {
		return nil, err
	}

	args, err := buildBaseBwrapArgs(mountCurrentDir, mountCurrentDirWritable, mountReadonly, mountWritable, symlinks, extraEnv, workdir, allEnv, resolvedProgram, tmpfs)
	if err != nil {
		return nil, err
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
func buildBaseBwrapArgs(mountCurrentDir, mountCurrentDirWritable bool, mountReadonly, mountWritable []string, symlinks []Symlink, extraEnv []string, workdir string, allEnv bool, resolvedProgram string, tmpfs []string) ([]string, error) {
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

	for _, symlink := range symlinks {
		args = append(args, "--symlink", symlink.Src, symlink.Dest)
	}

	for _, path := range tmpfs {
		args = append(args, "--tmpfs", path)
	}

	if !allEnv {
		args = append(args, "--clearenv")
		for _, k := range envPassthrough {
			if v, ok := os.LookupEnv(k); ok {
				args = append(args, "--setenv", k, v)
			}
		}
		args = append(args, "--setenv", "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	}

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

	// Bind-mount the program if not already covered by an existing mount.
	mountedDirs := collectMountedDirs(mountCurrentDir, cwd, mountReadonly, mountWritable)
	if !isProgramCovered(resolvedProgram, mountedDirs) {
		args = append(args, "--ro-bind", resolvedProgram, resolvedProgram)
	}

	return args, nil
}

// collectMountedDirs returns the list of directories that are already mounted in the sandbox.
func collectMountedDirs(mountCurrentDir bool, cwd string, mountReadonly, mountWritable []string) []string {
	dirs := []string{"/usr", "/etc"}
	if mountCurrentDir {
		dirs = append(dirs, cwd)
	}
	for _, path := range mountReadonly {
		resolved, err := filepath.EvalSymlinks(path)
		if err == nil {
			dirs = append(dirs, resolved)
		}
	}
	for _, path := range mountWritable {
		resolved, err := filepath.EvalSymlinks(path)
		if err == nil {
			dirs = append(dirs, resolved)
		}
	}
	return dirs
}

// isProgramCovered reports whether programDir is already covered by one of the mounted directories.
func isProgramCovered(program string, mountedDirs []string) bool {
	for _, dir := range mountedDirs {
		if isParentOrEqual(dir, program) {
			return true
		}
	}
	return false
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
