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
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

var validApparmorProfile = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
var validPortRange = regexp.MustCompile(`^\d+(-\d+)?$`)
var validCPULimit = regexp.MustCompile(`^\d+(\.\d+)?$`)
var validMemoryLimit = regexp.MustCompile(`^\d+[KMGTPkmgtp]?$`)

func validatePortRanges(label string, ports []string) error {
	for _, p := range ports {
		if !validPortRange.MatchString(p) {
			return fmt.Errorf("invalid %s port range %q: must be a port number or low-high range", label, p)
		}
	}
	return nil
}

// Cgroup describes the cgroup to place the sandboxed program in.
// A limit implies Enabled; an empty limit means unlimited.
type Cgroup struct {
	// Enabled requests that the program runs in a cgroup of its own.
	Enabled bool
	// CPULimit is a number of CPUs, for example "0.5" or "2". Empty means unlimited.
	CPULimit string
	// MemoryLimit is a number of bytes with an optional K, M, G, T or P suffix,
	// for example "512M". Empty means unlimited.
	MemoryLimit string
}

// cpuQuota converts a CPU limit expressed as a number of CPUs into the percentage
// form used by systemd's CPUQuota property, where one CPU is 100%.
func cpuQuota(limit string) (string, error) {
	if !validCPULimit.MatchString(limit) {
		return "", fmt.Errorf("invalid CPU limit %q: must be a number of CPUs, for example 0.5 or 2", limit)
	}
	cpus, err := strconv.ParseFloat(limit, 64)
	if err != nil || cpus <= 0 {
		return "", fmt.Errorf("invalid CPU limit %q: must be greater than zero", limit)
	}
	// systemd resolves CPUQuota with permyriad (0.01%) precision, so two decimals
	// is all it can act on; trailing zeros are dropped for readability.
	percent := strconv.FormatFloat(cpus*100, 'f', 2, 64)
	percent = strings.TrimRight(strings.TrimRight(percent, "0"), ".")
	return percent + "%", nil
}

// memoryMax converts a memory limit into the form used by systemd's MemoryMax property.
func memoryMax(limit string) (string, error) {
	if !validMemoryLimit.MatchString(limit) {
		return "", fmt.Errorf("invalid memory limit %q: must be a number of bytes with an optional K, M, G, T or P suffix, for example 512M", limit)
	}
	upper := strings.ToUpper(limit)
	if strings.Trim(upper, "0KMGTP") == "" {
		return "", fmt.Errorf("invalid memory limit %q: must be greater than zero", limit)
	}
	return upper, nil
}

// systemdUserBusEnv returns the environment to run systemd-run with, and an error if
// this process has no reachable systemd user session bus.
//
// systemd-run --user finds the session bus through DBUS_SESSION_BUS_ADDRESS, or
// through XDG_RUNTIME_DIR, whose "bus" entry is the socket. With neither variable set
// it fails with the rather opaque "Failed to connect to bus: No medium found". A shell
// that inherited neither variable can still have a perfectly good session bus at the
// standard path, so fall back to that rather than failing, and report the situation in
// wrapped's own terms when there is no bus to be found at all.
func systemdUserBusEnv(env []string) ([]string, error) {
	return systemdUserBusEnvAt(env, fmt.Sprintf("/run/user/%d", os.Getuid()))
}

// systemdUserBusEnvAt is systemdUserBusEnv with the standard runtime directory of the
// current user passed in, so that the fallback can be exercised in tests.
func systemdUserBusEnvAt(env []string, standardRuntimeDir string) ([]string, error) {
	// An explicit address may point anywhere, including a socket of a kind that
	// cannot be stat'ed, so take it as given.
	if _, ok := os.LookupEnv("DBUS_SESSION_BUS_ADDRESS"); ok {
		return env, nil
	}

	runtimeDir, fromEnv := os.LookupEnv("XDG_RUNTIME_DIR")
	if !fromEnv {
		runtimeDir = standardRuntimeDir
	}

	if _, err := os.Stat(filepath.Join(runtimeDir, "bus")); err != nil {
		if fromEnv {
			return nil, fmt.Errorf("no systemd user session bus at %s/bus (XDG_RUNTIME_DIR): %w; "+
				"a cgroup needs a systemd user session", runtimeDir, err)
		}
		return nil, fmt.Errorf("no systemd user session bus: neither DBUS_SESSION_BUS_ADDRESS nor "+
			"XDG_RUNTIME_DIR is set and %s/bus does not exist; a cgroup needs a systemd user session, "+
			"which su, sudo, cron and container shells do not set up", runtimeDir)
	}

	if fromEnv {
		return env, nil
	}
	// The session bus is there, only the variable pointing at it is missing.
	return append(env, "XDG_RUNTIME_DIR="+runtimeDir), nil
}

// buildCgroupPrefix returns the command prefix that runs the sandbox in a transient
// systemd scope, that is, in a cgroup of its own, with the requested limits applied,
// together with the environment the sandbox must run with. The first element of the
// prefix is the absolute path of systemd-run and doubles as argv[0]. The prefix is nil
// if no cgroup was requested; the environment is always the one to use.
func buildCgroupPrefix(cgroup Cgroup, env []string) ([]string, []string, error) {
	if !cgroup.Enabled {
		return nil, env, nil
	}

	systemdRunPath, err := exec.LookPath("systemd-run")
	if err != nil {
		return nil, nil, fmt.Errorf("systemd-run is required to create a cgroup: %w; install systemd via your package manager", err)
	}

	env, err = systemdUserBusEnv(env)
	if err != nil {
		return nil, nil, err
	}

	// --collect makes systemd garbage-collect the scope even if the program fails.
	//
	// Accounting is requested even when no limit is set: systemd enables a cgroup
	// controller for a unit only if the unit uses it, so without this a cgroup
	// created by --cgroup alone would have neither the cpu nor the memory
	// controller, leaving the program's resource usage unmeasured. Asking for it
	// explicitly also makes the same control files present whether or not limits
	// are set, rather than depending on the distribution's DefaultCPUAccounting
	// and DefaultMemoryAccounting settings.
	args := []string{
		systemdRunPath,
		"--user", "--scope", "--quiet", "--collect",
		"--description", "wrapped sandbox",
		"--property", "CPUAccounting=yes",
		"--property", "MemoryAccounting=yes",
	}

	if cgroup.CPULimit != "" {
		quota, err := cpuQuota(cgroup.CPULimit)
		if err != nil {
			return nil, nil, err
		}
		args = append(args, "--property", "CPUQuota="+quota)
	}
	if cgroup.MemoryLimit != "" {
		max, err := memoryMax(cgroup.MemoryLimit)
		if err != nil {
			return nil, nil, err
		}
		args = append(args, "--property", "MemoryMax="+max)
	}

	return append(args, "--"), env, nil
}

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

// Individual /etc entries to bind-mount into the sandbox.
// Files and directories are both supported; each is checked at runtime.
var etcBindEntries = []string{
	"resolv.conf",
	"hosts",
	"passwd",
	"group",
	"nsswitch.conf",
	"ld.so.cache",
	"ld.so.conf",
	"ld.so.conf.d",
	"localtime",
	"ssl/certs",
	"default/locale",
	"locale.conf",
	"timezone",
	"lsb-release",
}

type Symlink struct {
	Src  string
	Dest string
}

func Wrapped(program string, arguments []string, networkMode string, mountCurrentDir, mountCurrentDirWritable bool,
	mountReadonly, mountWritable []string, symlinks []Symlink, extraEnv []string, workdir, apparmor string, allowedHosts []string,
	networkSandboxOnly bool, allEnv bool, tmpfs []string, exposeTCP, exposeUDP []string, unshareCgroup bool, cgroup Cgroup) error {
	if apparmor != "" && !validApparmorProfile.MatchString(apparmor) {
		return fmt.Errorf("invalid AppArmor profile name %q: must match ^[a-zA-Z0-9._-]+$", apparmor)
	}

	if networkSandboxOnly {
		switch networkMode {
		case NetworkBridge:
			return wrappedPastaNetworkOnly(program, arguments, apparmor, exposeTCP, exposeUDP, cgroup)

		case NetworkFiltered:
			if len(exposeTCP) > 0 || len(exposeUDP) > 0 {
				return fmt.Errorf("--expose-tcp and --expose-udp can only be used with --network bridge")
			}
			return wrappedFilteredNft(program, arguments, apparmor, allowedHosts,
				false, false, nil, nil, nil, nil, "", false, true, nil, false, cgroup)
		}
	}

	if networkMode == NetworkBridge {
		return wrappedPasta(program, arguments, mountCurrentDir, mountCurrentDirWritable,
			mountReadonly, mountWritable, symlinks, extraEnv, workdir, apparmor, allEnv, tmpfs, exposeTCP, exposeUDP, unshareCgroup, cgroup)
	}

	if networkMode == NetworkFiltered {
		if len(exposeTCP) > 0 || len(exposeUDP) > 0 {
			return fmt.Errorf("--expose-tcp and --expose-udp can only be used with --network bridge")
		}
		return wrappedFilteredNft(program, arguments, apparmor, allowedHosts,
			mountCurrentDir, mountCurrentDirWritable, mountReadonly, mountWritable,
			symlinks, extraEnv, workdir, allEnv, false, tmpfs, unshareCgroup, cgroup)
	}

	if len(exposeTCP) > 0 || len(exposeUDP) > 0 {
		return fmt.Errorf("--expose-tcp and --expose-udp can only be used with --network bridge")
	}
	bwrapArgs, err := buildBwrapArgs(program, arguments, networkMode == NetworkHost, mountCurrentDir, mountCurrentDirWritable,
		mountReadonly, mountWritable, symlinks, extraEnv, workdir, apparmor, allEnv, tmpfs, unshareCgroup)
	if err != nil {
		return err
	}

	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		return fmt.Errorf("failed to find bwrap: %w; install bubblewrap via your package manager", err)
	}

	cgroupPrefix, env, err := buildCgroupPrefix(cgroup, os.Environ())
	if err != nil {
		return err
	}
	if len(cgroupPrefix) > 0 {
		// systemd-run --scope execs the command once the scope exists, so the exec
		// chain is preserved and the sandbox keeps this process's PID.
		argv := append(append([]string{}, cgroupPrefix...), bwrapPath)
		argv = append(argv, bwrapArgs...)
		// exec replaces the current process; if we reach the return, exec failed.
		return fmt.Errorf("failed to exec systemd-run: %w", syscall.Exec(cgroupPrefix[0], argv, env))
	}

	argv := append([]string{"bwrap"}, bwrapArgs...)
	// exec replaces the current process; if we reach the return, exec failed.
	return fmt.Errorf("failed to exec bwrap: %w", syscall.Exec(bwrapPath, argv, env))
}

func wrappedFilteredNft(program string, arguments []string, apparmor string, allowedHosts []string,
	mountCurrentDir, mountCurrentDirWritable bool, mountReadonly, mountWritable []string,
	symlinks []Symlink, extraEnv []string, workdir string, allEnv bool, networkSandboxOnly bool, tmpfs []string,
	unshareCgroup bool, cgroup Cgroup) error {
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("nft (nftables) is required for filtered network access: %w; install nftables via your package manager", err)
	}

	ipv6 := hasIPv6Route()
	allowedIPs, err := resolveHosts(allowedHosts, ipv6)
	if err != nil {
		return err
	}

	resolverIPs, err := parseResolverIPs()
	if err != nil {
		return fmt.Errorf("--network filtered: cannot determine DNS resolver IPs: %w", err)
	}
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

		bwrapArgs, err = buildBaseBwrapArgs(mountCurrentDir, mountCurrentDirWritable, mountReadonly, mountWritable, symlinks, extraEnv, workdir, allEnv, resolvedProgram, tmpfs, unshareCgroup)
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
		return fmt.Errorf("failed to find bwrap: %w; install bubblewrap via your package manager", err)
	}

	if apparmor != "" {
		bwrapArgs = append(bwrapArgs, "aa-exec", "-p", apparmor, "--")
	}
	bwrapArgs = append(bwrapArgs, program)
	bwrapArgs = append(bwrapArgs, arguments...)

	// The nft rules must be applied inside pasta's namespace but before bwrap, so that
	// nft has CAP_NET_ADMIN from pasta's user namespace rather than bwrap's. pasta's
	// command mode runs a single command, so wrapped re-execs itself as that command:
	// the helper applies the ruleset and then execs bwrap. Passing the ruleset and the
	// bwrap arguments as plain argv elements avoids any shell quoting.
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to determine own executable path: %w", err)
	}

	helperArgs := append([]string{internalNftExecArg, nftScript, bwrapPath}, bwrapArgs...)
	return runPastaCommand(self, helperArgs, nil, nil, cgroup)
}

// internalNftExecArg marks an invocation of wrapped as the internal nft helper
// described in wrappedFilteredNft, rather than a normal sandbox run.
const internalNftExecArg = "__nft-exec"

// RunInternalCommand handles wrapped's internal helper invocations, in which wrapped
// re-execs itself to perform setup that must happen inside pasta's namespace. It
// reports whether args were such an invocation; if so, the caller must not proceed
// with normal argument parsing.
//
// A program embedding this package must call RunInternalCommand with os.Args[1:]
// before parsing its own arguments, since --network filtered re-execs the running
// binary (as reported by os.Executable) to reach the helper.
func RunInternalCommand(args []string) (handled bool, err error) {
	if len(args) == 0 || args[0] != internalNftExecArg {
		return false, nil
	}
	return true, runNftExec(args[1:])
}

// runNftExec applies an nftables ruleset and, only if that succeeds, execs the given
// command. args is the ruleset followed by the command and its arguments.
func runNftExec(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("%s: expected a ruleset followed by a command", internalNftExecArg)
	}
	ruleset, argv := args[0], args[1:]

	nftPath, err := exec.LookPath("nft")
	if err != nil {
		return fmt.Errorf("failed to find nft: %w; install nftables via your package manager", err)
	}

	cmd := exec.Command(nftPath, "-f", "/dev/stdin")
	cmd.Stdin = strings.NewReader(ruleset)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to apply nftables rules: %w", err)
	}

	// exec replaces the current process; if we reach the return, exec failed.
	return fmt.Errorf("failed to exec %s: %w", argv[0], syscall.Exec(argv[0], argv, os.Environ()))
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
// Returns an error if no resolver IPs can be determined.
func parseResolverIPs() ([]string, error) {
	paths := []string{systemdResolve + "/resolv.conf", "/etc/resolv.conf"}
	for _, path := range paths {
		ips, err := parseResolvConf(path)
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
	}
	return nil, fmt.Errorf("no nameserver entries found in %s", strings.Join(paths, " or "))
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

// buildNftRules returns an nftables script (suitable for `nft -f /dev/stdin`) that restricts
// outbound traffic to the given IPs. resolverIPs are allowed only on port 53.
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

	var b strings.Builder
	b.WriteString("table inet filter {\n\tchain output {\n")
	b.WriteString("\t\ttype filter hook output priority 0; policy drop;\n")
	b.WriteString("\t\tct state established,related accept\n")
	b.WriteString("\t\toifname lo accept\n")
	if len(dnsIPv4) > 0 {
		b.WriteString("\t\tip daddr { " + strings.Join(dnsIPv4, ", ") + " } meta l4proto { tcp, udp } th dport 53 accept\n")
	}
	if len(dnsIPv6) > 0 {
		b.WriteString("\t\tip6 daddr { " + strings.Join(dnsIPv6, ", ") + " } meta l4proto { tcp, udp } th dport 53 accept\n")
	}
	if len(ipv4) > 0 {
		b.WriteString("\t\tip daddr { " + strings.Join(ipv4, ", ") + " } accept\n")
	}
	if len(ipv6) > 0 {
		b.WriteString("\t\tip6 daddr { " + strings.Join(ipv6, ", ") + " } accept\n")
	}
	b.WriteString("\t}\n}\n")
	return b.String()
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
	mountReadonly, mountWritable []string, symlinks []Symlink, extraEnv []string, workdir, apparmor string, allEnv bool, tmpfs []string,
	exposeTCP, exposeUDP []string, unshareCgroup bool, cgroup Cgroup) error {
	resolvedProgram, err := resolveProgram(program)
	if err != nil {
		return err
	}

	args, err := buildBaseBwrapArgs(mountCurrentDir, mountCurrentDirWritable, mountReadonly, mountWritable, symlinks, extraEnv, workdir, allEnv, resolvedProgram, tmpfs, unshareCgroup)
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
		return fmt.Errorf("failed to find bwrap: %w; install bubblewrap via your package manager", err)
	}

	return runPastaCommand(bwrapPath, args, exposeTCP, exposeUDP, cgroup)
}

func wrappedPastaNetworkOnly(program string, arguments []string, apparmor string, exposeTCP, exposeUDP []string, cgroup Cgroup) error {
	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		return fmt.Errorf("failed to find bwrap: %w; install bubblewrap via your package manager", err)
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

	return runPastaCommand(bwrapPath, args, exposeTCP, exposeUDP, cgroup)
}

// buildPastaArgs constructs the pasta command-line arguments for command mode.
// The returned slice starts with pasta flags and ends with "--", name, args...
func buildPastaArgs(name string, args []string, exposeTCP, exposeUDP []string) ([]string, error) {
	if err := validatePortRanges("--expose-tcp", exposeTCP); err != nil {
		return nil, err
	}
	if err := validatePortRanges("--expose-udp", exposeUDP); err != nil {
		return nil, err
	}

	pastaArgs := []string{
		"--config-net",
		"-T", "none", "-U", "none", // Disable host-to-namespace port forwarding.
	}
	// -t: namespace-to-host TCP port forwarding.
	if len(exposeTCP) == 0 {
		pastaArgs = append(pastaArgs, "-t", "none")
	} else {
		pastaArgs = append(pastaArgs, "-t", strings.Join(exposeTCP, ","))
	}
	// -u: namespace-to-host UDP port forwarding.
	if len(exposeUDP) == 0 {
		pastaArgs = append(pastaArgs, "-u", "none")
	} else {
		pastaArgs = append(pastaArgs, "-u", strings.Join(exposeUDP, ","))
	}
	if !hasIPv6Route() {
		pastaArgs = append(pastaArgs, "-4")
	}

	pastaArgs = append(pastaArgs, "--")
	pastaArgs = append(pastaArgs, name)
	pastaArgs = append(pastaArgs, args...)
	return pastaArgs, nil
}

// runPastaCommand runs pasta in command mode, where pasta creates the user+network
// namespace and runs the given command as its child. This avoids the --info-fd/--userns-block-fd
// coordination protocol that causes ECHILD errors with --unshare-pid.
// If a cgroup is requested, pasta is started inside it, so that the sandbox and the
// network stack serving it share the same limits.
func runPastaCommand(name string, args []string, exposeTCP, exposeUDP []string, cgroup Cgroup) error {
	pastaArgs, err := buildPastaArgs(name, args, exposeTCP, exposeUDP)
	if err != nil {
		return err
	}

	pastaPath, err := exec.LookPath("pasta")
	if err != nil {
		return fmt.Errorf("pasta is required: %w; install passt via your package manager", err)
	}

	cgroupPrefix, env, err := buildCgroupPrefix(cgroup, os.Environ())
	if err != nil {
		return err
	}
	cmdPath, cmdArgs := pastaPath, pastaArgs
	if len(cgroupPrefix) > 0 {
		cmdPath = cgroupPrefix[0]
		cmdArgs = append(append(append([]string{}, cgroupPrefix[1:]...), pastaPath), pastaArgs...)
	}

	cmd := exec.Command(cmdPath, cmdArgs...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start %s: %w", filepath.Base(cmdPath), err)
	}

	// Forward signals to the child.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
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
		return fmt.Errorf("%s failed: %w", filepath.Base(cmdPath), err)
	}
	return nil
}

func buildBwrapArgs(program string, arguments []string, network, mountCurrentDir, mountCurrentDirWritable bool,
	mountReadonly, mountWritable []string, symlinks []Symlink, extraEnv []string, workdir, apparmor string, allEnv bool, tmpfs []string,
	unshareCgroup bool) ([]string, error) {
	resolvedProgram, err := resolveProgram(program)
	if err != nil {
		return nil, err
	}

	args, err := buildBaseBwrapArgs(mountCurrentDir, mountCurrentDirWritable, mountReadonly, mountWritable, symlinks, extraEnv, workdir, allEnv, resolvedProgram, tmpfs, unshareCgroup)
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
func buildBaseBwrapArgs(mountCurrentDir, mountCurrentDirWritable bool, mountReadonly, mountWritable []string, symlinks []Symlink, extraEnv []string, workdir string, allEnv bool, resolvedProgram string, tmpfs []string, unshareCgroup bool) ([]string, error) {
	var args []string

	args = append(args,
		"--ro-bind", "/usr", "/usr",
		"--symlink", "/usr/lib", "/lib",
		"--symlink", "/usr/lib64", "/lib64",
		"--symlink", "/usr/bin", "/bin",
		"--symlink", "/usr/sbin", "/sbin",
	)

	// Bind-mount only the /etc files needed inside the sandbox,
	// rather than exposing the entire /etc directory.
	args = append(args, "--dir", "/etc")
	etcParentDirs := make(map[string]bool)
	for _, entry := range etcBindEntries {
		src := "/etc/" + entry
		info, err := os.Lstat(src)
		if err != nil {
			continue
		}
		// Ensure parent directories exist inside the sandbox for nested entries.
		if dir := filepath.Dir(entry); dir != "." {
			parentPath := "/etc/" + dir
			if !etcParentDirs[parentPath] {
				etcParentDirs[parentPath] = true
				args = append(args, "--dir", parentPath)
			}
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(src)
			if err != nil {
				continue
			}
			args = append(args, "--symlink", target, src)
		} else {
			args = append(args, "--ro-bind", src, src)
		}
	}

	args = append(args,
		"--perms", "1777",
		"--tmpfs", "/tmp",
		"--proc", "/proc",
		"--dev", "/dev",
	)

	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get current directory: %w", err)
	}
	cwd, err = filepath.EvalSymlinks(cwd)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve current directory symlinks: %w", err)
	}

	if workdir != "" {
		resolvedWorkdir, err := filepath.EvalSymlinks(workdir)
		if err != nil {
			return nil, fmt.Errorf("workdir %q not found: %w", workdir, err)
		}
		mountedDirs := collectMountedDirs(mountCurrentDir, cwd, mountReadonly, mountWritable)
		mountedDirs = append(mountedDirs, "/tmp")
		if !isCovered(resolvedWorkdir, mountedDirs) {
			return nil, fmt.Errorf("workdir %q is not within any mounted directory", workdir)
		}
		workdir = resolvedWorkdir
	}

	if mountCurrentDir {
		homeDir, ok := os.LookupEnv("HOME")
		if !ok {
			return nil, errors.New("HOME not set")
		}
		homeDir, err = filepath.EvalSymlinks(homeDir)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve home directory symlinks: %w", err)
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
		if isForbiddenMountTarget(resolved) {
			return nil, fmt.Errorf("mount target %q is not allowed", path)
		}
		args = append(args, "--ro-bind", resolved, resolved)
	}
	for _, path := range mountWritable {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return nil, fmt.Errorf("mount point %q not found: %w", path, err)
		}
		if isForbiddenMountTarget(resolved) {
			return nil, fmt.Errorf("mount target %q is not allowed", path)
		}
		args = append(args, "--bind", resolved, resolved)
	}

	sandboxPaths := collectMountedDirs(mountCurrentDir, cwd, mountReadonly, mountWritable)
	sandboxPaths = append(sandboxPaths, "/etc", "/tmp", "/proc", "/dev")
	for _, symlink := range symlinks {
		if err := validateSymlinkSrc(symlink.Src, sandboxPaths); err != nil {
			return nil, fmt.Errorf("invalid --symlink %q -> %q: %w", symlink.Dest, symlink.Src, err)
		}
		args = append(args, "--symlink", symlink.Src, symlink.Dest)
	}

	for _, path := range tmpfs {
		if isForbiddenMountTarget(path) {
			return nil, fmt.Errorf("tmpfs target %q is not allowed", path)
		}
		args = append(args, "--tmpfs", path)
	}

	if !allEnv {
		args = append(args, "--clearenv")
		for _, k := range envPassthrough {
			if v, ok := os.LookupEnv(k); ok {
				args = append(args, "--setenv", k, v)
			}
		}
	}

	hasPath := false
	for _, e := range extraEnv {
		if k, v, ok := strings.Cut(e, "="); ok {
			if k == "PATH" {
				hasPath = true
			}
			args = append(args, "--setenv", k, v)
		} else {
			if e == "PATH" {
				hasPath = true
			}
			v, ok := os.LookupEnv(e)
			if !ok {
				return nil, fmt.Errorf("env var %s is not set", e)
			}
			args = append(args, "--setenv", e, v)
		}
	}

	if !allEnv && !hasPath {
		args = append(args, "--setenv", "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	}

	args = append(args,
		"--unshare-user",
		"--unshare-ipc",
		"--unshare-pid",
	)

	if unshareCgroup {
		args = append(args, "--unshare-cgroup")
	}

	// Bind-mount the program if not already covered by an existing mount.
	mountedDirs := collectMountedDirs(mountCurrentDir, cwd, mountReadonly, mountWritable)
	if !isCovered(resolvedProgram, mountedDirs) {
		args = append(args, "--ro-bind", resolvedProgram, resolvedProgram)
	}

	return args, nil
}

// collectMountedDirs returns the list of directories that are already mounted in the sandbox.
func collectMountedDirs(mountCurrentDir bool, cwd string, mountReadonly, mountWritable []string) []string {
	dirs := []string{"/usr"}
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

// isCovered reports whether file is already covered by one of the mounted directories.
func isCovered(file string, mountedDirs []string) bool {
	for _, dir := range mountedDirs {
		if isParentOrEqual(dir, file) {
			return true
		}
	}
	return false
}

// isForbiddenMountTarget reports whether the resolved path is a sensitive directory
// that must not be used as a --mount, --mount-writable or --tmpfs target.
func isForbiddenMountTarget(resolved string) bool {
	cleaned := filepath.Clean(resolved)
	switch cleaned {
	case "/", "/proc", "/dev", "/sys":
		return true
	}
	return false
}

// validateSymlinkSrc returns an error if src is an absolute path that does not fall
// under any of the sandbox's mounted paths. Relative paths are always permitted since
// they are resolved relative to the symlink's own location inside the sandbox.
func validateSymlinkSrc(src string, sandboxPaths []string) error {
	if !filepath.IsAbs(src) {
		return nil
	}
	cleaned := filepath.Clean(src)
	for _, p := range sandboxPaths {
		if isParentOrEqual(p, cleaned) {
			return nil
		}
	}
	return fmt.Errorf("source %q is outside the sandbox's mounted paths", src)
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
