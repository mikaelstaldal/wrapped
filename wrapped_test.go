package wrapped

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// containsSeq reports whether args contains the given consecutive subsequence.
func containsSeq(args []string, seq ...string) bool {
	for i := 0; i <= len(args)-len(seq); i++ {
		match := true
		for j, s := range seq {
			if args[i+j] != s {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func TestApparmorProfileValidation(t *testing.T) {
	valid := []string{
		"firefox",
		"snap.chromium.chromium",
		"my-profile",
		"profile_v2",
		"AppArmor.Profile-123",
	}
	for _, name := range valid {
		assert.Regexp(t, validApparmorProfile, name, "expected %q to be valid", name)
	}

	invalid := []string{
		"profile name", // space
		"../escape",    // path traversal
		"foo;bar",      // semicolon
		"foo&bar",      // shell metachar
		"foo|bar",      // pipe
		"foo`cmd`",     // backtick
		"foo$(cmd)",    // subshell
		"",             // empty is handled separately (skipped), but ensure regex rejects
		"foo/bar",      // slash
	}
	for _, name := range invalid {
		if name != "" {
			assert.NotRegexp(t, validApparmorProfile, name, "expected %q to be invalid", name)
		}
	}
}

func TestValidatePortRanges(t *testing.T) {
	valid := []string{"80", "443", "1024-65535", "0", "8080-8090"}
	assert.NoError(t, validatePortRanges("--expose-tcp", valid), "unexpected error for valid ports")

	invalid := []string{"abc", "80-", "-443", "80:443", "80/tcp"}
	for _, p := range invalid {
		assert.Error(t, validatePortRanges("--expose-tcp", []string{p}), "expected error for port %q", p)
	}
}

func TestIsParentOrEqual(t *testing.T) {
	cases := []struct {
		parent, child string
		want          bool
	}{
		{"/home/user", "/home/user", true},
		{"/home/user", "/home/user/project", true},
		{"/home/user", "/home/user2", false},
		{"/home", "/home/user", true},
		{"/usr", "/usr/bin/go", true},
		{"/usr/bin", "/usr", false},
	}
	for _, c := range cases {
		got := isParentOrEqual(c.parent, c.child)
		assert.Equal(t, c.want, got, "isParentOrEqual(%q, %q)", c.parent, c.child)
	}
}

func TestIsCovered(t *testing.T) {
	dirs := []string{"/usr", "/home/user/project"}
	cases := []struct {
		file string
		want bool
	}{
		{"/usr/bin/go", true},
		{"/usr", true},
		{"/home/user/project/main.go", true},
		{"/home/user", false},
		{"/etc/passwd", false},
	}
	for _, c := range cases {
		got := isCovered(c.file, dirs)
		assert.Equal(t, c.want, got, "isCovered(%q)", c.file)
	}
}

func TestIsForbiddenMountTarget(t *testing.T) {
	forbidden := []string{"/", "/proc", "/dev", "/sys"}
	for _, p := range forbidden {
		assert.True(t, isForbiddenMountTarget(p), "expected %q to be forbidden", p)
	}

	allowed := []string{"/home/user", "/tmp/mydir", "/opt/data"}
	for _, p := range allowed {
		assert.False(t, isForbiddenMountTarget(p), "expected %q to be allowed", p)
	}
}

func TestValidateSymlinkSrc(t *testing.T) {
	sandbox := []string{"/usr", "/tmp", "/home/user/project"}

	// Relative paths always OK.
	assert.NoError(t, validateSymlinkSrc("../lib", sandbox), "unexpected error for relative path")

	// Absolute paths inside sandbox OK.
	assert.NoError(t, validateSymlinkSrc("/usr/lib", sandbox), "unexpected error for /usr/lib")
	assert.NoError(t, validateSymlinkSrc("/home/user/project/file", sandbox), "unexpected error for project path")

	// Absolute paths outside sandbox rejected.
	assert.Error(t, validateSymlinkSrc("/etc/passwd", sandbox), "expected error for /etc/passwd outside sandbox")
	assert.Error(t, validateSymlinkSrc("/root/secret", sandbox), "expected error for /root/secret outside sandbox")
}

func TestRunInternalCommand(t *testing.T) {
	handled, err := RunInternalCommand(nil)
	assert.False(t, handled, "no arguments must not be an internal invocation")
	assert.NoError(t, err)

	handled, err = RunInternalCommand([]string{"echo", "hello"})
	assert.False(t, handled, "a normal invocation must not be treated as internal")
	assert.NoError(t, err)

	handled, err = RunInternalCommand([]string{internalNftExecArg})
	assert.True(t, handled, "the internal argument must be handled")
	assert.Error(t, err, "expected an error when no ruleset and command follow")
}

func TestParseResolvConf(t *testing.T) {
	content := "# comment\nnameserver 1.1.1.1\nnameserver 8.8.8.8\nsearch example.com\nnameserver not-an-ip\n"
	f, err := os.CreateTemp(t.TempDir(), "resolv.conf")
	require.NoError(t, err)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	f.Close()

	ips, err := parseResolvConf(f.Name())
	assert.NoError(t, err)
	assert.Equal(t, []string{"1.1.1.1", "8.8.8.8"}, ips)

	_, err = parseResolvConf(filepath.Join(t.TempDir(), "nonexistent"))
	assert.Error(t, err, "expected error for missing file")
}

func TestBuildNftRules(t *testing.T) {
	rules := buildNftRules([]string{"1.2.3.4", "2001:db8::1"}, []string{"8.8.8.8", "2001:4860:4860::8888"})

	mustContain := []string{
		"table inet filter",
		"chain output",
		"policy drop",
		"ct state established,related accept",
		"oifname lo accept",
		"ip daddr { 1.2.3.4 } accept",
		"ip6 daddr { 2001:db8::1 } accept",
		"ip daddr { 8.8.8.8 } meta l4proto { tcp, udp } th dport 53 accept",
		"ip6 daddr { 2001:4860:4860::8888 } meta l4proto { tcp, udp } th dport 53 accept",
	}
	for _, s := range mustContain {
		assert.Contains(t, rules, s, "nft rules missing %q", s)
	}
}

func TestBuildNftRulesEmpty(t *testing.T) {
	rules := buildNftRules(nil, nil)
	assert.Contains(t, rules, "policy drop", "rules should still have drop policy when no IPs given")
	assert.NotContains(t, rules, "ip daddr", "rules should have no ip daddr rules when no IPs given")
}

func TestWrappedExposeTCPUDPRequiresBridge(t *testing.T) {
	cases := []struct {
		network string
		tcp     []string
		udp     []string
	}{
		{NetworkNone, []string{"80"}, nil},
		{NetworkNone, nil, []string{"53"}},
		{NetworkHost, []string{"443"}, nil},
		{NetworkFiltered, []string{"8080"}, nil},
		{NetworkFiltered, nil, []string{"123"}},
	}
	for _, c := range cases {
		err := Wrapped("true", nil, c.network, false, false, nil, nil, nil, nil, "", "", nil, false, false, nil, c.tcp, c.udp, false, Cgroup{})
		assert.ErrorContains(t, err, "--expose-tcp and --expose-udp can only be used with --network bridge", "expected error for network=%q tcp=%v udp=%v", c.network, c.tcp, c.udp)
	}
}

func TestWrappedRejectsInvalidApparmorProfile(t *testing.T) {
	bad := []string{
		"profile name",
		"../escape",
		"foo;bar",
		"foo|bar",
	}
	for _, name := range bad {
		err := Wrapped("true", nil, NetworkNone, false, false, nil, nil, nil, nil, "", name, nil, false, false, nil, nil, nil, false, Cgroup{})
		assert.ErrorContains(t, err, "invalid AppArmor profile name", "expected error for profile %q", name)
	}
}

// testProgram returns an absolute path to an existing executable suitable for
// use as the program argument in build*Args tests.
func testProgram(t *testing.T) string {
	t.Helper()
	return os.Args[0] // the test binary itself
}

func TestBuildBaseBwrapArgsStructure(t *testing.T) {
	prog := testProgram(t)
	args, err := buildBaseBwrapArgs(false, false, nil, nil, nil, nil, "", false, prog, nil, false)
	require.NoError(t, err)

	mustHaveSeq := [][]string{
		{"--ro-bind", "/usr", "/usr"},
		{"--symlink", "/usr/lib", "/lib"},
		{"--symlink", "/usr/lib64", "/lib64"},
		{"--symlink", "/usr/bin", "/bin"},
		{"--symlink", "/usr/sbin", "/sbin"},
		{"--tmpfs", "/tmp"},
		{"--proc", "/proc"},
		{"--dev", "/dev"},
	}
	for _, seq := range mustHaveSeq {
		assert.True(t, containsSeq(args, seq...), "args missing sequence %v", seq)
	}

	for _, flag := range []string{"--unshare-user", "--unshare-ipc", "--unshare-pid"} {
		assert.Contains(t, args, flag)
	}

	// The cgroup namespace is not unshared by default.
	assert.NotContains(t, args, "--unshare-cgroup")
	assert.NotContains(t, args, "--unshare-cgroup-try")
}

func TestBuildBaseBwrapArgsUnshareCgroup(t *testing.T) {
	prog := testProgram(t)

	args, err := buildBaseBwrapArgs(false, false, nil, nil, nil, nil, "", false, prog, nil, true)
	require.NoError(t, err)
	assert.Contains(t, args, "--unshare-cgroup")
}

func TestBuildBaseBwrapArgsClearEnv(t *testing.T) {
	prog := testProgram(t)

	// Without allEnv: --clearenv and default PATH should be present.
	args, err := buildBaseBwrapArgs(false, false, nil, nil, nil, nil, "", false, prog, nil, false)
	require.NoError(t, err)
	assert.Contains(t, args, "--clearenv")
	assert.True(t, containsSeq(args, "--setenv", "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"))

	// With allEnv: --clearenv must not appear, nor should default PATH be set.
	args, err = buildBaseBwrapArgs(false, false, nil, nil, nil, nil, "", true, prog, nil, false)
	require.NoError(t, err)
	assert.NotContains(t, args, "--clearenv")
	assert.False(t, containsSeq(args, "--setenv", "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"))
}

func TestBuildBaseBwrapArgsExtraEnv(t *testing.T) {
	prog := testProgram(t)

	// Extra env with KEY=VALUE form.
	args, err := buildBaseBwrapArgs(false, false, nil, nil, nil, []string{"FOO=bar", "BAZ=qux"}, "", false, prog, nil, false)
	require.NoError(t, err)
	assert.True(t, containsSeq(args, "--setenv", "FOO", "bar"))
	assert.True(t, containsSeq(args, "--setenv", "BAZ", "qux"))

	// Providing PATH in extraEnv suppresses the default PATH.
	args, err = buildBaseBwrapArgs(false, false, nil, nil, nil, []string{"PATH=/custom/bin"}, "", false, prog, nil, false)
	require.NoError(t, err)
	assert.True(t, containsSeq(args, "--setenv", "PATH", "/custom/bin"))
	assert.False(t, containsSeq(args, "--setenv", "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"))
}

func TestBuildBaseBwrapArgsMountCurrentDir(t *testing.T) {
	prog := testProgram(t)
	cwd, _ := os.Getwd()
	cwd, _ = filepath.EvalSymlinks(cwd)

	// Read-only mount.
	args, err := buildBaseBwrapArgs(true, false, nil, nil, nil, nil, "", false, prog, nil, false)
	require.NoError(t, err)
	assert.True(t, containsSeq(args, "--ro-bind", cwd, cwd))
	assert.False(t, containsSeq(args, "--bind", cwd, cwd))

	// Writable mount.
	args, err = buildBaseBwrapArgs(true, true, nil, nil, nil, nil, "", false, prog, nil, false)
	require.NoError(t, err)
	assert.True(t, containsSeq(args, "--bind", cwd, cwd))
}

func TestBuildBaseBwrapArgsTmpfs(t *testing.T) {
	prog := testProgram(t)
	args, err := buildBaseBwrapArgs(false, false, nil, nil, nil, nil, "", false, prog, []string{"/run/cache"}, false)
	require.NoError(t, err)
	assert.True(t, containsSeq(args, "--tmpfs", "/run/cache"))
}

func TestBuildBwrapArgsNoNetwork(t *testing.T) {
	prog := testProgram(t)
	args, err := buildBwrapArgs(prog, nil, false, false, false, nil, nil, nil, nil, "", "", false, nil, false)
	require.NoError(t, err)
	assert.Contains(t, args, "--unshare-net")
	assert.Contains(t, args, "--unshare-uts")
}

func TestBuildBwrapArgsHostNetwork(t *testing.T) {
	prog := testProgram(t)
	args, err := buildBwrapArgs(prog, nil, true, false, false, nil, nil, nil, nil, "", "", false, nil, false)
	require.NoError(t, err)
	assert.NotContains(t, args, "--unshare-net")
	assert.NotContains(t, args, "--unshare-uts")
}

func TestBuildBwrapArgsAppArmor(t *testing.T) {
	prog := testProgram(t)
	resolvedProg, err := resolveProgram(prog)
	require.NoError(t, err)

	args, err := buildBwrapArgs(prog, []string{"arg1"}, false, false, false, nil, nil, nil, nil, "", "my-profile", false, nil, false)
	require.NoError(t, err)

	// aa-exec -p profile -- must appear immediately before the program.
	assert.True(t, containsSeq(args, "aa-exec", "-p", "my-profile", "--", resolvedProg, "arg1"))
}

func TestBuildBwrapArgsProgramAndArguments(t *testing.T) {
	prog := testProgram(t)
	resolvedProg, err := resolveProgram(prog)
	require.NoError(t, err)

	args, err := buildBwrapArgs(prog, []string{"--foo", "bar"}, false, false, false, nil, nil, nil, nil, "", "", false, nil, false)
	require.NoError(t, err)

	assert.True(t, containsSeq(args, resolvedProg, "--foo", "bar"))
}

func TestBuildPastaArgsNoPorts(t *testing.T) {
	args, err := buildPastaArgs("/usr/bin/bwrap", []string{"--unshare-user"}, nil, nil)
	require.NoError(t, err)
	assert.Contains(t, args, "--config-net")
	// Host-to-namespace forwarding must be disabled.
	assert.True(t, containsSeq(args, "-T", "none"))
	assert.True(t, containsSeq(args, "-U", "none"))
	// No exposed ports → -t none and -u none.
	assert.True(t, containsSeq(args, "-t", "none"))
	assert.True(t, containsSeq(args, "-u", "none"))
	// Command separator and wrapped command must follow pasta flags.
	assert.True(t, containsSeq(args, "--", "/usr/bin/bwrap", "--unshare-user"))
}

func TestBuildPastaArgsWithPorts(t *testing.T) {
	args, err := buildPastaArgs("/usr/bin/bwrap", nil, []string{"80", "443"}, []string{"53"})
	require.NoError(t, err)
	assert.True(t, containsSeq(args, "-t", "80,443"))
	assert.True(t, containsSeq(args, "-u", "53"))
}

func TestBuildPastaArgsPortRange(t *testing.T) {
	args, err := buildPastaArgs("/usr/bin/bwrap", nil, []string{"8080-8090"}, nil)
	require.NoError(t, err)
	assert.True(t, containsSeq(args, "-t", "8080-8090"))
}

func TestBuildPastaArgsInvalidPorts(t *testing.T) {
	_, err := buildPastaArgs("/usr/bin/bwrap", nil, []string{"not-a-port"}, nil)
	assert.Error(t, err, "expected error for invalid TCP port")

	_, err = buildPastaArgs("/usr/bin/bwrap", nil, nil, []string{"80:443"})
	assert.Error(t, err, "expected error for invalid UDP port")
}

func TestCPUQuota(t *testing.T) {
	cases := map[string]string{
		"1":     "100%",
		"2":     "200%",
		"0.5":   "50%",
		"1.5":   "150%",
		"0.25":  "25%",
		"0.125": "12.5%",
		"16":    "1600%",
	}
	for limit, want := range cases {
		got, err := cpuQuota(limit)
		require.NoError(t, err, "limit %q", limit)
		assert.Equal(t, want, got, "limit %q", limit)
	}
}

func TestCPUQuotaInvalid(t *testing.T) {
	invalid := []string{
		"",
		"0",
		"0.0",
		"-1",
		"50%",
		"one",
		"1,5",
		"1 2",
		"1;rm -rf /",
	}
	for _, limit := range invalid {
		_, err := cpuQuota(limit)
		assert.Error(t, err, "expected error for CPU limit %q", limit)
	}
}

func TestMemoryMax(t *testing.T) {
	cases := map[string]string{
		"512M":       "512M",
		"2G":         "2G",
		"1024":       "1024",
		"512m":       "512M",
		"4g":         "4G",
		"1T":         "1T",
		"1024000000": "1024000000",
	}
	for limit, want := range cases {
		got, err := memoryMax(limit)
		require.NoError(t, err, "limit %q", limit)
		assert.Equal(t, want, got, "limit %q", limit)
	}
}

func TestMemoryMaxInvalid(t *testing.T) {
	invalid := []string{
		"",
		"0",
		"0M",
		"-1G",
		"512MB",
		"1.5G",
		"512 M",
		"lots",
		"512M; rm -rf /",
	}
	for _, limit := range invalid {
		_, err := memoryMax(limit)
		assert.Error(t, err, "expected error for memory limit %q", limit)
	}
}

// withSessionBus points XDG_RUNTIME_DIR at a directory holding a "bus" entry, so that
// the cgroup helpers find a session bus regardless of the machine running the tests.
func withSessionBus(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bus"), nil, 0o600))
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	require.NoError(t, os.Unsetenv("DBUS_SESSION_BUS_ADDRESS"))
	t.Setenv("XDG_RUNTIME_DIR", dir)
}

func TestSystemdUserBusEnvExplicitAddress(t *testing.T) {
	// An explicit address is taken as given, even with no XDG_RUNTIME_DIR.
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/somewhere/else")
	t.Setenv("XDG_RUNTIME_DIR", "")
	require.NoError(t, os.Unsetenv("XDG_RUNTIME_DIR"))

	env, err := systemdUserBusEnv([]string{"FOO=bar"})
	require.NoError(t, err)
	assert.Equal(t, []string{"FOO=bar"}, env)
}

func TestSystemdUserBusEnvFromRuntimeDir(t *testing.T) {
	withSessionBus(t)

	env, err := systemdUserBusEnv([]string{"FOO=bar"})
	require.NoError(t, err)
	// The variable is already set, so the environment is left alone.
	assert.Equal(t, []string{"FOO=bar"}, env)
}

// unsetBusVars clears both variables systemd-run uses to find the session bus, as a
// shell started by su, sudo or cron leaves them.
func unsetBusVars(t *testing.T) {
	t.Helper()
	// t.Setenv registers the restore; Unsetenv then removes the variable itself.
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	require.NoError(t, os.Unsetenv("DBUS_SESSION_BUS_ADDRESS"))
	t.Setenv("XDG_RUNTIME_DIR", "")
	require.NoError(t, os.Unsetenv("XDG_RUNTIME_DIR"))
}

// TestSystemdUserBusEnvFallsBackToStandardPath covers a shell that inherited neither
// variable: the session bus is still at the standard path, so wrapped points
// systemd-run at it instead of failing the way plain systemd-run would.
func TestSystemdUserBusEnvFallsBackToStandardPath(t *testing.T) {
	unsetBusVars(t)
	runtimeDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(runtimeDir, "bus"), nil, 0o600))

	env, err := systemdUserBusEnvAt([]string{"FOO=bar"}, runtimeDir)
	require.NoError(t, err)
	assert.Equal(t, []string{"FOO=bar", "XDG_RUNTIME_DIR=" + runtimeDir}, env)
}

// TestSystemdUserBusEnvNoSessionAtAll covers the reported failure: with neither
// variable set and no bus at the standard path, systemd-run would report only
// "Failed to connect to bus: No medium found".
func TestSystemdUserBusEnvNoSessionAtAll(t *testing.T) {
	unsetBusVars(t)
	standardPath := filepath.Join(t.TempDir(), "run-user")

	_, err := systemdUserBusEnvAt(nil, standardPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no systemd user session bus")
	assert.Contains(t, err.Error(), standardPath)
	assert.Contains(t, err.Error(), "systemd user session")
}

// TestSystemdUserBusEnvUsesRealStandardPath checks that the wrapper passes the current
// user's own runtime directory to the fallback.
func TestSystemdUserBusEnvUsesRealStandardPath(t *testing.T) {
	unsetBusVars(t)
	standardPath := fmt.Sprintf("/run/user/%d", os.Getuid())

	env, err := systemdUserBusEnv(nil)
	if _, statErr := os.Stat(filepath.Join(standardPath, "bus")); statErr != nil {
		assert.ErrorContains(t, err, standardPath)
		return
	}
	require.NoError(t, err)
	assert.Equal(t, []string{"XDG_RUNTIME_DIR=" + standardPath}, env)
}

func TestSystemdUserBusEnvMissingBus(t *testing.T) {
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	require.NoError(t, os.Unsetenv("DBUS_SESSION_BUS_ADDRESS"))
	// Set but bus-less, as in a sandbox that does not carry the socket in.
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	_, err := systemdUserBusEnv(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no systemd user session bus")
	assert.Contains(t, err.Error(), "XDG_RUNTIME_DIR")
}

func TestBuildCgroupPrefixDisabled(t *testing.T) {
	prefix, env, err := buildCgroupPrefix(Cgroup{}, []string{"FOO=bar"})
	require.NoError(t, err)
	assert.Empty(t, prefix)
	// Without a cgroup the environment must pass through untouched, and no session
	// bus is needed at all.
	assert.Equal(t, []string{"FOO=bar"}, env)
}

func TestBuildCgroupPrefix(t *testing.T) {
	if _, err := exec.LookPath("systemd-run"); err != nil {
		t.Skip("systemd-run not in PATH")
	}
	withSessionBus(t)

	prefix, _, err := buildCgroupPrefix(Cgroup{Enabled: true}, nil)
	require.NoError(t, err)
	require.NotEmpty(t, prefix)
	assert.Equal(t, "systemd-run", filepath.Base(prefix[0]))
	assert.True(t, containsSeq(prefix, "--user", "--scope"))
	// The prefix must end with the separator, so the sandbox command follows it.
	assert.Equal(t, "--", prefix[len(prefix)-1])
	// Accounting is always requested, so that a cgroup without limits still gets
	// the cpu and memory controllers and the program's usage is measured.
	assert.True(t, containsSeq(prefix, "--property", "CPUAccounting=yes"))
	assert.True(t, containsSeq(prefix, "--property", "MemoryAccounting=yes"))
	// No limits requested → no limit properties.
	for _, arg := range prefix {
		assert.NotContains(t, arg, "CPUQuota=")
		assert.NotContains(t, arg, "MemoryMax=")
	}

	prefix, _, err = buildCgroupPrefix(Cgroup{Enabled: true, CPULimit: "1.5", MemoryLimit: "512m"}, nil)
	require.NoError(t, err)
	assert.True(t, containsSeq(prefix, "--property", "CPUQuota=150%"))
	assert.True(t, containsSeq(prefix, "--property", "MemoryMax=512M"))
	assert.Equal(t, "--", prefix[len(prefix)-1])
}

func TestBuildCgroupPrefixInvalidLimits(t *testing.T) {
	if _, err := exec.LookPath("systemd-run"); err != nil {
		t.Skip("systemd-run not in PATH")
	}
	withSessionBus(t)

	_, _, err := buildCgroupPrefix(Cgroup{Enabled: true, CPULimit: "half"}, nil)
	assert.ErrorContains(t, err, "invalid CPU limit")

	_, _, err = buildCgroupPrefix(Cgroup{Enabled: true, MemoryLimit: "512MB"}, nil)
	assert.ErrorContains(t, err, "invalid memory limit")
}
