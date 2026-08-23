package wrapped

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requireIntegration skips the test under -short. Every test in this file runs real
// programs — bwrap, pasta, nft, systemd-run, a shell — and sends real signals, which a
// machine that confines the test runner may well refuse. `go test -short ./...` is
// therefore the way to run the unit tests on their own, and every test here must call
// this first.
func requireIntegration(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
}

// requireBwrap skips the test if bwrap is not available or if unprivileged user
// namespaces are not functional on this system.
func requireBwrap(t *testing.T) string {
	t.Helper()
	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		t.Skip("bwrap not in PATH; skipping integration test")
	}
	// Probe: run a trivial program through the same argument builder the real
	// sandbox uses, so the probe cannot drift from it. A hand-written probe that
	// binds only /usr fails on every system, because the ELF interpreter path
	// (/lib64/ld-linux-x86-64.so.2) is absolute and needs the /lib64 symlink that
	// buildBaseBwrapArgs sets up — which looks identical to "namespaces are
	// disabled" and silently skips every integration test.
	args, err := buildBwrapArgs("/usr/bin/true", nil, false, false, false, nil, nil, nil, nil, "", "", false, nil, false)
	if err != nil {
		t.Skipf("cannot build bwrap arguments: %v", err)
	}
	out, err := exec.Command(bwrapPath, args...).CombinedOutput()
	if err != nil {
		t.Skipf("bwrap not functional (user namespaces may be disabled): %v: %s", err, out)
	}
	return bwrapPath
}

// requirePasta skips the test if pasta is not available or not functional
// (it needs to create a user and network namespace, which CI images may forbid).
func requirePasta(t *testing.T) string {
	t.Helper()
	pastaPath, err := exec.LookPath("pasta")
	if err != nil {
		t.Skip("pasta not in PATH; skipping integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	probe := exec.CommandContext(ctx, pastaPath,
		"--config-net", "-t", "none", "-u", "none", "-T", "none", "-U", "none",
		"--", "/usr/bin/true",
	)
	if out, err := probe.CombinedOutput(); err != nil {
		t.Skipf("pasta not functional (namespaces may be restricted): %v: %s", err, out)
	}
	return pastaPath
}

// requireSystemdRun skips the test if systemd-run cannot create a transient user
// scope, which needs a systemd user session with a reachable session bus.
func requireSystemdRun(t *testing.T) string {
	t.Helper()
	systemdRunPath, err := exec.LookPath("systemd-run")
	if err != nil {
		t.Skip("systemd-run not in PATH; skipping integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	probe := exec.CommandContext(ctx, systemdRunPath,
		"--user", "--scope", "--quiet", "--collect", "--", "/usr/bin/true")
	if out, err := probe.CombinedOutput(); err != nil {
		t.Skipf("systemd-run cannot create a user scope: %v: %s", err, out)
	}
	return systemdRunPath
}

// requireNft skips the test if nft is not available.
func requireNft(t *testing.T) string {
	t.Helper()
	nftPath, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("nft not in PATH; skipping integration test")
	}
	return nftPath
}

// requireTool skips the test if the named program is not in PATH.
func requireTool(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s not in PATH; skipping integration test", name)
	}
	return path
}

// requireSignals skips the test if this process cannot signal a process group of its
// own. Everything about terminating the sandbox rests on being able to, and some
// restricted sandboxes and container runtimes refuse it — where they do, a test that
// cannot kill anything says nothing about whether wrapped can.
func requireSignals(t *testing.T) {
	t.Helper()
	sleepPath := requireTool(t, "sleep")
	probe := exec.Command(sleepPath, "1")
	probe.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	require.NoError(t, probe.Start())
	err := syscall.Kill(-probe.Process.Pid, syscall.SIGKILL)
	// The probe exits on its own shortly, so waiting for it is safe either way.
	_ = probe.Wait()
	if err != nil {
		t.Skipf("cannot signal a process group here: %v", err)
	}
}

// requireInternet skips the test if the host cannot reach the public internet,
// which the filtered-network tests need in order to be meaningful.
func requireInternet(t *testing.T) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", "example.com:443", 15*time.Second)
	if err != nil {
		t.Skipf("no internet connectivity: %v", err)
	}
	conn.Close()
}

var (
	buildOnce   sync.Once
	builtBin    string
	builtBinDir string
	buildErr    error
	// repoDir is the package directory, captured before any test can change
	// the working directory, so the build below does not depend on the cwd.
	repoDir string
)

// buildWrappedBinary builds the wrapped CLI once per test run and returns its path.
// The filtered-network code path re-execs the running binary, so these tests need a
// real wrapped executable rather than just the library.
func buildWrappedBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		builtBinDir, buildErr = os.MkdirTemp("", "wrapped-itest-*")
		if buildErr != nil {
			return
		}
		builtBin = filepath.Join(builtBinDir, "wrapped")
		build := exec.Command("go", "build", "-tags", "netgo", "-o", builtBin, "./cmd/wrapped")
		build.Dir = repoDir
		out, err := build.CombinedOutput()
		if err != nil {
			buildErr = fmt.Errorf("go build ./cmd/wrapped: %w: %s", err, out)
		}
	})
	require.NoError(t, buildErr)
	return builtBin
}

func TestMain(m *testing.M) {
	// The code under test re-execs os.Executable to reach its internal helpers, which
	// under test is this binary. Answering to them here lets the tests exercise the
	// helpers rather than watching the test binary choke on their arguments.
	if handled, err := RunInternalCommand(os.Args[1:]); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	var err error
	repoDir, err = os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to get working directory:", err)
		os.Exit(1)
	}
	code := m.Run()
	if builtBinDir != "" {
		_ = os.RemoveAll(builtBinDir)
	}
	os.Exit(code)
}

// stubNft writes a fake nft into a fresh directory. The fake records its arguments
// in "args" and its stdin in "stdin", then exits with exitCode. Callers put the
// returned directory first on the child's PATH.
func stubNft(t *testing.T, exitCode int) string {
	t.Helper()
	dir := t.TempDir()
	script := fmt.Sprintf("#!/bin/sh\necho \"$@\" > %s\ncat > %s\nexit %d\n",
		filepath.Join(dir, "args"), filepath.Join(dir, "stdin"), exitCode)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0o755))
	return dir
}

// envWithPathPrefix returns the current environment with dir prepended to PATH.
func envWithPathPrefix(dir string) []string {
	return append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// TestIntegrationNftExecPassesArgumentsVerbatim checks that the internal helper hands
// the ruleset to nft unchanged and execs the target command with its arguments intact,
// including characters that would have needed quoting when this went through a shell.
func TestIntegrationNftExecPassesArgumentsVerbatim(t *testing.T) {
	requireIntegration(t)
	bin := buildWrappedBinary(t)
	stubDir := stubNft(t, 0)
	echoPath := requireTool(t, "echo")

	ruleset := "table inet filter {\n\tchain output {\n\t\tip daddr { 1.2.3.4 } accept\n\t}\n}\n"
	awkward := []string{"plain", "with space", "quote'and$dollar", "semi;colon", "new\nline"}

	cmd := exec.Command(bin, append([]string{internalNftExecArg, ruleset, echoPath}, awkward...)...)
	cmd.Env = envWithPathPrefix(stubDir)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	require.NoError(t, cmd.Run(), "stderr: %s", stderr.String())

	assert.Equal(t, strings.Join(awkward, " "), strings.TrimSpace(stdout.String()))

	gotRuleset, err := os.ReadFile(filepath.Join(stubDir, "stdin"))
	require.NoError(t, err, "nft was not invoked")
	assert.Equal(t, ruleset, string(gotRuleset), "ruleset must reach nft unchanged")

	gotArgs, err := os.ReadFile(filepath.Join(stubDir, "args"))
	require.NoError(t, err)
	assert.Equal(t, "-f /dev/stdin", strings.TrimSpace(string(gotArgs)))
}

// TestIntegrationNftExecFailsClosed checks that the target command is never executed
// when applying the nftables rules fails. Failing open here would silently downgrade
// --network filtered to an unfiltered network.
func TestIntegrationNftExecFailsClosed(t *testing.T) {
	requireIntegration(t)
	bin := buildWrappedBinary(t)
	stubDir := stubNft(t, 1)
	shPath := requireTool(t, "sh")

	marker := filepath.Join(t.TempDir(), "marker")
	cmd := exec.Command(bin, internalNftExecArg, "bogus ruleset", shPath, "-c", "touch "+marker)
	cmd.Env = envWithPathPrefix(stubDir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	require.Error(t, err, "wrapped must fail when nft fails")
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	assert.NotEqual(t, 0, exitErr.ExitCode())
	assert.Contains(t, stderr.String(), "failed to apply nftables rules")
	assert.NoFileExists(t, marker, "the sandboxed command must not run when nft fails")
}

// runFiltered runs the wrapped CLI in filtered-network mode and returns its stdout.
func runFiltered(t *testing.T, bin string, wrappedArgs, programArgs []string) (string, error) {
	t.Helper()
	args := append(append([]string{}, wrappedArgs...), "--")
	args = append(args, programArgs...)
	cmd := exec.Command(bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	t.Logf("wrapped %s\nstdout: %s\nstderr: %s", strings.Join(args, " "), stdout.String(), stderr.String())
	return stdout.String(), err
}

// curlStatusArgs builds a curl invocation that prints just the HTTP status code.
func curlStatusArgs(curlPath, url string) []string {
	return []string{curlPath, "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "30", url}
}

// TestIntegrationFilteredNetworkAllowsAllowedHost exercises the real re-exec path:
// pasta creates the namespace, wrapped re-execs itself to apply the nftables rules,
// and the allowed host must still be reachable.
func TestIntegrationFilteredNetworkAllowsAllowedHost(t *testing.T) {
	requireIntegration(t)
	bin := buildWrappedBinary(t)
	requireBwrap(t)
	requirePasta(t)
	requireNft(t)
	requireInternet(t)
	curlPath := requireTool(t, "curl")

	out, err := runFiltered(t, bin,
		[]string{"--only-network", "--allow-host", "example.com"},
		curlStatusArgs(curlPath, "https://example.com/"))
	require.NoError(t, err, "allowed host should be reachable")
	assert.Equal(t, "200", strings.TrimSpace(out))
}

// TestIntegrationFilteredNetworkBlocksOtherHosts checks that the rules actually filter:
// an address that is not among the allowed hosts must be unreachable. A literal IP is
// used so the attempt does not depend on DNS.
func TestIntegrationFilteredNetworkBlocksOtherHosts(t *testing.T) {
	requireIntegration(t)
	bin := buildWrappedBinary(t)
	requireBwrap(t)
	requirePasta(t)
	requireNft(t)
	requireInternet(t)
	curlPath := requireTool(t, "curl")

	_, err := runFiltered(t, bin,
		[]string{"--only-network", "--allow-host", "example.com"},
		[]string{curlPath, "-sS", "-o", "/dev/null", "--max-time", "15", "https://1.1.1.1/"})
	assert.Error(t, err, "a host outside the allowlist must be unreachable")
}

// TestIntegrationFilteredNetworkFullSandbox runs the same check through the full
// filesystem sandbox rather than --only-network, since that path builds a much
// longer bwrap argument list for the re-exec to carry.
func TestIntegrationFilteredNetworkFullSandbox(t *testing.T) {
	requireIntegration(t)
	bin := buildWrappedBinary(t)
	requireBwrap(t)
	requirePasta(t)
	requireNft(t)
	requireInternet(t)
	curlPath := requireTool(t, "curl")

	out, err := runFiltered(t, bin,
		[]string{"--allow-host", "example.com"},
		curlStatusArgs(curlPath, "https://example.com/"))
	require.NoError(t, err, "allowed host should be reachable in the full sandbox")
	assert.Equal(t, "200", strings.TrimSpace(out))
}

// runInSandbox builds bwrap args for the given program and runs it as a
// subprocess, returning combined stdout+stderr output and the run error.
func runInSandbox(t *testing.T, bwrapPath, program string, arguments []string,
	network, mountCurrentDir, mountCurrentDirWritable bool,
	mountReadonly, mountWritable []string, extraEnv []string) (string, error) {
	t.Helper()
	args, err := buildBwrapArgs(program, arguments, network,
		mountCurrentDir, mountCurrentDirWritable,
		mountReadonly, mountWritable, nil, extraEnv, "", "", false, nil, false)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	cmd := exec.Command(bwrapPath, args...)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	// Run before reading the buffer. "return buf.String(), cmd.Run()" would not do
	// that: a return statement evaluates its operands left to right, so the buffer
	// would be read before the process had even started, and every caller would see
	// empty output together with a nil error.
	err = cmd.Run()
	return buf.String(), err
}

func TestIntegrationTrueExitsZero(t *testing.T) {
	requireIntegration(t)
	bwrapPath := requireBwrap(t)
	_, err := runInSandbox(t, bwrapPath, "/usr/bin/true", nil, false, false, false, nil, nil, nil)
	assert.NoError(t, err, "expected exit 0")
}

func TestIntegrationFalseExitsNonZero(t *testing.T) {
	requireIntegration(t)
	bwrapPath := requireBwrap(t)
	_, err := runInSandbox(t, bwrapPath, "/usr/bin/false", nil, false, false, false, nil, nil, nil)
	require.Error(t, err, "expected non-zero exit from /usr/bin/false")
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	assert.Equal(t, 1, exitErr.ExitCode())
}

func TestIntegrationStdout(t *testing.T) {
	requireIntegration(t)
	bwrapPath := requireBwrap(t)
	out, err := runInSandbox(t, bwrapPath, "/usr/bin/echo", []string{"hello", "world"}, false, false, false, nil, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "hello world", strings.TrimSpace(out))
}

func TestIntegrationExtraEnv(t *testing.T) {
	requireIntegration(t)
	bwrapPath := requireBwrap(t)
	out, err := runInSandbox(t, bwrapPath, "/usr/bin/sh", []string{"-c", "echo $MYVAR"},
		false, false, false, nil, nil, []string{"MYVAR=integration-test-value"})
	require.NoError(t, err)
	assert.Equal(t, "integration-test-value", strings.TrimSpace(out))
}

func TestIntegrationReadonlyMount(t *testing.T) {
	requireIntegration(t)
	bwrapPath := requireBwrap(t)

	dir := t.TempDir()
	testFile := filepath.Join(dir, "data.txt")
	err := os.WriteFile(testFile, []byte("mount-test-content"), 0o644)
	require.NoError(t, err)

	out, err := runInSandbox(t, bwrapPath, "/usr/bin/cat", []string{testFile},
		false, false, false, []string{dir}, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "mount-test-content", out)
}

func TestIntegrationWritableMount(t *testing.T) {
	requireIntegration(t)
	bwrapPath := requireBwrap(t)

	dir := t.TempDir()
	outFile := filepath.Join(dir, "output.txt")

	_, err := runInSandbox(t, bwrapPath, "/usr/bin/sh",
		[]string{"-c", "echo written > " + outFile},
		false, false, false, nil, []string{dir}, nil)
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err, "output file not created")
	assert.Contains(t, string(data), "written")
}

func TestIntegrationFilesystemIsolation(t *testing.T) {
	requireIntegration(t)
	bwrapPath := requireBwrap(t)

	// /usr must be accessible.
	_, err := runInSandbox(t, bwrapPath, "/usr/bin/test", []string{"-d", "/usr"},
		false, false, false, nil, nil, nil)
	assert.NoError(t, err, "/usr should be accessible in sandbox")

	// /root must not be accessible (not mounted).
	_, err = runInSandbox(t, bwrapPath, "/usr/bin/test", []string{"-d", "/root"},
		false, false, false, nil, nil, nil)
	assert.Error(t, err, "/root should not be accessible in sandbox")
}

func TestIntegrationNetworkIsolation(t *testing.T) {
	requireIntegration(t)
	bwrapPath := requireBwrap(t)

	// With no-network, loopback should exist but external interfaces should not.
	out, err := runInSandbox(t, bwrapPath, "/usr/bin/sh",
		[]string{"-c", "ip link show 2>/dev/null | grep -v lo || true"},
		false, false, false, nil, nil, nil)
	if err != nil {
		t.Skipf("ip command not available: %v", err)
	}
	// Only the loopback interface should be present; no eth0/ens* etc.
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// ip link output for non-loopback interfaces contains the interface name.
		// If any non-loopback interface appears, network isolation failed.
		assert.Fail(t, "unexpected network interface visible in sandbox", "interface: %q", line)
	}
}

func TestIntegrationCurrentDirMount(t *testing.T) {
	requireIntegration(t)
	bwrapPath := requireBwrap(t)

	// Create a temp dir that is NOT under HOME, to avoid the home-dir check.
	dir, err := os.MkdirTemp("/tmp", "wrapped-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	testFile := filepath.Join(dir, "cwd-file.txt")
	err = os.WriteFile(testFile, []byte("cwd-content"), 0o644)
	require.NoError(t, err)

	// Change to the temp dir so mountCurrentDir mounts it.
	orig, err := os.Getwd()
	require.NoError(t, err)
	err = os.Chdir(dir)
	require.NoError(t, err)
	defer os.Chdir(orig)

	out, err := runInSandbox(t, bwrapPath, "/usr/bin/cat", []string{testFile},
		false, true, false, nil, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "cwd-content", out)
}

func TestIntegrationPastaBasic(t *testing.T) {
	requireIntegration(t)
	bwrapPath := requireBwrap(t)
	_ = requirePasta(t)

	bwrapArgs, err := buildBaseBwrapArgs(false, false, nil, nil, nil, nil, "", false, "/usr/bin/true", nil, false)
	require.NoError(t, err)
	// The real code uses the current UID/GID here. Hard-coding 1000 only works
	// where the user happens to be uid 1000; elsewhere (CI runners typically run
	// as uid 1001) it is an unmapped id inside pasta's user namespace and bwrap
	// refuses to start.
	bwrapArgs = append(bwrapArgs,
		"--uid", strconv.Itoa(os.Getuid()),
		"--gid", strconv.Itoa(os.Getgid()),
		"/usr/bin/true",
	)

	pastaArgs, err := buildPastaArgs(bwrapPath, bwrapArgs, nil, nil)
	require.NoError(t, err)

	pastaPath, _ := exec.LookPath("pasta")
	cmd := exec.Command(pastaPath, pastaArgs...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err = cmd.Run()
	assert.NoError(t, err, "pasta+bwrap run failed: %s", out.String())
}

// startSandboxReportingCgroup runs the wrapped CLI with the given flags on a program
// that reports its own cgroup and then blocks, so that the test can inspect that
// cgroup on the host while the sandbox is still alive, and see which cgroup the
// program ended up in. It returns the cgroup path and a function that releases the
// sandboxed program. Anything in env is added to the environment of the wrapped
// process itself.
func startSandboxReportingCgroup(t *testing.T, env []string, flags ...string) (string, func()) {
	t.Helper()
	requireBwrap(t)
	bin := buildWrappedBinary(t)
	shPath := requireTool(t, "sh")

	args := append(append([]string{}, flags...), "--", shPath, "-c",
		"cut -d: -f3 /proc/self/cgroup; read _")
	cmd := exec.Command(bin, args...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start(), "wrapped %s", strings.Join(args, " "))

	release := func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	}
	t.Cleanup(release)

	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		release()
		t.Fatalf("sandboxed program did not report its cgroup: %v", err)
	}
	return strings.TrimSpace(line), release
}

// inWrappedScope reports whether a cgroup path is one of the transient scopes wrapped
// creates, which scopeUnitName names after wrapped itself. Some other scope — the
// login session's, or the terminal application's — is one the sandbox merely inherited.
func inWrappedScope(cgroupPath string) bool {
	return strings.HasPrefix(filepath.Base(cgroupPath), "wrapped-") &&
		strings.HasSuffix(cgroupPath, ".scope")
}

// startCgroupSandbox is startSandboxReportingCgroup for the runs that must end up in a
// transient scope of wrapped's making.
func startCgroupSandbox(t *testing.T, flags ...string) (string, func()) {
	t.Helper()
	requireSystemdRun(t)
	cgroupPath, release := startSandboxReportingCgroup(t, nil, flags...)
	require.True(t, inWrappedScope(cgroupPath),
		"expected the program to run in a transient scope of its own, got %q", cgroupPath)
	return cgroupPath, release
}

// lookupCgroupFile reads a control file from the given cgroup, reporting whether it
// exists. A control file is present only where its controller is enabled for that
// cgroup, which for cpu.max means a CPU limit was set.
func lookupCgroupFile(t *testing.T, cgroupPath, name string) (string, bool) {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", cgroupPath, name))
	if os.IsNotExist(err) {
		return "", false
	}
	require.NoError(t, err)
	return strings.TrimSpace(string(content)), true
}

// readCgroupFile reads a control file that the run under test must have produced,
// skipping the test if it is absent because that controller is not delegated to
// this user rather than because wrapped failed to ask for it.
func readCgroupFile(t *testing.T, cgroupPath, name string) string {
	t.Helper()
	content, ok := lookupCgroupFile(t, cgroupPath, name)
	if !ok {
		t.Skipf("%s is absent in %s; the controller is not delegated to this user", name, cgroupPath)
	}
	return content
}

// cpuMaxQuota splits the "<quota> <period>" contents of cpu.max. The quota is
// returned verbatim, since it is "max" when the CPU time is unlimited.
func cpuMaxQuota(t *testing.T, cpuMax string) (string, int) {
	t.Helper()
	quota, periodStr, ok := strings.Cut(cpuMax, " ")
	require.True(t, ok, "unexpected cpu.max contents %q", cpuMax)
	period, err := strconv.Atoi(periodStr)
	require.NoError(t, err, "unexpected cpu.max contents %q", cpuMax)
	return quota, period
}

// fakeSystemdRun puts a systemd-run that fails, and nothing else bar a real "true",
// on PATH, and gives the bus check an address to be satisfied by, so that the only
// thing left to fail is running systemd-run itself. That is the AT_SECURE failure of
// an AppArmor profile with an uppercase exec mode, which no amount of inspection
// beforehand can predict.
func fakeSystemdRun(t *testing.T) {
	t.Helper()
	truePath := requireTool(t, "true")
	requireTool(t, "sh")

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "systemd-run"),
		[]byte("#!/bin/sh\necho 'Failed to connect to bus: No medium found' >&2\nexit 1\n"), 0o755))
	require.NoError(t, os.Symlink(truePath, filepath.Join(dir, "true")))

	t.Setenv("PATH", dir)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+filepath.Join(dir, "bus"))
}

// TestIntegrationCgroupDegradesWhenSystemdRunFails checks that auto mode falls back
// when systemd-run fails at the point of use rather than being absent, which is what
// the probe is there to catch.
func TestIntegrationCgroupDegradesWhenSystemdRunFails(t *testing.T) {
	requireIntegration(t)
	fakeSystemdRun(t)

	prefix, env, err := resolveCgroupPrefix(Cgroup{}, []string{"FOO=bar"}, "wrapped-test.scope")
	require.NoError(t, err)
	assert.Empty(t, prefix, "a systemd-run that cannot create a scope must not be used")
	assert.Equal(t, []string{"FOO=bar"}, env)
}

// TestIntegrationCgroupRequiredDoesNotProbe checks that the probe is auto mode's alone.
// Required mode reports what happens when it runs the sandbox for real, and spending a
// round trip on predicting it would only slow the run down.
func TestIntegrationCgroupRequiredDoesNotProbe(t *testing.T) {
	requireIntegration(t)
	fakeSystemdRun(t)

	prefix, _, err := resolveCgroupPrefix(Cgroup{Mode: CgroupRequired}, nil, "wrapped-test.scope")
	require.NoError(t, err)
	require.NotEmpty(t, prefix)
	assert.Equal(t, "systemd-run", filepath.Base(prefix[0]))
}

// TestIntegrationCgroupByDefault checks that a run with no cgroup flag at all still
// puts the program in a cgroup of its own, which is what makes cgroup.kill available
// for taking the sandbox down without anyone having had to ask for it.
func TestIntegrationCgroupByDefault(t *testing.T) {
	requireIntegration(t)
	cgroupPath, _ := startCgroupSandbox(t)

	ownCgroup, err := os.ReadFile("/proc/self/cgroup")
	require.NoError(t, err)
	assert.NotContains(t, string(ownCgroup), cgroupPath,
		"the program must run in a cgroup of its own, not in wrapped's caller's")
}

// TestIntegrationNoCgroup checks that --no-cgroup runs the program without a cgroup of
// its own, leaving it wherever wrapped itself was.
func TestIntegrationNoCgroup(t *testing.T) {
	requireIntegration(t)
	cgroupPath, _ := startSandboxReportingCgroup(t, nil, "--no-cgroup")

	assert.False(t, inWrappedScope(cgroupPath),
		"--no-cgroup must not create a cgroup, got %q", cgroupPath)
}

// TestIntegrationCgroupDegradesWithoutSystemdRun checks that the default falls back to
// running without a cgroup where none can be created, rather than failing — a machine
// with no systemd, or a shell with no user session, must still be able to run wrapped.
// The fallback is provoked by a PATH with no systemd-run in it, since that is the one
// condition a test can arrange on a machine that does have a working systemd.
func TestIntegrationCgroupDegradesWithoutSystemdRun(t *testing.T) {
	requireIntegration(t)
	requireSystemdRun(t)

	// A PATH holding only what the run itself needs to find: bwrap, and the shell the
	// sandboxed program is. Everything else, systemd-run included, is out of reach.
	pathDir := t.TempDir()
	for _, tool := range []string{"bwrap", "sh"} {
		require.NoError(t, os.Symlink(requireTool(t, tool), filepath.Join(pathDir, tool)))
	}

	cgroupPath, _ := startSandboxReportingCgroup(t, []string{"PATH=" + pathDir})
	assert.False(t, inWrappedScope(cgroupPath),
		"expected the run to fall back to no cgroup, got %q", cgroupPath)
}

// TestIntegrationCgroupRequiredWithoutSystemdRun checks the other half of the same
// story: --cgroup asks for a cgroup outright, so a run that cannot have one fails
// instead of quietly going without.
func TestIntegrationCgroupRequiredWithoutSystemdRun(t *testing.T) {
	requireIntegration(t)
	requireBwrap(t)
	bin := buildWrappedBinary(t)
	shPath := requireTool(t, "sh")

	pathDir := t.TempDir()
	for _, tool := range []string{"bwrap", "sh"} {
		require.NoError(t, os.Symlink(requireTool(t, tool), filepath.Join(pathDir, tool)))
	}

	cmd := exec.Command(bin, "--cgroup", "--", shPath, "-c", "exit 0")
	cmd.Env = append(os.Environ(), "PATH="+pathDir)
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "--cgroup must fail where no cgroup can be created: %s", out)
	assert.Contains(t, string(out), "systemd-run is required to create a cgroup")
}

// TestIntegrationNoCgroupRejectsCgroupFlags checks that --no-cgroup and the flags that
// ask for a cgroup cannot be combined, since the two say opposite things.
func TestIntegrationNoCgroupRejectsCgroupFlags(t *testing.T) {
	requireIntegration(t)
	bin := buildWrappedBinary(t)

	for _, flags := range [][]string{
		{"--no-cgroup", "--cgroup"},
		{"--no-cgroup", "--cpu-limit", "1"},
		{"--no-cgroup", "--memory-limit", "512M"},
	} {
		args := append(append([]string{}, flags...), "--", "/usr/bin/true")
		out, err := exec.Command(bin, args...).CombinedOutput()
		assert.Error(t, err, "expected %v to be rejected: %s", flags, out)
		assert.Contains(t, string(out), "none of the others can be",
			"expected a mutual exclusion error for %v", flags)
	}
}

// TestIntegrationCgroupWithoutLimits checks that --cgroup on its own puts the program
// in a cgroup of its own, accounted for but with nothing limited.
func TestIntegrationCgroupWithoutLimits(t *testing.T) {
	requireIntegration(t)
	cgroupPath, _ := startCgroupSandbox(t, "--cgroup")

	ownCgroup, err := os.ReadFile("/proc/self/cgroup")
	require.NoError(t, err)
	assert.NotContains(t, string(ownCgroup), cgroupPath,
		"the program must run in a cgroup of its own, not in wrapped's caller's")

	// MemoryAccounting enables the memory controller, so these two are present.
	assert.Equal(t, "max", readCgroupFile(t, cgroupPath, "memory.max"),
		"--cgroup on its own must not limit memory")
	assert.FileExists(t, filepath.Join("/sys/fs/cgroup", cgroupPath, "memory.current"),
		"memory usage must be accounted for even with no limit set")

	// cpu.max is absent unless the cpu controller is enabled for the cgroup, and
	// systemd enables it for a CPU limit rather than for accounting, since cgroup v2
	// reports CPU usage in cpu.stat without that controller. Absent therefore means
	// unlimited here, exactly as an explicit "max" quota would.
	if cpuMax, ok := lookupCgroupFile(t, cgroupPath, "cpu.max"); ok {
		quota, _ := cpuMaxQuota(t, cpuMax)
		assert.Equal(t, "max", quota, "--cgroup on its own must not limit CPU time")
	}
}

// TestIntegrationCgroupLimits checks that the limit flags reach the control files of
// the cgroup the sandboxed program runs in.
func TestIntegrationCgroupLimits(t *testing.T) {
	requireIntegration(t)
	cgroupPath, _ := startCgroupSandbox(t, "--cpu-limit", "0.5", "--memory-limit", "64M")

	assert.Equal(t, strconv.Itoa(64*1024*1024), readCgroupFile(t, cgroupPath, "memory.max"))

	// cpu.max is "<quota> <period>" in microseconds; 0.5 CPUs is half the period.
	cpuMax := readCgroupFile(t, cgroupPath, "cpu.max")
	quotaStr, period := cpuMaxQuota(t, cpuMax)
	quota, err := strconv.Atoi(quotaStr)
	require.NoError(t, err, "unexpected cpu.max contents %q", cpuMax)
	assert.Equal(t, period, quota*2, "expected a quota of half the period in %q", cpuMax)
}

// waitForFile blocks until path exists, failing the test if it never does.
func waitForFile(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s never appeared", path)
}

// processesMatching returns the ids of the processes whose command line contains
// marker. Everything the sandbox consists of carries the marker, since wrapped hands
// the program's command line down to bwrap and pasta as arguments of their own, so an
// empty result means the whole sandbox is gone.
func processesMatching(t *testing.T, marker string) []int {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	require.NoError(t, err)
	var pids []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil {
			continue // Exited between the listing and the read, or is not ours.
		}
		if bytes.Contains(cmdline, []byte(marker)) {
			pids = append(pids, pid)
		}
	}
	return pids
}

// assertSandboxGone waits for every process carrying the marker to disappear.
func assertSandboxGone(t *testing.T, marker string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var left []int
	for time.Now().Before(deadline) {
		left = processesMatching(t, marker)
		if len(left) == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, pid := range left {
		cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		t.Logf("still running: %d %s", pid, bytes.ReplaceAll(cmdline, []byte{0}, []byte{' '}))
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
	t.Fatalf("%d process(es) of the sandbox outlived wrapped", len(left))
}

// startMarkedSandbox runs the wrapped CLI on a program that never exits, and returns
// the running command together with the marker that identifies every process of the
// sandbox. It returns once the sandboxed program is known to be running.
func startMarkedSandbox(t *testing.T, flags ...string) (*exec.Cmd, string) {
	t.Helper()
	requireSignals(t)
	requireBwrap(t)
	bin := buildWrappedBinary(t)
	shPath := requireTool(t, "sh")

	dir := t.TempDir()
	ready := filepath.Join(dir, "ready")
	marker := fmt.Sprintf("wrapped-liveness-%d-%d", os.Getpid(), time.Now().UnixNano())
	// The marker rides along in a comment, so that it shows up in the command line of
	// every process wrapped starts without changing what the program does.
	script := fmt.Sprintf("touch %s; while :; do sleep 1; done # %s", ready, marker)

	args := append(append([]string{}, flags...), "--mount-writable", dir, "--", shPath, "-c", script)
	cmd := exec.Command(bin, args...)
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start(), "wrapped %s", strings.Join(args, " "))
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		for _, pid := range processesMatching(t, marker) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})

	waitForFile(t, ready, 60*time.Second)
	require.NotEmpty(t, processesMatching(t, marker), "the sandbox should be running")
	return cmd, marker
}

// TestIntegrationSandboxDiesWhenWrappedIsTerminated checks that a sandboxed program
// that would otherwise run forever, and the bwrap processes around it, are gone once
// wrapped has been asked to stop.
func TestIntegrationSandboxDiesWhenWrappedIsTerminated(t *testing.T) {
	requireIntegration(t)
	cmd, marker := startMarkedSandbox(t)

	require.NoError(t, cmd.Process.Signal(syscall.SIGTERM))
	_ = cmd.Wait()

	assertSandboxGone(t, marker, 30*time.Second)
}

// TestIntegrationSandboxDiesWhenWrappedIsKilled checks the same for a wrapped that
// never got the chance to clean up after itself, which is what the reaper is for.
func TestIntegrationSandboxDiesWhenWrappedIsKilled(t *testing.T) {
	requireIntegration(t)
	cmd, marker := startMarkedSandbox(t)

	require.NoError(t, cmd.Process.Signal(syscall.SIGKILL))
	_ = cmd.Wait()

	assertSandboxGone(t, marker, 30*time.Second)
}

// TestIntegrationCgroupSandboxDiesWhenWrappedIsKilled checks that the cgroup lever
// works, on a sandbox whose processes a SIGKILLed wrapped can no longer reach any
// other way.
func TestIntegrationCgroupSandboxDiesWhenWrappedIsKilled(t *testing.T) {
	requireIntegration(t)
	requireSystemdRun(t)
	cmd, marker := startMarkedSandbox(t, "--cgroup")

	require.NoError(t, cmd.Process.Signal(syscall.SIGKILL))
	_ = cmd.Wait()

	assertSandboxGone(t, marker, 30*time.Second)
}

// TestIntegrationPastaSandboxDiesWhenWrappedIsKilled checks that pasta, which sits
// between wrapped and bwrap in bridge mode, is taken down along with the sandbox it
// serves rather than left behind holding a network namespace.
func TestIntegrationPastaSandboxDiesWhenWrappedIsKilled(t *testing.T) {
	requireIntegration(t)
	requirePasta(t)
	cmd, marker := startMarkedSandbox(t, "--network", "bridge")

	require.NoError(t, cmd.Process.Signal(syscall.SIGKILL))
	_ = cmd.Wait()

	assertSandboxGone(t, marker, 30*time.Second)
}

// startProcessGroup runs a shell that leaves a long sleep behind in a process group of
// its own, and returns the group's id, the group leader's start time and the id of the
// sleep. It is the smallest stand-in for a sandbox that needs neither bwrap nor
// namespaces, so the termination machinery can be tested wherever the tests run.
func startProcessGroup(t *testing.T) (pgid, startTime, sleeperPid int) {
	t.Helper()
	requireSignals(t)
	shPath := requireTool(t, "sh")
	requireTool(t, "sleep")

	cmd := exec.Command(shPath, "-c", "sleep 3600 & echo $!; wait")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
	})

	line, err := bufio.NewReader(stdout).ReadString('\n')
	require.NoError(t, err)
	sleeperPid, err = strconv.Atoi(strings.TrimSpace(line))
	require.NoError(t, err)

	pgid = cmd.Process.Pid
	startTime, err = processStartTime(pgid)
	require.NoError(t, err)
	return pgid, startTime, sleeperPid
}

// startTestReaper runs the reaper helper out of the test binary, which stands in for
// the wrapped binary here, and returns the write end of its pipe. Closing that write
// end is what wrapped's death looks like from the reaper's side.
func startTestReaper(t *testing.T, pgid, startTime int) *os.File {
	t.Helper()
	readEnd, writeEnd, err := os.Pipe()
	require.NoError(t, err)

	self, err := os.Executable()
	require.NoError(t, err)
	cmd := exec.Command(self, reapArg, strconv.Itoa(pgid), strconv.Itoa(startTime))
	cmd.ExtraFiles = []*os.File{readEnd}
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())
	require.NoError(t, readEnd.Close())

	t.Cleanup(func() {
		_ = writeEnd.Close()
		_ = cmd.Wait()
	})
	return writeEnd
}

// TestIntegrationReaperKillsProcessGroupOnEndOfFile checks that the reaper takes the
// sandbox's process group down as soon as wrapped lets go of the pipe.
func TestIntegrationReaperKillsProcessGroupOnEndOfFile(t *testing.T) {
	requireIntegration(t)
	pgid, startTime, sleeperPid := startProcessGroup(t)
	pipe := startTestReaper(t, pgid, startTime)

	// The reaper must wait for wrapped, not act on its own.
	time.Sleep(200 * time.Millisecond)
	assert.NoError(t, syscall.Kill(sleeperPid, 0), "the reaper must not act while wrapped is alive")

	require.NoError(t, pipe.Close())
	assertProcessGone(t, sleeperPid, 10*time.Second)
}

// TestIntegrationReaperSparesAReusedProcessGroupID checks that the reaper leaves a
// process group alone when its leader is not the process wrapped started, which is
// what a process id handed out again after the sandbox exited looks like.
func TestIntegrationReaperSparesAReusedProcessGroupID(t *testing.T) {
	requireIntegration(t)
	pgid, startTime, sleeperPid := startProcessGroup(t)
	pipe := startTestReaper(t, pgid, startTime+1)

	require.NoError(t, pipe.Close())
	time.Sleep(500 * time.Millisecond)
	assert.NoError(t, syscall.Kill(sleeperPid, 0),
		"a process group whose leader has been replaced is somebody else's")
}

// assertProcessGone waits for a process to stop running. A zombie counts as gone: the
// process is dead, only the entry its parent has not yet collected is left.
func assertProcessGone(t *testing.T, pid int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if os.IsNotExist(err) {
			return
		}
		// Field 3, the state, is the first one after the name in parentheses.
		if fields := strings.Fields(string(stat[bytes.LastIndexByte(stat, ')')+1:])); len(fields) > 0 && fields[0] == "Z" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("process %d is still running", pid)
}

// TestIntegrationRunSandboxLeavesNothingBehind checks the supervisor itself, on a
// stand-in sandbox that needs no namespaces: a program that exits while leaving a
// child of its own running must not leave that child running.
func TestIntegrationRunSandboxLeavesNothingBehind(t *testing.T) {
	requireIntegration(t)
	requireSignals(t)
	shPath := requireTool(t, "sh")
	requireTool(t, "sleep")

	pidFile := filepath.Join(t.TempDir(), "pid")
	err := runSandbox(shPath, []string{"-c", fmt.Sprintf("sleep 3600 & echo $! > %s", pidFile)}, Cgroup{})
	require.NoError(t, err)

	content, err := os.ReadFile(pidFile)
	require.NoError(t, err)
	orphan, err := strconv.Atoi(strings.TrimSpace(string(content)))
	require.NoError(t, err)

	assertProcessGone(t, orphan, 10*time.Second)
}

// TestIntegrationRunSandboxUsesItsOwnProcessGroup checks that the sandbox is put in a
// process group of its own, which is what lets wrapped signal all of it at once
// without signalling whoever ran wrapped.
func TestIntegrationRunSandboxUsesItsOwnProcessGroup(t *testing.T) {
	requireIntegration(t)
	shPath := requireTool(t, "sh")

	statFile := filepath.Join(t.TempDir(), "stat")
	err := runSandbox(shPath, []string{"-c", "cat /proc/self/stat > " + statFile}, Cgroup{})
	require.NoError(t, err)

	content, err := os.ReadFile(statFile)
	require.NoError(t, err)
	// Field 5 of /proc/<pid>/stat is the process group id; the fields are counted from
	// the last closing parenthesis, since the name in field 2 may contain them.
	fields := strings.Fields(string(content[bytes.LastIndexByte(content, ')')+1:]))
	require.Greater(t, len(fields), 5-3)
	pgid, err := strconv.Atoi(fields[5-3])
	require.NoError(t, err)

	assert.NotEqual(t, syscall.Getpgrp(), pgid, "the sandbox must not share wrapped's process group")
}

// TestIntegrationRunSandboxReportsExitCode checks that the sandboxed program's exit
// code reaches wrapped's caller, which it used to by virtue of wrapped exec'ing the
// sandbox and no longer does.
func TestIntegrationRunSandboxReportsExitCode(t *testing.T) {
	requireIntegration(t)
	shPath := requireTool(t, "sh")

	assert.NoError(t, runSandbox(shPath, []string{"-c", "exit 0"}, Cgroup{}))

	err := runSandbox(shPath, []string{"-c", "exit 3"}, Cgroup{})
	var exitErr *ExitError
	require.ErrorAs(t, err, &exitErr)
	assert.Equal(t, 3, exitErr.Code)
}

// TestIntegrationRunSandboxDoesNotLeakGoroutines checks that a finished run leaves
// nothing running inside wrapped either. Wrapped returns now rather than replacing the
// process with the sandbox, so a caller that runs one sandbox after another would
// accumulate the signal-forwarding goroutine and its channel once per run.
func TestIntegrationRunSandboxDoesNotLeakGoroutines(t *testing.T) {
	requireIntegration(t)
	shPath := requireTool(t, "sh")

	// A first run on its own, so that whatever the runtime and os/exec start along
	// the way is already up and does not count as growth.
	require.NoError(t, runSandbox(shPath, []string{"-c", "exit 0"}, Cgroup{}))
	before := runtime.NumGoroutine()

	const runs = 5
	for range runs {
		require.NoError(t, runSandbox(shPath, []string{"-c", "exit 0"}, Cgroup{}))
	}

	// os/exec may take a moment to finish with the reaper, so settle rather than
	// measure straight away; a real leak never settles.
	deadline := time.Now().Add(5 * time.Second)
	after := runtime.NumGoroutine()
	for after > before && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		after = runtime.NumGoroutine()
	}
	assert.LessOrEqual(t, after, before,
		"%d runs left %d goroutines behind", runs, after-before)
}

// TestIntegrationRunSandboxReportsSignalledExit checks that a sandboxed program killed
// by a signal — an out-of-memory kill, say — is reported as such rather than as a
// nondescript failure.
func TestIntegrationRunSandboxReportsSignalledExit(t *testing.T) {
	requireIntegration(t)
	requireSignals(t)
	shPath := requireTool(t, "sh")

	err := runSandbox(shPath, []string{"-c", "kill -KILL $$"}, Cgroup{})
	var exitErr *ExitError
	require.ErrorAs(t, err, &exitErr)
	assert.Equal(t, 128+int(syscall.SIGKILL), exitErr.Code)
}
