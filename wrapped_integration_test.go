package wrapped

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requireBwrap skips the test if bwrap is not available or if unprivileged user
// namespaces are not functional on this system.
func requireBwrap(t *testing.T) string {
	t.Helper()
	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		t.Skip("bwrap not in PATH; skipping integration test")
	}
	// Probe: a minimal sandbox to verify user namespaces actually work.
	probe := exec.Command(bwrapPath,
		"--ro-bind", "/usr", "/usr",
		"--proc", "/proc",
		"--dev", "/dev",
		"--unshare-user",
		"--unshare-pid",
		"/usr/bin/true",
	)
	if err := probe.Run(); err != nil {
		t.Skipf("bwrap not functional (user namespaces may be disabled): %v", err)
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
	return buf.String(), cmd.Run()
}

func TestIntegrationTrueExitsZero(t *testing.T) {
	bwrapPath := requireBwrap(t)
	_, err := runInSandbox(t, bwrapPath, "/usr/bin/true", nil, false, false, false, nil, nil, nil)
	assert.NoError(t, err, "expected exit 0")
}

func TestIntegrationFalseExitsNonZero(t *testing.T) {
	bwrapPath := requireBwrap(t)
	_, err := runInSandbox(t, bwrapPath, "/usr/bin/false", nil, false, false, false, nil, nil, nil)
	require.Error(t, err, "expected non-zero exit from /usr/bin/false")
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	assert.Equal(t, 1, exitErr.ExitCode())
}

func TestIntegrationStdout(t *testing.T) {
	bwrapPath := requireBwrap(t)
	out, err := runInSandbox(t, bwrapPath, "/usr/bin/echo", []string{"hello", "world"}, false, false, false, nil, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "hello world", strings.TrimSpace(out))
}

func TestIntegrationExtraEnv(t *testing.T) {
	bwrapPath := requireBwrap(t)
	out, err := runInSandbox(t, bwrapPath, "/usr/bin/sh", []string{"-c", "echo $MYVAR"},
		false, false, false, nil, nil, []string{"MYVAR=integration-test-value"})
	require.NoError(t, err)
	assert.Equal(t, "integration-test-value", strings.TrimSpace(out))
}

func TestIntegrationReadonlyMount(t *testing.T) {
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
	bwrapPath := requireBwrap(t)
	_ = requirePasta(t)

	bwrapArgs, err := buildBaseBwrapArgs(false, false, nil, nil, nil, nil, "", false, "/usr/bin/true", nil, false)
	require.NoError(t, err)
	bwrapArgs = append(bwrapArgs,
		"--uid", "1000",
		"--gid", "1000",
		"/usr/bin/true",
	)

	pastaArgs, err := buildPastaArgs(bwrapPath, bwrapArgs, nil, nil)
	require.NoError(t, err)

	pastaPath, _ := exec.LookPath("pasta")
	cmd := exec.Command(pastaPath, pastaArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	assert.NoError(t, err, "pasta+bwrap run failed")
}
