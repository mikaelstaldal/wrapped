package wrapped

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

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

// requirePasta skips the test if pasta is not available.
func requirePasta(t *testing.T) string {
	t.Helper()
	pastaPath, err := exec.LookPath("pasta")
	if err != nil {
		t.Skip("pasta not in PATH; skipping integration test")
	}
	return pastaPath
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
