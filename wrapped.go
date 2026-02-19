// Package wrapped runs a program in a sandbox using bubblewrap.
package wrapped

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

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

func Wrapped(program string, arguments []string, network, mountCurrentDir, mountCurrentDirWritable bool,
	mountReadonly, mountWritable, extraEnv []string, workdir, apparmor string, allowedHosts []string,
	allowAllHosts bool, deniedHosts []string, networkLogFile string) error {
	if len(allowedHosts) > 0 {
		return wrappedFiltered(program, arguments, mountCurrentDir, mountCurrentDirWritable, mountReadonly, mountWritable,
			extraEnv, workdir, apparmor, allowListFilter(allowedHosts), networkLogFile)
	}
	if allowAllHosts {
		return wrappedFiltered(program, arguments, mountCurrentDir, mountCurrentDirWritable, mountReadonly, mountWritable,
			extraEnv, workdir, apparmor, denyListFilter(deniedHosts), networkLogFile)
	}

	if networkLogFile != "" {
		return fmt.Errorf("--network-log requires --allow-host or --allow-all-hosts")
	}

	bwrapArgs, err := buildBwrapArgs(program, arguments, network, mountCurrentDir, mountCurrentDirWritable,
		mountReadonly, mountWritable, extraEnv, workdir, apparmor, nil)
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

func wrappedFiltered(program string, arguments []string, mountCurrentDir, mountCurrentDirWritable bool,
	mountReadonly, mountWritable, extraEnv []string, workdir, apparmor string, filter hostFilter, networkLogFile string) error {
	// Check socat is available.
	if _, err := exec.LookPath("socat"); err != nil {
		return fmt.Errorf("socat is required for filtered network access: %w", err)
	}

	// Set up network logger if requested.
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
	httpBridge := exec.Command("socat",
		fmt.Sprintf("UNIX-LISTEN:%s,fork,reuseaddr", httpSock),
		fmt.Sprintf("TCP:127.0.0.1:%d", httpPort))
	if err := httpBridge.Start(); err != nil {
		return fmt.Errorf("failed to start HTTP socat bridge: %w", err)
	}
	defer httpBridge.Process.Kill()

	socksBridge := exec.Command("socat",
		fmt.Sprintf("UNIX-LISTEN:%s,fork,reuseaddr", socksSock),
		fmt.Sprintf("TCP:127.0.0.1:%d", socksPort))
	if err := socksBridge.Start(); err != nil {
		return fmt.Errorf("failed to start SOCKS5 socat bridge: %w", err)
	}
	defer socksBridge.Process.Kill()

	// Build bwrap args with filtered network config.
	filterConfig := &filteredNetConfig{
		httpSock:  httpSock,
		socksSock: socksSock,
	}
	bwrapArgs, err := buildBwrapArgs(program, arguments, false, mountCurrentDir, mountCurrentDirWritable,
		mountReadonly, mountWritable, extraEnv, workdir, apparmor, filterConfig)
	if err != nil {
		return err
	}

	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		return fmt.Errorf("failed to find bwrap: %w", err)
	}

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
			os.Exit(exitErr.ExitCode())
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

func buildBwrapArgs(program string, arguments []string, network, mountCurrentDir, mountCurrentDirWritable bool,
	mountReadonly, mountWritable, extraEnv []string, workdir, apparmor string, filterCfg *filteredNetConfig) ([]string, error) {
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

	resolvedProgram, err := resolveProgram(program)
	if err != nil {
		return nil, err
	}
	programDir := filepath.Dir(resolvedProgram)

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

		if programDir != cwd {
			args = append(args, "--ro-bind", programDir, programDir)
		}
	} else if workdir != "" {
		args = append(args, "--chdir", workdir)
	}

	if !strings.HasPrefix(programDir, "/usr") &&
		!strings.HasPrefix(programDir, "/bin") &&
		!strings.HasPrefix(programDir, "/sbin") &&
		!(mountCurrentDir && cwd == programDir) {
		args = append(args, "--ro-bind", programDir, programDir)
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

	if filterCfg != nil {
		// Filtered network: isolated network namespace with proxy access via Unix sockets.
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

		// Wrap the program invocation with socat bridges inside the sandbox.
		shellCmd := fmt.Sprintf(
			"socat TCP-LISTEN:3128,fork,reuseaddr UNIX-CONNECT:%s >/dev/null 2>&1 & "+
				"socat TCP-LISTEN:1080,fork,reuseaddr UNIX-CONNECT:%s >/dev/null 2>&1 & "+
				"exec ",
			filterCfg.httpSock, filterCfg.socksSock)

		if apparmor != "" {
			shellCmd += fmt.Sprintf("aa-exec -p %s -- ", apparmor)
		}
		shellCmd += `"$0" "$@"`

		args = append(args, "sh", "-c", shellCmd, resolvedProgram)
		args = append(args, arguments...)
	} else {
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
	}

	return args, nil
}
