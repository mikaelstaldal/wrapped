// Package wrapped runs a program in a sandbox using bubblewrap.
package wrapped

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
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

func Wrapped(program string, arguments []string, network, mountCurrentDir, mountCurrentDirWritable bool, mountReadonly, mountWritable, extraEnv []string, workdir, apparmor string) error {
	bwrapArgs, err := buildBwrapArgs(program, arguments, network, mountCurrentDir, mountCurrentDirWritable, mountReadonly, mountWritable, extraEnv, workdir, apparmor)
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

func buildBwrapArgs(program string, arguments []string, network, mountCurrentDir, mountCurrentDirWritable bool, mountReadonly, mountWritable, extraEnv []string, workdir, apparmor string) ([]string, error) {
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
