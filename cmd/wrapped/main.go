// wrapped - Run a program in a sandbox using bubblewrap.
package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"strings"
	"time"
	"wrapped"

	"github.com/spf13/cobra"
)

// Set via -ldflags at build time.
var version string

func main() {
	// wrapped re-execs itself for internal helper work — applying the nftables rules
	// inside pasta's namespace, and reaping the sandbox if wrapped is killed — so
	// handle that before interpreting the arguments as a normal sandbox invocation.
	if handled, err := wrapped.RunInternalCommand(os.Args[1:]); handled {
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	var (
		networkMode        string
		currentDir         bool
		currentDirWritable bool
		mounts             []string
		mountsWritable     []string
		envFlags           []string
		workdir            string
		apparmor           string
		allowedHosts       []string
		symlinks           []string
		tmpfs              []string
		networkSandboxOnly bool
		allEnv             bool
		exposeTCP          []string
		exposeUDP          []string
		unshareCgroup      bool
		cgroup             bool
		noCgroup           bool
		cpuLimit           string
		memoryLimit        string
	)

	versionStr := "dev"
	if version != "" {
		versionStr = version
	}
	info, ok := debug.ReadBuildInfo()
	if ok {
		settings := make(map[string]string, len(info.Settings))
		for _, s := range info.Settings {
			settings[s.Key] = s.Value
		}
		versionStr += " ("
		if vcs, ok := settings["vcs"]; ok {
			versionStr += vcs + " "
		}
		if rev, ok := settings["vcs.revision"]; ok {
			versionStr += "revision " + rev
		}
		modified := settings["vcs.modified"] == "true"
		if modified {
			versionStr += " (dirty)"
		}
		if t, ok := settings["vcs.time"]; ok {
			if parsedTime, err := time.Parse(time.RFC3339, t); err == nil {
				versionStr += " " + parsedTime.Local().Format("2006-01-02 15:04:05")
			} else {
				versionStr += " " + t
			}
		}
		versionStr += ")"
	}

	rootCmd := &cobra.Command{
		Version: versionStr,
		Use:     "wrapped [flags] program [arguments...]",
		Short:   "Run a program in a sandbox using Linux namespaces",
		Args:    cobra.MinimumNArgs(1),
		// Avoid printing usage/errors on every RunE error — we handle them in main().
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Validate --network mode value.
			switch networkMode {
			case wrapped.NetworkNone, wrapped.NetworkHost, wrapped.NetworkBridge, wrapped.NetworkFiltered:
			default:
				return fmt.Errorf("invalid --network mode %q: must be none, host, bridge, or filtered", networkMode)
			}

			// --allow-host implies --network filtered.
			if len(allowedHosts) > 0 {
				networkExplicit := cmd.Flags().Changed("network")
				if networkExplicit && networkMode != wrapped.NetworkFiltered {
					return fmt.Errorf("--allow-host requires --network filtered")
				}
				networkMode = wrapped.NetworkFiltered
			}

			if networkSandboxOnly {
				if networkMode == wrapped.NetworkNone {
					return fmt.Errorf("--only-network cannot be combined with --network none")
				}
				if networkMode == wrapped.NetworkHost {
					return fmt.Errorf("--only-network cannot be combined with --network host")
				}
			}

			if (len(exposeTCP) > 0 || len(exposeUDP) > 0) && networkMode != wrapped.NetworkBridge {
				return fmt.Errorf("--expose-tcp and --expose-udp can only be used with --network bridge")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var wrappedSymlinks []wrapped.Symlink
			for _, s := range symlinks {
				dest, src, ok := strings.Cut(s, "=")
				if !ok {
					return fmt.Errorf("invalid --symlink %q: must be DEST=SRC", s)
				}
				wrappedSymlinks = append(wrappedSymlinks, wrapped.Symlink{Src: src, Dest: dest})
			}

			return wrapped.Wrapped(
				args[0],
				args[1:],
				networkMode,
				currentDir || currentDirWritable,
				currentDirWritable,
				mounts,
				mountsWritable,
				wrappedSymlinks,
				envFlags,
				workdir,
				apparmor,
				allowedHosts,
				networkSandboxOnly,
				allEnv,
				tmpfs,
				exposeTCP,
				exposeUDP,
				unshareCgroup,
				wrapped.Cgroup{
					Mode:        cgroupMode(cgroup, noCgroup),
					CPULimit:    cpuLimit,
					MemoryLimit: memoryLimit,
				},
			)
		},
	}

	f := rootCmd.Flags()
	f.StringVar(&networkMode, "network", "none", "Network mode: none (isolated), host (unrestricted), bridge (sandboxed via pasta), filtered (bridge + nftables allowlist)")
	f.StringArrayVar(&exposeTCP, "expose-tcp", nil, "Expose TCP port from sandbox to host (bridge mode only, can be repeated)")
	f.StringArrayVar(&exposeUDP, "expose-udp", nil, "Expose UDP port from sandbox to host (bridge mode only, can be repeated)")
	f.StringArrayVar(&allowedHosts, "allow-host", nil, "Allow network access to specific host (can be repeated, implies --network filtered)")
	f.BoolVar(&currentDir, "current-dir", false, "Mount the current directory")
	f.BoolVar(&currentDirWritable, "current-dir-writable", false, "Mount the current directory writable")
	f.StringArrayVar(&mounts, "mount", nil, "Mount additional directory read-only")
	f.StringArrayVar(&mountsWritable, "mount-writable", nil, "Mount additional directory writable")
	f.StringArrayVar(&symlinks, "symlink", nil, "Create a symlink at DEST pointing to SRC (repeatable, specify as --symlink DEST=SRC)")
	f.StringArrayVar(&tmpfs, "tmpfs", nil, "Mount a tmpfs at the given path (can be repeated)")
	f.StringVarP(&workdir, "workdir", "w", "", "Working directory")
	f.StringArrayVarP(&envFlags, "env", "e", nil, "Pass environment variable")
	f.BoolVar(&allEnv, "all-env", false, "Pass through all environment variables (use with caution, can expose secrets)")
	f.StringVar(&apparmor, "apparmor", "", "Run program with AppArmor profile")
	f.BoolVar(&networkSandboxOnly, "only-network", false, "Only sandbox the network, leave filesystem untouched")
	f.BoolVar(&unshareCgroup, "unshare-cgroup", false, "Unshare the cgroup namespace")
	f.BoolVar(&cgroup, "cgroup", false, "Require a cgroup of the program's own, and refuse to run without one (the default is to use one when available)")
	f.BoolVar(&noCgroup, "no-cgroup", false, "Run the program without a cgroup of its own")
	f.StringVar(&cpuLimit, "cpu-limit", "", "Limit CPU usage to the given number of CPUs, e.g. 0.5 or 2 (implies --cgroup)")
	f.StringVar(&memoryLimit, "memory-limit", "", "Limit memory usage, e.g. 512M or 2G (implies --cgroup)")

	rootCmd.MarkFlagsMutuallyExclusive("current-dir", "current-dir-writable")
	rootCmd.MarkFlagsMutuallyExclusive("only-network", "all-env")
	rootCmd.MarkFlagsMutuallyExclusive("only-network", "current-dir")
	rootCmd.MarkFlagsMutuallyExclusive("only-network", "current-dir-writable")
	rootCmd.MarkFlagsMutuallyExclusive("only-network", "mount")
	rootCmd.MarkFlagsMutuallyExclusive("only-network", "mount-writable")
	rootCmd.MarkFlagsMutuallyExclusive("only-network", "symlink")
	rootCmd.MarkFlagsMutuallyExclusive("only-network", "workdir")
	rootCmd.MarkFlagsMutuallyExclusive("only-network", "env")
	rootCmd.MarkFlagsMutuallyExclusive("only-network", "tmpfs")
	rootCmd.MarkFlagsMutuallyExclusive("only-network", "unshare-cgroup")
	// --no-cgroup is at odds with every flag that asks for a cgroup. The three pairs
	// are spelled out one by one because a single mutually exclusive set would also
	// rule out --cgroup together with a limit, which is a perfectly sensible thing to
	// ask for.
	rootCmd.MarkFlagsMutuallyExclusive("no-cgroup", "cgroup")
	rootCmd.MarkFlagsMutuallyExclusive("no-cgroup", "cpu-limit")
	rootCmd.MarkFlagsMutuallyExclusive("no-cgroup", "memory-limit")

	if err := rootCmd.Execute(); err != nil {
		if exitErr, ok := errors.AsType[*wrapped.ExitError](err); ok {
			os.Exit(exitErr.Code)
		}
		log.Fatal(err)
	}
}

// cgroupMode turns the two cgroup flags into the mode the library takes. Neither flag
// leaves the choice to wrapped, which uses a cgroup where there is one to be had and
// runs without where there is not; --cgroup makes it a requirement, and --no-cgroup
// settles for the process group. A limit implies --cgroup, which the library reads off
// the limit itself.
func cgroupMode(cgroup, noCgroup bool) wrapped.CgroupMode {
	switch {
	case noCgroup:
		return wrapped.CgroupDisabled
	case cgroup:
		return wrapped.CgroupRequired
	default:
		return wrapped.CgroupAuto
	}
}

func init() {
	log.SetFlags(0)
}
