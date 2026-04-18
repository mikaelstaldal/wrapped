// wrapped - Run a program in a sandbox using bubblewrap.
package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"wrapped"

	"github.com/spf13/cobra"
)

// Set via -ldflags at build time.
var version, commit string

func main() {
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
	)

	versionStr := "dev"
	if version != "" {
		versionStr = version
		if commit != "" {
			versionStr += " (" + commit + ")"
		}
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
			)
		},
	}

	f := rootCmd.Flags()
	f.StringVar(&networkMode, "network", "none", "Network mode: none, host, bridge, or filtered")
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

	if err := rootCmd.Execute(); err != nil {
		var exitErr *wrapped.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code)
		}
		log.Fatal(err)
	}
}

func init() {
	log.SetFlags(0)
}
