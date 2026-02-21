// wrapped - Run a program in a sandbox using bubblewrap.
package main

import (
	"errors"
	"fmt"
	"log"
	"os"
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
		allowAllHosts      bool
		deniedHosts        []string
		networkLogFile     string
		networkSandboxOnly bool
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

			// --allow-host / --allow-all-hosts imply --network filtered.
			networkExplicit := cmd.Flags().Changed("network")
			hasFilterFlags := len(allowedHosts) > 0 || allowAllHosts
			if hasFilterFlags {
				if networkExplicit && networkMode != wrapped.NetworkFiltered {
					return fmt.Errorf("--allow-host and --allow-all-hosts require --network filtered")
				}
				networkMode = wrapped.NetworkFiltered
			}

			// --deny-host and --network-log require filtered mode.
			if len(deniedHosts) > 0 && networkMode != wrapped.NetworkFiltered {
				return fmt.Errorf("--deny-host requires --network filtered with --allow-all-hosts")
			}
			if networkLogFile != "" && networkMode != wrapped.NetworkFiltered {
				return fmt.Errorf("--network-log requires --network filtered")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return wrapped.Wrapped(
				args[0],
				args[1:],
				networkMode,
				currentDir || currentDirWritable,
				currentDirWritable,
				mounts,
				mountsWritable,
				envFlags,
				workdir,
				apparmor,
				allowedHosts,
				allowAllHosts,
				deniedHosts,
				networkLogFile,
				networkSandboxOnly,
			)
		},
	}

	f := rootCmd.Flags()
	f.StringVar(&networkMode, "network", "none", "Network mode: none, host, bridge, or filtered")
	f.BoolVar(&currentDir, "current-dir", false, "Mount the current directory")
	f.BoolVar(&currentDirWritable, "current-dir-writable", false, "Mount the current directory writable")
	f.StringArrayVar(&mounts, "mount", nil, "Mount additional directory read-only")
	f.StringArrayVar(&mountsWritable, "mount-writable", nil, "Mount additional directory writable")
	f.StringArrayVarP(&envFlags, "env", "e", nil, "Pass environment variable")
	f.StringVarP(&workdir, "workdir", "w", "", "Working directory")
	f.StringVar(&apparmor, "apparmor", "", "Run program with AppArmor profile")
	f.StringArrayVar(&allowedHosts, "allow-host", nil, "Allow network access to specific host (can be repeated, supports *.example.com wildcards, implies --network filtered)")
	f.BoolVar(&allowAllHosts, "allow-all-hosts", false, "Allow network access to all hosts (implies --network filtered, use --deny-host to exclude specific hosts)")
	f.StringArrayVar(&deniedHosts, "deny-host", nil, "Deny network access to specific host when using --allow-all-hosts (can be repeated, supports *.example.com wildcards)")
	f.StringVar(&networkLogFile, "network-log", "", "Log all network connections to file (requires --network filtered)")
	f.BoolVar(&networkSandboxOnly, "only-network", false, "Only sandbox the network, leave filesystem untouched")

	rootCmd.MarkFlagsMutuallyExclusive("current-dir", "current-dir-writable")

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
