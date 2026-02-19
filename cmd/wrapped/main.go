// wrapped - Run a program in a sandbox using bubblewrap.
package main

import (
	"log"
	"os"
	"wrapped"

	"github.com/spf13/cobra"
)

func main() {
	var (
		network            bool
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
	)

	rootCmd := &cobra.Command{
		Use:   "wrapped [flags] program [arguments...]",
		Short: "Run a program in a sandbox using bubblewrap",
		Args:  cobra.MinimumNArgs(1),
		// Avoid printing usage on every RunE error.
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return wrapped.Wrapped(
				args[0],
				args[1:],
				network,
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
			)
		},
	}

	f := rootCmd.Flags()
	f.BoolVar(&network, "network", false, "Enable full network access")
	f.BoolVar(&currentDir, "current-dir", false, "Mount the current directory")
	f.BoolVar(&currentDirWritable, "current-dir-writable", false, "Mount the current directory writable")
	f.StringArrayVar(&mounts, "mount", nil, "Mount additional directory read-only")
	f.StringArrayVar(&mountsWritable, "mount-writable", nil, "Mount additional directory writable")
	f.StringArrayVarP(&envFlags, "env", "e", nil, "Pass environment variable")
	f.StringVarP(&workdir, "workdir", "w", "", "Working directory")
	f.StringVar(&apparmor, "apparmor", "", "Run program with AppArmor profile")
	f.StringArrayVar(&allowedHosts, "allow-host", nil, "Allow network access to specific host (can be repeated, supports *.example.com wildcards)")
	f.BoolVar(&allowAllHosts, "allow-all-hosts", false, "Allow network access to all hosts (use --deny-host to exclude specific hosts)")
	f.StringArrayVar(&deniedHosts, "deny-host", nil, "Deny network access to specific host when using --allow-all-hosts (can be repeated, supports *.example.com wildcards)")
	f.StringVar(&networkLogFile, "network-log", "", "Log all network connections to file (requires --allow-host or --allow-all-hosts)")

	rootCmd.MarkFlagsMutuallyExclusive("current-dir", "current-dir-writable")
	rootCmd.MarkFlagsMutuallyExclusive("network", "allow-host", "allow-all-hosts")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	log.SetFlags(0)
}
