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
			)
		},
	}

	f := rootCmd.Flags()
	f.BoolVar(&network, "network", false, "Enable network access")
	f.BoolVar(&currentDir, "current-dir", false, "Mount the current directory")
	f.BoolVar(&currentDirWritable, "current-dir-writable", false, "Mount the current directory writable")
	f.StringArrayVar(&mounts, "mount", nil, "Mount additional directory read-only")
	f.StringArrayVar(&mountsWritable, "mount-writable", nil, "Mount additional directory writable")
	f.StringArrayVarP(&envFlags, "env", "e", nil, "Pass environment variable")
	f.StringVarP(&workdir, "workdir", "w", "", "Working directory")

	rootCmd.MarkFlagsMutuallyExclusive("current-dir", "current-dir-writable")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	log.SetFlags(0)
}
