package cmd

import (
	"github.com/falcosecurity/driverkit/pkg/driverbuilder"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"log/slog"
	"os"
	"os/user"
	"runtime"
)

type localCmdOptions struct {
	useDKMS bool
	srcDir  string
	envMap  map[string]string
}

// NewLocalCmd creates the `driverkit local` command.
func NewLocalCmd(rootCommand *RootCmd, rootOpts *RootOptions, rootFlags *pflag.FlagSet) *cobra.Command {
	opts := localCmdOptions{}
	localCmd := &cobra.Command{
		Use:               "local",
		Short:             "Build Falco kernel modules and eBPF probes in local env with local kernel sources and gcc/clang.",
		PersistentPreRunE: persistentPreRunFunc(rootCommand, rootOpts),
		Run: func(c *cobra.Command, args []string) {
			slog.With("processor", c.Name()).Info("driver building, it will take a few seconds")
			if !configOptions.DryRun {
				b := rootOpts.ToBuild()
				if !b.HasOutputs() {
					return
				}
				if opts.useDKMS {
					currentUser, err := user.Current()
					if err != nil {
						slog.With("err", err.Error()).Error("Failed to retrieve user. Exiting.")
						os.Exit(1)
					}
					if currentUser.Username != "root" {
						slog.Error("Must be run as root for DKMS build.")
						os.Exit(1)
					}
				}
				if err := driverbuilder.NewLocalBuildProcessor(viper.GetInt("timeout"), opts.useDKMS, opts.srcDir, opts.envMap).Start(b); err != nil {
					slog.With("err", err.Error()).Error("exiting")
					os.Exit(1)
				}
			}
		},
	}
	// Add root flags, but not the ones unneeded
	unusedFlagsSet := map[string]struct{}{
		"architecture":        {},
		"target":              {},
		"kernelurls":          {},
		"builderrepo":         {},
		"builderimage":        {},
		"gccversion":          {},
		"kernelconfigdata":    {},
		"proxy":               {},
		"registry-name":       {},
		"registry-password":   {},
		"registry-plain-http": {},
		"registry-user":       {},
	}
	flagSet := pflag.NewFlagSet("local", pflag.ExitOnError)
	rootFlags.VisitAll(func(flag *pflag.Flag) {
		if _, ok := unusedFlagsSet[flag.Name]; !ok {
			flagSet.AddFlag(flag)
		}
	})
	flagSet.BoolVar(&opts.useDKMS, "dkms", false, "Enforce usage of DKMS to build the kernel module.")
	flagSet.StringVar(&opts.srcDir, "src-dir", "", "Enforce usage of local source dir to build drivers.")
	flagSet.StringToStringVar(&opts.envMap, "env", make(map[string]string), "Env variables to be enforced during the driver build.")
	localCmd.PersistentFlags().AddFlagSet(flagSet)
	return localCmd
}

// Partially overrides rootCmd.persistentPreRunFunc setting some defaults before config init/validation stage.
func persistentPreRunFunc(rootCommand *RootCmd, rootOpts *RootOptions) func(c *cobra.Command, args []string) error {
	return func(c *cobra.Command, args []string) error {
		// Default values
		rootOpts.Target = "local"
		rootOpts.Architecture = runtime.GOARCH
		return rootCommand.c.PersistentPreRunE(c, args)
	}
}
