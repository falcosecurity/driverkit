package cmd

import (
	"github.com/falcosecurity/driverkit/pkg/driverbuilder"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"log/slog"
	"os"
)

// NewDockerCmd creates the `driverkit docker` command.
func NewDockerCmd(rootOpts *RootOptions, rootFlags *pflag.FlagSet) *cobra.Command {
	dockerCmd := &cobra.Command{
		Use:   "docker",
		Short: "Build Falco kernel modules and eBPF probes against a docker daemon.",
		Run: func(c *cobra.Command, args []string) {
			slog.With("processor", c.Name()).Info("driver building, it will take a few seconds")
			if !configOptions.DryRun {
				if err := driverbuilder.NewDockerBuildProcessor(viper.GetInt("timeout"), viper.GetString("proxy")).Start(rootOpts.ToBuild()); err != nil {
					slog.With("err", err.Error()).Error("exiting")
					os.Exit(1)
				}
			}
		},
	}
	// Add root flags
	dockerCmd.PersistentFlags().AddFlagSet(rootFlags)

	return dockerCmd
}
