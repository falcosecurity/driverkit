package cmd

import (
	"github.com/falcosecurity/driverkit/pkg/driverbuilder"
	"github.com/sirupsen/logrus"
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// NewDockerCmd creates the `driverkit docker` command.
func NewDockerCmd(rootOpts *RootOptions, rootFlags *pflag.FlagSet) *cobra.Command {
	dockerCmd := &cobra.Command{
		Use:   "docker",
		Short: "Build Falco kernel modules and eBPF probes against a docker daemon.",
		Run: func(c *cobra.Command, args []string) {
			logrus.WithField("processor", c.Name()).Info("driver building, it will take a few seconds")
			if !configOptions.DryRun {
				if err := driverbuilder.NewDockerBuildProcessor(viper.GetInt("timeout"), viper.GetString("proxy")).Start(rootOpts.toBuild()); err != nil {
					logger.WithError(err).Fatal("exiting")
				}
			}
		},
	}
	// Add root flags

	flags := dockerCmd.PersistentFlags()
	flags.AddFlagSet(rootFlags)
	flags.StringVarP(&rootOpts.LocalKernelBuildDir, "localkernelbuilddir", "k", rootOpts.LocalKernelBuildDir, "path to the local kernel build dir to use instead of downloading it from the internet. \nIt can be either the one under /lib/modules/$(uname -r)/build or one coming from somewhere else (vanilla target only)")

	return dockerCmd
}
