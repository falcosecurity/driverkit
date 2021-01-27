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
	dockerOptions = NewDockerOptions()
	dockerCmd := &cobra.Command{
		Use:   "docker",
		Short: "Build Falco kernel modules and eBPF probes against a docker daemon.",
		Run: func(c *cobra.Command, args []string) {
			logrus.WithField("processor", c.Name()).Info("driver building, it will take a few seconds")
			if errs := dockerOptions.Validate(); errs != nil {
				for _, err := range errs {
					logger.WithError(err).Fatal("error validating docker options")
				}
			}
			if !configOptions.DryRun {
				if err := driverbuilder.NewDockerBuildProcessor(viper.GetInt("timeout"), viper.GetString("proxy"), dockerOptions.DNS, dockerOptions.NetworkMode).Start(rootOpts.toBuild()); err != nil {
					logger.WithError(err).Fatal("exiting")
				}
			}
		},
	}
	// Add root flags
	dockerCmd.PersistentFlags().AddFlagSet(rootFlags)

	 // Add command flags
	flags := dockerCmd.Flags()
	flags.StringSliceVar(&dockerOptions.DNS, "dns", dockerOptions.DNS, "Set custom DNS servers")
	flags.StringVar(&dockerOptions.NetworkMode, "network", dockerOptions.NetworkMode, "Connect a container to a network")
	viper.BindPFlags(flags)

	return dockerCmd
}
