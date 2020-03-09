package cmd

import (
	"github.com/falcosecurity/driverkit/pkg/driverbuilder"
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// NewDockerCmd ...
func NewDockerCmd(rootOpts *RootOptions) *cobra.Command {
	dockerCmd := &cobra.Command{
		Use:   "docker",
		Short: "Build Falco kernel modules and eBPF probes against a docker daemon.",
		Run: func(c *cobra.Command, args []string) {
			if err := driverbuilder.NewDockerBuildProcessor(viper.GetInt("timeout")).Start(rootOpts.toBuild()); err != nil {
				logger.WithError(err).Fatal("exiting")
			}
		},
	}

	return dockerCmd
}
