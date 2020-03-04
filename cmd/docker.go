package cmd

import (
	"github.com/falcosecurity/driverkit/pkg/modulebuilder"
	"github.com/spf13/cobra"
)

// NewDockerCmd ...
func NewDockerCmd(cfgOpts *ConfigOptions, rootOpts *RootOptions) *cobra.Command {
	dockerCmd := &cobra.Command{
		Use:   "docker",
		Short: "Build Falco kernel modules and eBPF probes against a docker daemon.",
		RunE: func(c *cobra.Command, args []string) error {
			return modulebuilder.NewDockerBuildProcessor(cfgOpts.Timeout).Start(rootOpts.toBuild())
		},
	}

	return dockerCmd
}
