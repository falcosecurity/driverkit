package cmd

import (
	"fmt"

	"github.com/falcosecurity/driverkit/pkg/modulebuilder"
	"github.com/spf13/cobra"
)

// NewDockerCmd ...
func NewDockerCmd(rootOpts *RootOptions) *cobra.Command {
	dockerCmd := &cobra.Command{
		Use:   "docker",
		Short: "run driverkit against a docker daemon",
		Long:  "This is the actual command to use a docker daemon with driverkit",
		RunE: func(c *cobra.Command, args []string) error {
			b := rootOpts.toBuild()
			processor := modulebuilder.NewDockerBuildProcessor()
			return processor.Start(b)
		},
	}

	// Override help on all the commands tree
	walk(dockerCmd, func(c *cobra.Command) {
		c.Flags().BoolP("help", "h", false, fmt.Sprintf("Help for the %s command", c.Name()))
	})

	return dockerCmd
}
