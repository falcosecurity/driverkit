package cmd

import (
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/falcosecurity/driverkit/pkg/modulebuilder"
	"github.com/falcosecurity/driverkit/pkg/modulebuilder/build"
	"github.com/falcosecurity/driverkit/pkg/modulebuilder/buildtype"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// NewDockerCmd ...
func NewDockerCmd() *cobra.Command {
	dockerCmd := &cobra.Command{
		Use:   "docker",
		Short: "run driverkit against a docker daemon",
		Long:  "This is the actual command to use a docker daemon with driverkit",
		RunE: func(c *cobra.Command, args []string) error {
			b, err := a(c.Flags())
			if err != nil {
				return err
			}
			spew.Dump(b)

			processor := modulebuilder.NewDockerBuildProcessor()
			return processor.Start(*b)
		},
	}

	// Override help on all the commands tree
	walk(dockerCmd, func(c *cobra.Command) {
		c.Flags().BoolP("help", "h", false, fmt.Sprintf("Help for the %s command", c.Name()))
	})

	return dockerCmd
}

func a(pf *pflag.FlagSet) (*build.Build, error) {
	outputFileName, err := pf.GetString("output")
	if err != nil {
		return nil, err
	}
	moduleVersion, err := pf.GetString("moduleversion")
	if err != nil {
		return nil, err
	}
	kernelVersion, err := pf.GetString("kernelversion")
	if err != nil {
		return nil, err
	}
	kernelRelease, err := pf.GetString("kernelrelease")
	if err != nil {
		return nil, err
	}
	buildType, err := pf.GetString("target")
	if err != nil {
		return nil, err
	}
	kernelConfigData, err := pf.GetString("kernelconfigdata")
	if err != nil {
		return nil, err
	}
	if len(kernelConfigData) == 0 {
		kernelConfigData = "bm8tZGF0YQ==" // no-data
	}

	return &build.Build{
		ModuleVersion:    moduleVersion,
		KernelVersion:    kernelVersion,
		KernelRelease:    kernelRelease,
		Architecture:     string(modulebuilder.BuildArchitectureX86_64), // TODO(fntlnz,leodido): make this configurable
		BuildType:        buildtype.BuildType(buildType),
		KernelConfigData: kernelConfigData,
		OutputFilePath:   outputFileName,
	}, nil
}
