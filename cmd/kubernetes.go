package cmd

import (
	"fmt"
	"github.com/falcosecurity/build-service/pkg/kubernetes/factory"
	"github.com/falcosecurity/build-service/pkg/modulebuilder"
	"github.com/falcosecurity/build-service/pkg/modulebuilder/build"
	"github.com/falcosecurity/build-service/pkg/modulebuilder/buildtype"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func init() {
	rootCmd.AddCommand(NewKubernetesCmd())
}

func NewKubernetesCmd() *cobra.Command {
	kubernetesCmd := &cobra.Command{
		Use:   "kubernetes",
		Short: "Build Falco kernel module using a Kubernetes cluster",
		Long:  "This is the actual command to use a Kubernetes cluster for building the Falco Kernel module",
	}

	// Add Kubernetes client Flags
	configFlags := genericclioptions.NewConfigFlags(false)
	configFlags.AddFlags(kubernetesCmd.PersistentFlags())
	kubefactory := factory.NewFactory(configFlags)

	kubernetesCmd.RunE = kubernetesCmdRunE(kubefactory)

	// Override help on all the commands tree
	walk(kubernetesCmd, func(c *cobra.Command) {
		c.Flags().BoolP("help", "h", false, fmt.Sprintf("Help for the %s command", c.Name()))
	})

	return kubernetesCmd
}
func kubernetesCmdRunE(kubefactory factory.Factory) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		pf := cmd.PersistentFlags()
		outputFileName, err := pf.GetString("output")
		if err != nil {
			return err
		}
		moduleVersion, err := pf.GetString("moduleversion")
		if err != nil {
			return err
		}
		kernelVersion, err := pf.GetString("kernelversion")
		if err != nil {
			return err
		}
		kernelRelease, err := pf.GetString("kernelrelease")
		if err != nil {
			return err
		}
		buildType, err := pf.GetString("buildtype")
		if err != nil {
			return err
		}
		kernelConfigData, err := pf.GetString("kernelconfigdata")
		if err != nil {
			return err
		}
		if len(kernelConfigData) == 0 {
			kernelConfigData = "bm8tZGF0YQ==" // no-data
		}

		namespaceStr, err := pf.GetString("namespace")
		if err != nil {
			return err
		}
		if len(namespaceStr) == 0 {
			namespaceStr = "default"
		}

		b := build.Build{
			ModuleVersion:    moduleVersion,
			KernelVersion:    kernelVersion,
			KernelRelease:    kernelRelease,
			Architecture:     string(modulebuilder.BuildArchitectureX86_64), // TODO(fntlnz,leodido): make this configurable
			BuildType:        buildtype.BuildType(buildType),
			KernelConfigData: kernelConfigData,
			OutputFilePath:   outputFileName,
		}

		if _, err := b.Validate(); err != nil {
			return err
		}

		kc, err := kubefactory.KubernetesClientSet()
		if err != nil {
			return err
		}
		clientConfig, err := kubefactory.ToRESTConfig()
		if err != nil {
			return err
		}
		if err := factory.SetKubernetesDefaults(clientConfig); err != nil {
			return err
		}

		buildProcessor := modulebuilder.NewKubernetesBuildProcessor(kc.CoreV1(), clientConfig, namespaceStr)
		buildProcessor.WithLogger(logger)

		return buildProcessor.Start(b)
	}
}

// walk calls f for c and all of its children.
func walk(c *cobra.Command, f func(*cobra.Command)) {
	f(c)
	for _, c := range c.Commands() {
		walk(c, f)
	}
}
