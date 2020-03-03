package cmd

import (
	"fmt"

	"github.com/falcosecurity/driverkit/pkg/kubernetes/factory"
	"github.com/falcosecurity/driverkit/pkg/modulebuilder"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func NewKubernetesCmd(rootOpts *RootOptions) *cobra.Command {
	kubernetesCmd := &cobra.Command{
		Use:   "kubernetes",
		Short: "run driverkit against a Kubernetes cluster",
		Long:  "This is the actual command to use a Kubernetes cluster with driverkit",
	}

	// Add Kubernetes client Flags
	configFlags := genericclioptions.NewConfigFlags(false)
	configFlags.AddFlags(kubernetesCmd.PersistentFlags())
	kubefactory := factory.NewFactory(configFlags)

	kubernetesCmd.RunE = kubernetesCmdRunE(rootOpts, kubefactory)

	// Override help on all the commands tree
	walk(kubernetesCmd, func(c *cobra.Command) {
		c.Flags().BoolP("help", "h", false, fmt.Sprintf("Help for the %s command", c.Name()))
	})

	return kubernetesCmd
}
func kubernetesCmdRunE(rootOpts *RootOptions, kubefactory factory.Factory) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		pf := cmd.Flags()
		b := rootOpts.toBuild()

		namespaceStr, err := pf.GetString("namespace")
		if err != nil {
			return err
		}
		if len(namespaceStr) == 0 {
			namespaceStr = "default"
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
