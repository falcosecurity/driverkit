package cmd

import (
	"github.com/falcosecurity/driverkit/pkg/kubernetes/factory"
	"github.com/falcosecurity/driverkit/pkg/modulebuilder"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

// NewKubernetesCmd creates the `driverkit kubernetes` command.
func NewKubernetesCmd(rootOpts *RootOptions) *cobra.Command {
	kubernetesCmd := &cobra.Command{
		Use:   "kubernetes",
		Short: "Build Falco kernel modules and eBPF probes against a Kubernetes cluster.",
	}

	// Add Kubernetes client Flags
	configFlags := genericclioptions.NewConfigFlags(false)
	configFlags.AddFlags(kubernetesCmd.PersistentFlags())
	kubefactory := factory.NewFactory(configFlags)

	kubernetesCmd.RunE = kubernetesCmdRunE(rootOpts, kubefactory)

	return kubernetesCmd
}

func kubernetesCmdRunE(rootOpts *RootOptions, kubefactory factory.Factory) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		f := cmd.Flags()
		b := rootOpts.toBuild()

		namespaceStr, err := f.GetString("namespace")
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

		buildProcessor := modulebuilder.NewKubernetesBuildProcessor(kc.CoreV1(), clientConfig, namespaceStr, viper.GetInt("timeout"))

		return buildProcessor.Start(b)
	}
}
