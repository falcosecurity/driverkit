package cmd

import (
	"github.com/falcosecurity/driverkit/pkg/driverbuilder"
	"github.com/sirupsen/logrus"
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"

	// Initialize all k8s client auth plugins
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

// NewKubernetesCmd creates the `driverkit kubernetes` command.
func NewKubernetesCmd(rootOpts *RootOptions) *cobra.Command {
	kubernetesCmd := &cobra.Command{
		Use:   "kubernetes",
		Short: "Build Falco kernel modules and eBPF probes against a Kubernetes cluster.",
	}

	// Add Kubernetes client Flags
	flags := kubernetesCmd.PersistentFlags()
	configFlags := genericclioptions.NewConfigFlags(false)
	configFlags.AddFlags(flags)
	matchVersionFlags := cmdutil.NewMatchVersionFlags(configFlags)
	matchVersionFlags.AddFlags(flags)

	kubernetesCmd.Run = func(cmd *cobra.Command, args []string) {
		logrus.WithField("processor", cmd.Name()).Info("driver building, it will take a few seconds to complete")
		if !configOptions.DryRun {
			if err := kubernetesRun(cmd, args, cmdutil.NewFactory(matchVersionFlags), rootOpts); err != nil {
				logger.WithError(err).Fatal("exiting")
			}
		}
	}

	return kubernetesCmd
}

func kubernetesRun(cmd *cobra.Command, args []string, kubefactory cmdutil.Factory, rootOpts *RootOptions) error {
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
	// if err := factory.SetKubernetesDefaults(clientConfig); err != nil {
	// 	return err
	// }

	buildProcessor := driverbuilder.NewKubernetesBuildProcessor(kc.CoreV1(), clientConfig, namespaceStr, viper.GetInt("timeout"))

	return buildProcessor.Start(b)
}
