package cmd

import (
	"github.com/falcosecurity/driverkit/pkg/driverbuilder"
	"github.com/falcosecurity/driverkit/pkg/kubernetes/factory"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"log/slog"
	"os"
)

// NewKubernetesInClusterCmd creates the `driverkit kubernetes` command.
func NewKubernetesInClusterCmd(rootOpts *RootOptions, rootFlags *pflag.FlagSet) *cobra.Command {
	kubernetesInClusterCmd := &cobra.Command{
		Use:     "kubernetes-in-cluster",
		Short:   "Build Falco kernel modules and eBPF probes against a Kubernetes cluster inside a Kubernetes cluster.",
		Aliases: []string{"k8s-ic"},
	}

	// Add Kubernetes pods options flags
	flags := kubernetesInClusterCmd.Flags()
	addKubernetesFlags(flags)
	kubernetesInClusterCmd.PersistentFlags().AddFlagSet(flags)
	// Add root flags
	kubernetesInClusterCmd.PersistentFlags().AddFlagSet(rootFlags)

	kubernetesInClusterCmd.Run = func(cmd *cobra.Command, args []string) {
		slog.With("processor", cmd.Name()).Info("driver building, it will take a few seconds")
		if !configOptions.DryRun {
			config, err := rest.InClusterConfig()
			if err != nil {
				slog.With("err", err.Error()).Error("exiting")
				os.Exit(1)
			}
			if err = factory.SetKubernetesDefaults(config); err != nil {
				slog.With("err", err.Error()).Error("exiting")
				os.Exit(1)
			}
			if err = kubernetesInClusterRun(cmd, args, config, rootOpts); err != nil {
				slog.With("err", err.Error()).Error("exiting")
				os.Exit(1)
			}
		}
	}

	return kubernetesInClusterCmd
}

func kubernetesInClusterRun(_ *cobra.Command, _ []string, kubeConfig *rest.Config, rootOpts *RootOptions) error {
	b := rootOpts.ToBuild()
	if !b.HasOutputs() {
		return nil
	}

	kc, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return err
	}

	buildProcessor := driverbuilder.NewKubernetesBuildProcessor(kc.CoreV1(), kubeConfig, kubernetesOptions.RunAsUser, kubernetesOptions.Namespace, kubernetesOptions.ImagePullSecret, viper.GetInt("timeout"), viper.GetString("proxy"))

	return buildProcessor.Start(b)
}
