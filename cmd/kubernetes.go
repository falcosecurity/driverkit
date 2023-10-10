package cmd

import (
	"log/slog"
	"os"
	"regexp"
	"strings"

	"github.com/falcosecurity/driverkit/pkg/driverbuilder"
	"github.com/falcosecurity/driverkit/pkg/kubernetes/factory"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

// NewKubernetesCmd creates the `driverkit kubernetes` command.
func NewKubernetesCmd(rootOpts *RootOptions, rootFlags *pflag.FlagSet) *cobra.Command {
	kubernetesCmd := &cobra.Command{
		Use:     "kubernetes",
		Short:   "Build Falco kernel modules and eBPF probes against a Kubernetes cluster.",
		Aliases: []string{"k8s"},
	}

	// Add Kubernetes client flags
	configFlags := genericclioptions.NewConfigFlags(false)
	configFlags.AddFlags(kubernetesCmd.PersistentFlags())
	// Some styling to make Kubernetes client flags look like they were ours
	dotEndingRegexp := regexp.MustCompile(`\.$`)
	upperAfterPointRegexp := regexp.MustCompile(`\. ([A-Z0-9])`)
	upperAfterCommaRegexp := regexp.MustCompile(`, ([A-Z0-9])`)
	kubernetesCmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		f.Usage = strings.ToLower(f.Usage[:1]) + f.Usage[1:]
		f.Usage = dotEndingRegexp.ReplaceAllString(f.Usage, "")
		f.Usage = upperAfterPointRegexp.ReplaceAllString(f.Usage, ", ${1}")
		f.Usage = upperAfterCommaRegexp.ReplaceAllStringFunc(f.Usage, strings.ToLower)
	})
	// Add Kubernetes pods options flags
	flags := kubernetesCmd.Flags()
	addKubernetesFlags(flags)
	kubernetesCmd.PersistentFlags().AddFlagSet(flags)
	// Add root flags
	kubernetesCmd.PersistentFlags().AddFlagSet(rootFlags)

	kubefactory := factory.NewFactory(configFlags)

	kubernetesCmd.Run = func(cmd *cobra.Command, args []string) {
		slog.With("processor", cmd.Name()).Info("driver building, it will take a few seconds")
		if !configOptions.DryRun {
			if err := kubernetesRun(cmd, args, kubefactory, rootOpts); err != nil {
				slog.With("err", err.Error()).Error("exiting")
				os.Exit(1)
			}
		}
	}

	return kubernetesCmd
}

func kubernetesRun(cmd *cobra.Command, args []string, kubefactory factory.Factory, rootOpts *RootOptions) error {
	f := cmd.Flags()
	b := rootOpts.ToBuild()
	if !b.HasOutputs() {
		return nil
	}

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

	buildProcessor := driverbuilder.NewKubernetesBuildProcessor(kc.CoreV1(), clientConfig, kubernetesOptions.RunAsUser, kubernetesOptions.Namespace, kubernetesOptions.ImagePullSecret, viper.GetInt("timeout"), viper.GetString("proxy"))
	return buildProcessor.Start(b)
}
