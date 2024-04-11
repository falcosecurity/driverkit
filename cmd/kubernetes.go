// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"bytes"
	"github.com/falcosecurity/driverkit/pkg/driverbuilder/builder"
	"regexp"
	"strings"

	"github.com/falcosecurity/driverkit/pkg/driverbuilder"
	"github.com/falcosecurity/driverkit/pkg/kubernetes/factory"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

// NewKubernetesCmd creates the `driverkit kubernetes` command.
func NewKubernetesCmd(configOpts *ConfigOptions, rootOpts *RootOptions, rootFlags *pflag.FlagSet) *cobra.Command {
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

	kubernetesCmd.RunE = func(c *cobra.Command, args []string) error {
		configOpts.Printer.Logger.Info("starting build",
			configOpts.Printer.Logger.Args("processor", c.Name()))
		if !configOpts.dryRun {
			if !rootOpts.Output.HasOutputs() {
				configOpts.Printer.Logger.Info("no output specified")
				return nil
			}
			// Since we use a spinner, cache log data to a bytesbuffer;
			// we will later print it once we stop the spinner.
			var b *builder.Build
			if configOpts.disableStyling {
				b = rootOpts.ToBuild(configOpts.Printer)
			} else {
				var buf bytes.Buffer
				b = rootOpts.ToBuild(configOpts.Printer.WithWriter(&buf))
				configOpts.Printer.Spinner, _ = configOpts.Printer.Spinner.Start("driver building, it will take a few seconds")
				defer func() {
					configOpts.Printer.DefaultText.Print(buf.String())
				}()
			}
			return kubernetesRun(kubefactory, b, configOpts)
		}
		return nil
	}

	return kubernetesCmd
}

func kubernetesRun(kubefactory factory.Factory,
	b *builder.Build,
	configOpts *ConfigOptions,
) error {
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

	buildProcessor := driverbuilder.NewKubernetesBuildProcessor(kc.CoreV1(),
		clientConfig,
		kubernetesOptions.RunAsUser,
		kubernetesOptions.Namespace,
		kubernetesOptions.ImagePullSecret,
		configOpts.Timeout,
		configOpts.ProxyURL)
	return buildProcessor.Start(b)
}
