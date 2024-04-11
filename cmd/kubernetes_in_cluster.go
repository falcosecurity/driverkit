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
	"github.com/falcosecurity/driverkit/pkg/driverbuilder"
	"github.com/falcosecurity/driverkit/pkg/driverbuilder/builder"
	"github.com/falcosecurity/driverkit/pkg/kubernetes/factory"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// NewKubernetesInClusterCmd creates the `driverkit kubernetes` command.
func NewKubernetesInClusterCmd(configOpts *ConfigOptions, rootOpts *RootOptions, rootFlags *pflag.FlagSet) *cobra.Command {
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

	kubernetesInClusterCmd.RunE = func(c *cobra.Command, args []string) error {
		configOpts.Printer.Logger.Info("starting build",
			configOpts.Printer.Logger.Args("processor", c.Name()))
		if !configOpts.dryRun {
			// Since we use a spinner, cache log data to a bytesbuffer;
			// we will later print it once we stop the spinner.
			var buf bytes.Buffer
			b := rootOpts.ToBuild(configOpts.Printer.WithWriter(&buf))
			defer func() {
				configOpts.Printer.DefaultText.Print(buf.String())
			}()
			if !b.HasOutputs() {
				return nil
			}
			configOpts.Printer.Spinner, _ = configOpts.Printer.Spinner.Start("driver building, it will take a few seconds")
			defer func() {
				_ = configOpts.Printer.Spinner.Stop()
			}()
			return kubernetesInClusterRun(b, configOpts)
		}
		return nil
	}

	return kubernetesInClusterCmd
}

func kubernetesInClusterRun(b *builder.Build, configOpts *ConfigOptions) error {
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	if err = factory.SetKubernetesDefaults(kubeConfig); err != nil {
		return err
	}

	kc, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return err
	}

	buildProcessor := driverbuilder.NewKubernetesBuildProcessor(kc.CoreV1(),
		kubeConfig,
		kubernetesOptions.RunAsUser,
		kubernetesOptions.Namespace,
		kubernetesOptions.ImagePullSecret,
		configOpts.timeout,
		configOpts.proxyURL)
	return buildProcessor.Start(b)
}
