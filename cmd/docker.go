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
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// NewDockerCmd creates the `driverkit docker` command.
func NewDockerCmd(configOpts *ConfigOptions, rootOpts *RootOptions, rootFlags *pflag.FlagSet) *cobra.Command {
	dockerCmd := &cobra.Command{
		Use:   "docker",
		Short: "Build Falco kernel modules and eBPF probes against a docker daemon.",
		RunE: func(c *cobra.Command, args []string) error {
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
				return driverbuilder.NewDockerBuildProcessor(configOpts.timeout, configOpts.proxyURL).Start(b)
			}
			return nil
		},
	}
	// Add root flags
	dockerCmd.PersistentFlags().AddFlagSet(rootFlags)

	return dockerCmd
}
