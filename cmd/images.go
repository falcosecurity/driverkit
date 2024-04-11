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
	"os"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// NewImagesCmd creates the `driverkit images` command.
func NewImagesCmd(configOpts *ConfigOptions, rootOpts *RootOptions, rootFlags *pflag.FlagSet) *cobra.Command {
	imagesCmd := &cobra.Command{
		Use:   "images",
		Short: "List builder images",
		RunE: func(c *cobra.Command, args []string) error {
			configOpts.Printer.Logger.Info("starting loading images",
				configOpts.Printer.Logger.Args("processor", c.Name()))
			// Since we use a spinner, cache log data to a bytesbuffer;
			// we will later print it once we stop the spinner.
			var (
				buf bytes.Buffer
				b   *builder.Build
			)
			if configOpts.disableStyling {
				b = rootOpts.ToBuild(configOpts.Printer)
			} else {
				b = rootOpts.ToBuild(configOpts.Printer.WithWriter(&buf))
				configOpts.Printer.Spinner, _ = configOpts.Printer.Spinner.Start("listing images, it will take a few seconds")
			}
			b.LoadImages()
			if !configOpts.disableStyling {
				_ = configOpts.Printer.Spinner.Stop()
				configOpts.Printer.DefaultText.Print(buf.String())
			}

			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Image", "Target", "Arch", "GCC"})
			table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
			table.SetCenterSeparator("|")

			for _, img := range b.Images {
				data := make([]string, 4)
				data[0] = img.Name
				data[1] = img.Target.String()
				data[2] = b.Architecture
				data[3] = img.GCCVersion.String()
				table.Append(data)
			}
			table.Render() // Send output
			return nil
		},
	}
	// Add root flags
	imagesCmd.PersistentFlags().AddFlagSet(rootFlags)

	return imagesCmd
}
