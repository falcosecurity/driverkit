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
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/falcosecurity/driverkit/pkg/driverbuilder/builder"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"github.com/falcosecurity/driverkit/pkg/version"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/spf13/viper"
)

func persistentValidateFunc(rootCommand *RootCmd, configOpts *ConfigOptions, rootOpts *RootOptions) func(c *cobra.Command, args []string) error {
	return func(c *cobra.Command, args []string) error {
		configErr := configOpts.Init()
		// Early exit if detect some error into config flags
		if configErr {
			return fmt.Errorf("exiting for validation errors")
		}
		// Merge environment variables or config file values into the RootOptions instance
		skip := map[string]bool{ // do not merge these
			"config":   true,
			"timeout":  true,
			"loglevel": true,
			"dryrun":   true,
			"proxy":    true,
		}
		nested := map[string]string{ // handle nested options in config file
			"output-module": "output.module",
			"output-probe":  "output.probe",
		}
		rootCommand.c.Flags().VisitAll(func(f *pflag.Flag) {
			if name := f.Name; !skip[name] {
				if name == "kernelurls" {
					// Slice types need special treatment when used as flags. If we call 'Set(name, value)',
					// rather than replace, it appends. Since viper will already have the cli options set
					// if supplied, we only need this step if rootCommand doesn't already have them e.g.
					// not set on CLI so read from config.
					if cliURLs, err := rootCommand.c.Flags().GetStringSlice(name); err == nil && len(cliURLs) != 0 {
						return
					}
					value := viper.GetStringSlice(name)
					if len(value) != 0 {
						strValue := strings.Join(value, ",")
						_ = rootCommand.c.Flags().Set(name, strValue)
					}
				} else {
					value := viper.GetString(name)
					if value == "" {
						// fallback to nested options in config file, if any
						if nestedName, ok := nested[name]; ok {
							value = viper.GetString(nestedName)
						}
					}
					// set the value, if any, otherwise let the default
					if value != "" {
						_ = rootCommand.c.Flags().Set(name, value)
					}
				}
			}
		})

		// Avoid sensitive info into default values help line
		rootCommand.StripSensitive()

		// Do not block root or help command to exec disregarding the root flags validity
		if c.Root() != c && c.Name() != "help" && c.Name() != "__complete" && c.Name() != "__completeNoDesc" && c.Name() != "completion" {
			if errs := rootOpts.Validate(); errs != nil {
				for _, err := range errs {
					configOpts.Printer.Logger.Error("error validating build options",
						configOpts.Printer.Logger.Args("err", err.Error()))
				}
				return fmt.Errorf("exiting for validation errors")
			}
			rootOpts.Log(configOpts.Printer)
		}
		return nil
	}
}

// RootCmd wraps the main cobra.Command.
type RootCmd struct {
	c *cobra.Command
}

// NewRootCmd instantiates the root command.
func NewRootCmd(configOpts *ConfigOptions, rootOpts *RootOptions) *RootCmd {
	rootCmd := &cobra.Command{
		Use:                   "driverkit",
		Short:                 "A command line tool to build Falco kernel modules and eBPF probes.",
		ValidArgs:             validProcessors,
		ArgAliases:            aliasProcessors,
		Args:                  cobra.OnlyValidArgs,
		DisableFlagsInUseLine: true,
		DisableAutoGenTag:     true,
		Version:               version.String(),
		Run: func(c *cobra.Command, args []string) {
			if len(args) == 0 {
				configOpts.Printer.Logger.Info("specify a valid processor", configOpts.Printer.Logger.Args("processors", validProcessors))
			}
			// Fallback to help
			_ = c.Help()
		},
	}
	ret := &RootCmd{
		c: rootCmd,
	}

	rootCmd.PersistentPreRunE = persistentValidateFunc(ret, configOpts, rootOpts)

	flags := rootCmd.Flags()

	targets := builder.Targets()
	sort.Strings(targets)

	configOpts.AddFlags(flags)
	rootOpts.AddFlags(flags, targets)

	if err := viper.BindPFlags(flags); err != nil {
		panic(err)
	}

	// Flag annotations and custom completions
	_ = rootCmd.MarkFlagFilename("config", viper.SupportedExts...)
	_ = rootCmd.RegisterFlagCompletionFunc("target", func(c *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return targets, cobra.ShellCompDirectiveDefault
	})
	_ = rootCmd.RegisterFlagCompletionFunc("architecture", func(c *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return kernelrelease.SupportedArchs.Strings(), cobra.ShellCompDirectiveDefault
	})

	// Subcommands
	rootCmd.AddCommand(NewKubernetesCmd(configOpts, rootOpts, flags))
	rootCmd.AddCommand(NewKubernetesInClusterCmd(configOpts, rootOpts, flags))
	rootCmd.AddCommand(NewDockerCmd(configOpts, rootOpts, flags))
	rootCmd.AddCommand(NewLocalCmd(configOpts, rootOpts, flags))
	rootCmd.AddCommand(NewImagesCmd(configOpts, rootOpts, flags))
	rootCmd.AddCommand(NewCompletionCmd(configOpts, rootOpts, flags))

	ret.StripSensitive()

	return ret
}

// Sensitive is a list of sensitive environment variable to replace into the help outputs.
var Sensitive = []string{
	"HOME",
}

// StripSensitive removes sensistive info from default values printed into the help messages.
func (r *RootCmd) StripSensitive() {
	for _, s := range Sensitive {
		homeDir := os.Getenv(s)
		for _, childCommand := range r.c.Commands() {
			childCommand.Flags().VisitAll(func(f *pflag.Flag) {
				f.DefValue = strings.ReplaceAll(f.DefValue, homeDir, fmt.Sprintf("$%s", s))
			})
		}
	}
}

// Command returns the underlying cobra.Command.
func (r *RootCmd) Command() *cobra.Command {
	return r.c
}

// SetArgs proxies the arguments to the underlying cobra.Command.
func (r *RootCmd) SetArgs(args []string) {
	r.c.SetArgs(args)
}

// Execute proxies the cobra.Command execution.
func (r *RootCmd) Execute() error {
	return r.c.Execute()
}

// Start creates the root command and runs it.
func Start() {
	configOpts, err := NewConfigOptions()
	if err != nil {
		// configOpts will never be nil here
		if configOpts != nil {
			configOpts.Printer.Logger.Fatal("error setting driverkit config options defaults",
				configOpts.Printer.Logger.Args("err", err.Error()))
		} else {
			os.Exit(1)
		}
	}
	rootOpts, err := NewRootOptions()
	if err != nil {
		configOpts.Printer.Logger.Fatal("error setting driverkit root options defaults",
			configOpts.Printer.Logger.Args("err", err.Error()))
	}
	root := NewRootCmd(configOpts, rootOpts)
	if err = root.Execute(); err != nil {
		configOpts.Printer.Logger.Fatal("error executing driverkit", configOpts.Printer.Logger.Args("err", err.Error()))
	}
}
