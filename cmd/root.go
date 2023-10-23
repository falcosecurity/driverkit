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
	"io"
	"log/slog"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"github.com/falcosecurity/driverkit/validate"

	"github.com/falcosecurity/driverkit/pkg/driverbuilder/builder"
	"github.com/falcosecurity/driverkit/pkg/version"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

func persistentValidateFunc(rootCommand *RootCmd, rootOpts *RootOptions) func(c *cobra.Command, args []string) error {
	return func(c *cobra.Command, args []string) error {
		initConfig()
		// Early exit if detect some error into config flags
		if configOptions.configErrors {
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
					if cli_urls, err := rootCommand.c.Flags().GetStringSlice(name); err == nil && len(cli_urls) != 0 {
						return
					}
					value := viper.GetStringSlice(name)
					if len(value) != 0 {
						strValue := strings.Join(value, ",")
						rootCommand.c.Flags().Set(name, strValue)
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
						rootCommand.c.Flags().Set(name, value)
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
					slog.With("err", err.Error()).Error("error validating build options")
				}
				return fmt.Errorf("exiting for validation errors")
			}
			rootOpts.Log()
		}
		return nil
	}
}

// RootCmd wraps the main cobra.Command.
type RootCmd struct {
	c *cobra.Command
}

// NewRootCmd instantiates the root command.
func NewRootCmd() *RootCmd {
	configOptions = NewConfigOptions()
	rootOpts := NewRootOptions()
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
				slog.With("processors", validProcessors).Info("specify a valid processor")
			}
			// Fallback to help
			c.Help()
		},
	}
	ret := &RootCmd{
		c: rootCmd,
	}

	rootCmd.PersistentPreRunE = persistentValidateFunc(ret, rootOpts)

	flags := rootCmd.Flags()

	targets := builder.Targets()
	sort.Strings(targets)

	flags.StringVarP(&configOptions.ConfigFile, "config", "c", configOptions.ConfigFile, "config file path (default $HOME/.driverkit.yaml if exists)")
	flags.StringVarP(&configOptions.LogLevel, "loglevel", "l", configOptions.LogLevel, "log level")
	flags.IntVar(&configOptions.Timeout, "timeout", configOptions.Timeout, "timeout in seconds")
	flags.BoolVar(&configOptions.DryRun, "dryrun", configOptions.DryRun, "do not actually perform the action")
	flags.StringVar(&configOptions.ProxyURL, "proxy", configOptions.ProxyURL, "the proxy to use to download data")

	flags.StringVar(&rootOpts.Output.Module, "output-module", rootOpts.Output.Module, "filepath where to save the resulting kernel module")
	flags.StringVar(&rootOpts.Output.Probe, "output-probe", rootOpts.Output.Probe, "filepath where to save the resulting eBPF probe")
	flags.StringVar(&rootOpts.Architecture, "architecture", runtime.GOARCH, "target architecture for the built driver, one of "+kernelrelease.SupportedArchs.String())
	flags.StringVar(&rootOpts.DriverVersion, "driverversion", rootOpts.DriverVersion, "driver version as a git commit hash or as a git tag")
	flags.StringVar(&rootOpts.KernelVersion, "kernelversion", rootOpts.KernelVersion, "kernel version to build the module for, it's the numeric value after the hash when you execute 'uname -v'")
	flags.StringVar(&rootOpts.KernelRelease, "kernelrelease", rootOpts.KernelRelease, "kernel release to build the module for, it can be found by executing 'uname -v'")
	flags.StringVarP(&rootOpts.Target, "target", "t", rootOpts.Target, "the system to target the build for, one of ["+strings.Join(targets, ",")+"]")
	flags.StringVar(&rootOpts.KernelConfigData, "kernelconfigdata", rootOpts.KernelConfigData, "base64 encoded kernel config data: in some systems it can be found under the /boot directory, in other it is gzip compressed under /proc")
	flags.StringVar(&rootOpts.ModuleDeviceName, "moduledevicename", rootOpts.ModuleDeviceName, "kernel module device name (the default is falco, so the device will be under /dev/falco*)")
	flags.StringVar(&rootOpts.ModuleDriverName, "moduledrivername", rootOpts.ModuleDriverName, "kernel module driver name, i.e. the name you see when you check installed modules via lsmod")
	flags.StringVar(&rootOpts.BuilderImage, "builderimage", rootOpts.BuilderImage, "docker image to be used to build the kernel module and eBPF probe. If not provided, an automatically selected image will be used.")
	flags.StringSliceVar(&rootOpts.BuilderRepos, "builderrepo", rootOpts.BuilderRepos, "list of docker repositories or yaml file (absolute path) containing builder images index with the format 'images: [ { target:<target>, name:<image-name>, arch: <arch>, tag: <imagetag>, gcc_versions: [ <gcc-tag> ] },...]', in descending priority order. Used to search for builder images. eg: --builderrepo myorg/driverkit-builder --builderrepo falcosecurity/driverkit-builder --builderrepo '/path/to/my/index.yaml'.")
	flags.StringVar(&rootOpts.GCCVersion, "gccversion", rootOpts.GCCVersion, "enforce a specific gcc version for the build")

	flags.StringSliceVar(&rootOpts.KernelUrls, "kernelurls", nil, "list of kernel header urls (e.g. --kernelurls <URL1> --kernelurls <URL2> --kernelurls \"<URL3>,<URL4>\")")

	flags.StringVar(&rootOpts.Repo.Org, "repo-org", rootOpts.Repo.Org, "repository github organization")
	flags.StringVar(&rootOpts.Repo.Name, "repo-name", rootOpts.Repo.Name, "repository github name")

	flags.StringVar(&rootOpts.Registry.Name, "registry-name", rootOpts.Registry.Name, "registry name to which authenticate")
	flags.StringVar(&rootOpts.Registry.Username, "registry-user", rootOpts.Registry.Username, "registry username")
	flags.StringVar(&rootOpts.Registry.Password, "registry-password", rootOpts.Registry.Password, "registry password")
	flags.BoolVar(&rootOpts.Registry.PlainHTTP, "registry-plain-http", rootOpts.Registry.PlainHTTP, "allows interacting with remote registry via plain http requests")

	viper.BindPFlags(flags)

	// Flag annotations and custom completions
	rootCmd.MarkFlagFilename("config", viper.SupportedExts...)
	rootCmd.RegisterFlagCompletionFunc("target", func(c *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return targets, cobra.ShellCompDirectiveDefault
	})
	rootCmd.RegisterFlagCompletionFunc("architecture", func(c *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return kernelrelease.SupportedArchs.Strings(), cobra.ShellCompDirectiveDefault
	})

	// Subcommands
	rootCmd.AddCommand(NewKubernetesCmd(rootOpts, flags))
	rootCmd.AddCommand(NewKubernetesInClusterCmd(rootOpts, flags))
	rootCmd.AddCommand(NewDockerCmd(rootOpts, flags))
	rootCmd.AddCommand(NewImagesCmd(rootOpts, flags))
	rootCmd.AddCommand(NewCompletionCmd())

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

func createDefaultLogger(w io.Writer) {
	h := slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: validate.ProgramLevel,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		}})
	slog.SetDefault(slog.New(h))
}

// SetOutput sets the main command output writer.
func (r *RootCmd) SetOutput(w io.Writer) {
	r.c.SetOut(w)
	r.c.SetErr(w)
	createDefaultLogger(w)
}

func init() {
	createDefaultLogger(os.Stdout)
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
	root := NewRootCmd()
	if err := root.Execute(); err != nil {
		slog.With("err", err.Error()).Error("error executing driverkit")
		os.Exit(1)
	}
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if errs := configOptions.Validate(); errs != nil {
		for _, err := range errs {
			slog.With("err", err.Error()).Error("error validating config options")
		}
		// configOptions.configErrors should be true here
	}
	if configOptions.ConfigFile != "" {
		viper.SetConfigFile(configOptions.ConfigFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			slog.With("err", err.Error()).Debug("error getting the home directory")
			// not setting configOptions.configErrors = true because we fallback to `$HOME/.driverkit.yaml` and try with it
		}

		viper.AddConfigPath(home)
		viper.SetConfigName(".driverkit")
	}

	viper.AutomaticEnv()
	viper.SetEnvPrefix("driverkit")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		slog.With("file", viper.ConfigFileUsed()).Info("using config file")
	} else {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found, ignore ...
			slog.Debug("running without a configuration file")
		} else {
			// Config file was found but another error was produced
			slog.With("file", viper.ConfigFileUsed(), "err", err.Error()).Debug("error running with config file")
			configOptions.configErrors = true
		}
	}
}
