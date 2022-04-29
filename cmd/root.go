package cmd

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/falcosecurity/driverkit/pkg/driverbuilder/builder"
	"github.com/falcosecurity/driverkit/pkg/version"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	homedir "github.com/mitchellh/go-homedir"
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func persistentValidateFunc(rootCommand *RootCmd, rootOpts *RootOptions) func(c *cobra.Command, args []string) error {
	return func(c *cobra.Command, args []string) error {
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
		})

		// Avoid sensitive info into default values help line
		rootCommand.StripSensitive()

		// Do not block root or help command to exec disregarding the root flags validity
		if c.Root() != c && c.Name() != "help" && c.Name() != "__complete" && c.Name() != "__completeNoDesc" && c.Name() != "completion" {
			if errs := rootOpts.Validate(); errs != nil {
				for _, err := range errs {
					logger.WithError(err).Error("error validating build options")
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
				logger.WithField("processors", validProcessors).Info("specify a valid processor")
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

	flags.StringVarP(&configOptions.ConfigFile, "config", "c", configOptions.ConfigFile, "config file path (default $HOME/.driverkit.yaml if exists)")
	flags.StringVarP(&configOptions.LogLevel, "loglevel", "l", configOptions.LogLevel, "log level")
	flags.IntVar(&configOptions.Timeout, "timeout", configOptions.Timeout, "timeout in seconds")
	flags.BoolVar(&configOptions.DryRun, "dryrun", configOptions.DryRun, "do not actually perform the action")
	flags.StringVar(&configOptions.ProxyURL, "proxy", configOptions.ProxyURL, "the proxy to use to download data")

	flags.StringVar(&rootOpts.Output.Module, "output-module", rootOpts.Output.Module, "filepath where to save the resulting kernel module")
	flags.StringVar(&rootOpts.Output.Probe, "output-probe", rootOpts.Output.Probe, "filepath where to save the resulting eBPF probe")
	flags.StringVar(&rootOpts.Architecture, "architecture", runtime.GOARCH, "target architecture for the built driver")
	flags.StringVar(&rootOpts.DriverVersion, "driverversion", rootOpts.DriverVersion, "driver version as a git commit hash or as a git tag")
	flags.Uint16Var(&rootOpts.KernelVersion, "kernelversion", rootOpts.KernelVersion, "kernel version to build the module for, it's the numeric value after the hash when you execute 'uname -v'")
	flags.StringVar(&rootOpts.KernelRelease, "kernelrelease", rootOpts.KernelRelease, "kernel release to build the module for, it can be found by executing 'uname -v'")
	flags.StringVarP(&rootOpts.Target, "target", "t", rootOpts.Target, "the system to target the build for")
	flags.StringVar(&rootOpts.KernelConfigData, "kernelconfigdata", rootOpts.KernelConfigData, "base64 encoded kernel config data: in some systems it can be found under the /boot directory, in other it is gzip compressed under /proc")
	flags.StringVar(&rootOpts.ModuleDeviceName, "moduledevicename", rootOpts.ModuleDeviceName, "kernel module device name (the default is falco, so the device will be under /dev/falco*)")
	flags.StringVar(&rootOpts.ModuleDriverName, "moduledrivername", rootOpts.ModuleDriverName, "kernel module driver name, i.e. the name you see when you check installed modules via lsmod")
	flags.StringVar(&rootOpts.BuilderImage, "builderimage", rootOpts.BuilderImage, "docker image to be used to build the kernel module and eBPF probe. If not provided, the default image will be used.")
	viper.BindPFlags(flags)

	// Flag annotations and custom completions
	rootCmd.MarkFlagFilename("config", viper.SupportedExts...)
	rootCmd.RegisterFlagCompletionFunc("target", func(c *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		targets := builder.BuilderByTarget.Targets()
		sort.Strings(targets)
		return targets, cobra.ShellCompDirectiveDefault
	})

	// Subcommands
	rootCmd.AddCommand(NewKubernetesCmd(rootOpts, flags))
	rootCmd.AddCommand(NewDockerCmd(rootOpts, flags))
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

// SetOutput sets the main command output writer.
func (r *RootCmd) SetOutput(w io.Writer) {
	r.c.SetOut(w)
	r.c.SetErr(w)
	logger.SetOutput(w)
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
		logger.WithError(err).Fatal("error executing driverkit")
	}
}

func init() {
	logger.SetFormatter(&logger.TextFormatter{
		ForceColors:            true,
		DisableLevelTruncation: false,
		DisableTimestamp:       true,
	})

	cobra.OnInitialize(initConfig)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if errs := configOptions.Validate(); errs != nil {
		for _, err := range errs {
			logger.WithError(err).Error("error validating config options")
		}
		// configOptions.configErrors should be true here
	}
	if configOptions.ConfigFile != "" {
		viper.SetConfigFile(configOptions.ConfigFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			logger.WithError(err).Debug("error getting the home directory")
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
		logger.WithField("file", viper.ConfigFileUsed()).Info("using config file")
	} else {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found, ignore ...
			logger.Debug("running without a configuration file")
		} else {
			// Config file was found but another error was produced
			logger.WithField("file", viper.ConfigFileUsed()).WithError(err).Debug("error running with config file")
			configOptions.configErrors = true
		}
	}
}
