package cmd

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	homedir "github.com/mitchellh/go-homedir"
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func persistentValidateFunc(rootCommand *cobra.Command, rootOpts *RootOptions) func(c *cobra.Command, args []string) error {
	return func(c *cobra.Command, args []string) error {
		// Merge environment variables or config file values into the RootOptions instance
		skip := map[string]bool{ // do not merge these
			"config":   true,
			"timeout":  true,
			"loglevel": true,
			"dryrun":   true,
		}
		nested := map[string]string{ // handle nested options in config file
			"output-module": "output.module",
			"output-probe":  "output.probe",
		}
		rootCommand.PersistentFlags().VisitAll(func(f *pflag.Flag) {
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
					rootCommand.PersistentFlags().Set(name, value)
				}
			}
		})

		// Do not block root or help command to exec disregarding the persistent flags validity
		if c.Root() != c && c.Name() != "help" {
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
		Args:                  cobra.OnlyValidArgs,
		DisableFlagsInUseLine: true,
		DisableAutoGenTag:     true,
		Run: func(c *cobra.Command, args []string) {
			if len(args) == 0 {
				logger.WithField("processors", validProcessors).Info("specify the processor")
			}
			// Fallback to help
			c.Help()
		},
	}
	rootCmd.PersistentPreRunE = persistentValidateFunc(rootCmd, rootOpts)

	flags := rootCmd.PersistentFlags()

	flags.StringVarP(&configOptions.ConfigFile, "config", "c", configOptions.ConfigFile, "config file path (default $HOME/.driverkit.yaml if exists)")
	flags.StringVarP(&configOptions.LogLevel, "loglevel", "l", configOptions.LogLevel, "log level")
	flags.IntVar(&configOptions.Timeout, "timeout", configOptions.Timeout, "timeout in seconds")
	flags.BoolVar(&configOptions.DryRun, "dryrun", configOptions.DryRun, "do not actually perform the action")

	flags.StringVar(&rootOpts.Output.Module, "output-module", rootOpts.Output.Module, "filepath where to save the resulting kernel module")
	flags.StringVar(&rootOpts.Output.Probe, "output-probe", rootOpts.Output.Probe, "filepath where to save the resulting eBPF probe")
	flags.StringVar(&rootOpts.DriverVersion, "driverversion", rootOpts.DriverVersion, "driver version as a git commit hash or as a git tag")
	flags.Uint16Var(&rootOpts.KernelVersion, "kernelversion", rootOpts.KernelVersion, "kernel version to build the module for, it's the numeric value after the hash when you execute 'uname -v'")
	flags.StringVar(&rootOpts.KernelRelease, "kernelrelease", rootOpts.KernelRelease, "kernel release to build the module for, it can be found by executing 'uname -v'")
	flags.StringVarP(&rootOpts.Target, "target", "t", rootOpts.Target, "the system to target the build for")
	flags.StringVar(&rootOpts.KernelConfigData, "kernelconfigdata", rootOpts.KernelConfigData, "base64 encoded kernel config data: in some systems it can be found under the /boot directory, in other it is gzip compressed under /proc")

	viper.BindPFlags(flags)

	// Subcommands
	rootCmd.AddCommand(NewKubernetesCmd(rootOpts))
	rootCmd.AddCommand(NewDockerCmd(rootOpts))

	return &RootCmd{
		c: rootCmd,
	}
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
		DisableLevelTruncation: true,
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
		logger.Fatal("exiting for validation errors")
	}
	if configOptions.ConfigFile != "" {
		viper.SetConfigFile(configOptions.ConfigFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			logger.WithError(err).Fatal("error getting the home directory")
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
			logger.WithField("file", viper.ConfigFileUsed()).WithError(err).Fatal("error running with config file")
		}
	}
}
