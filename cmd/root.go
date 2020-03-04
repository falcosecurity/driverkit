package cmd

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	homedir "github.com/mitchellh/go-homedir"
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func persistentValidateFunc(rootCommand *cobra.Command, rootOpts *RootOptions) func(c *cobra.Command, args []string) {
	return func(c *cobra.Command, args []string) {
		// Merge environment variables or config file values into the RootOptions instance
		rootCommand.PersistentFlags().VisitAll(func(f *pflag.Flag) {
			switch f.Name {
			case "output":
				fallthrough
			case "moduleversion":
				fallthrough
			case "kerenlversion":
				fallthrough
			case "kernelrelease":
				fallthrough
			case "target":
				fallthrough
			case "kernelconfigdata":
				if val := viper.Get(f.Name); val != "" {
					switch f.Value.Type() {
					case "uint16":
						rootCommand.PersistentFlags().Set(f.Name, strconv.Itoa(val.(int)))
						break
					case "string":
						fallthrough
					default:
						rootCommand.PersistentFlags().Set(f.Name, val.(string))
						break
					}
				}
			}
		})

		if errs := rootOpts.Validate(); errs != nil {
			for _, err := range errs {
				logger.WithError(err).Error("error validating build options")
			}
			logger.Fatal("exiting for validation errors")
		}
	}
}

// NewRootCmd ...
func NewRootCmd() *cobra.Command {
	configOptions = NewConfigOptions()
	rootOpts := NewRootOptions()
	rootCmd := &cobra.Command{
		Use:   "driverkit",
		Short: "A command line tool to build Falco kernel modules and eBPF probes.",
		Run: func(c *cobra.Command, args []string) {
			// This is needed to make `PersistentPreRunE` always run
		},
	}
	rootCmd.PersistentPreRun = persistentValidateFunc(rootCmd, rootOpts)

	flags := rootCmd.PersistentFlags()

	flags.StringVarP(&configOptions.ConfigFile, "config", "c", configOptions.ConfigFile, "config file path (default $HOME/.driverkit.yaml if exists)")
	flags.StringVarP(&configOptions.LogLevel, "loglevel", "l", configOptions.LogLevel, "log level")
	flags.IntVar(&configOptions.Timeout, "timeout", configOptions.Timeout, "timeout in seconds")

	flags.StringVarP(&rootOpts.Output, "output", "o", rootOpts.Output, "filepath where to save the resulting kernel module")
	flags.StringVar(&rootOpts.ModuleVersion, "moduleversion", rootOpts.ModuleVersion, "kernel module version as a git reference")
	flags.Uint16Var(&rootOpts.KernelVersion, "kernelversion", rootOpts.KernelVersion, "kernel version to build the module for, it's the numeric value after the hash when you execute 'uname -v'")
	flags.StringVar(&rootOpts.KernelRelease, "kernelrelease", rootOpts.KernelRelease, "kernel release to build the module for, it can be found by executing 'uname -v'")
	flags.StringVarP(&rootOpts.Target, "target", "t", rootOpts.Target, "the system to target the build for")
	flags.StringVar(&rootOpts.KernelConfigData, "kernelconfigdata", rootOpts.KernelConfigData, "kernel config data, base64 encoded. In some systems this can be found under the /boot directory, in oder is gzip compressed under /proc")

	viper.BindPFlags(flags)

	// Subcommands
	rootCmd.AddCommand(NewKubernetesCmd(rootOpts))
	rootCmd.AddCommand(NewDockerCmd(rootOpts))

	// Override help on all the commands tree
	walk(rootCmd, func(c *cobra.Command) {
		c.Flags().BoolP("help", "h", false, fmt.Sprintf("help for the %s command", c.Name()))
	})

	return rootCmd
}

// Start creates the root command and runs it.
func Start() {
	root := NewRootCmd()
	if err := root.Execute(); err != nil {
		logger.WithError(err).Fatal("error executing driverkit")
	}
}

func init() {
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
		logger.WithField("file", viper.ConfigFileUsed()).Info("Using config file")
	} else {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found, ignore ...
			logger.Debug("Running without a configuration file")
		} else {
			// Config file was found but another error was produced
			logger.WithField("file", viper.ConfigFileUsed()).WithError(err).Fatal("Error running with config file")
		}
	}
}
