package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var configFile string
var logger *zap.Logger

// NewRootCmd ...
func NewRootCmd() *cobra.Command {
	rootOpts := NewRootOptions()
	rootCmd := &cobra.Command{
		Use:   "driverkit",
		Short: "A command line tool to build Falco kernel modules and eBPF probes.",
		PersistentPreRun: func(c *cobra.Command, args []string) {
			// Merge environment variables or config file values into the options instance
			c.PersistentFlags().VisitAll(func(f *pflag.Flag) {
				if f.Name != "config" {
					if val := viper.Get(f.Name); val != "" {
						c.PersistentFlags().Set(f.Name, val.(string))
					}
				}
			})
			spew.Dump(rootOpts)
			if err := rootOpts.Validate(); err != nil {
				fmt.Fprintf(os.Stderr, err.Error())
				os.Exit(1)
			}
		},
		Run: func(c *cobra.Command, args []string) {
			// This is needed to make `PersistentPreRunE` always run
		},
	}

	flags := rootCmd.PersistentFlags()

	flags.StringVar(&configFile, "config", "", "config file path (default $HOME/.driverkit.yaml if exists)")

	flags.StringVarP(&rootOpts.Output, "output", "o", rootOpts.Output, "filepath where to save the resulting kernel module")
	flags.StringVar(&rootOpts.ModuleVersion, "moduleversion", rootOpts.ModuleVersion, "kernel module version as a git reference")
	flags.StringVar(&rootOpts.KernelVersion, "kernelversion", rootOpts.KernelVersion, "kernel version to build the module for, it's the numeric value after the hash when you execute 'uname -v'")
	flags.StringVar(&rootOpts.KernelRelease, "kernelrelease", rootOpts.KernelRelease, "kernel release to build the module for, it can be found by executing 'uname -v'")
	flags.StringVarP(&rootOpts.Target, "target", "t", rootOpts.Target, "the system to target the build for")
	flags.StringVar(&rootOpts.KernelConfigData, "kernelconfigdata", rootOpts.KernelConfigData, "kernel config data, base64 encoded. In some systems this can be found under the /boot directory, in oder is gzip compressed under /proc")

	viper.BindPFlags(flags)

	// Subcommands
	rootCmd.AddCommand(NewKubernetesCmd())
	rootCmd.AddCommand(NewDockerCmd())

	return rootCmd
}

// Start creates the root command and runs it.
func Start() {
	logger, _ = zap.NewProduction()
	defer logger.Sync()
	root := NewRootCmd()
	if err := root.Execute(); err != nil {
		logger.Fatal("error", zap.Error(err))
	}
}

func init() {
	cobra.OnInitialize(initConfig)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		viper.AddConfigPath(home)
		viper.SetConfigName(".driverkit")
	}

	viper.AutomaticEnv()
	viper.SetEnvPrefix("driverkit")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	} else {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found, ignore ...
			fmt.Println("Running without config file...")
		} else {
			// Config file was found but another error was produced
			fmt.Fprintf(os.Stderr, "Running with config file:%s\n", viper.ConfigFileUsed())
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}
	}
}
