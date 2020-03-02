package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var cfgFile string

// NewRootCmd ...
func NewRootCmd() *cobra.Command {
	rootOpts := NewRootOptions()
	rootCmd := &cobra.Command{
		Use:   "driverkit",
		Short: "A command line tool to build Falco kernel modules and eBPF probes.",
		// Run: func(c *cobra.Command, args []string) {
		// 	spew.Dump(rootOpts)
		// 	os.Exit(1)
		// },
	}

	flags := rootCmd.PersistentFlags()
	flags.StringVar(&rootOpts.ConfigFile, "config", rootOpts.ConfigFile, "config file path")

	initConfig(rootOpts.ConfigFile)

	flags.StringVarP(&rootOpts.Output, "output", "o", viper.GetString("output"), "filepath where to save the resulting kernel module")
	flags.StringVar(&rootOpts.ModuleVersion, "moduleversion", viper.GetString("moduleversion"), "kernel module version as a git reference")
	flags.StringVar(&rootOpts.KernelVersion, "kernelversion", viper.GetString("kernelversion"), "kernel version to build the module for, it's the numeric value after the hash when you execute 'uname -v'")
	flags.StringVar(&rootOpts.KernelRelease, "kernelrelease", viper.GetString("kernelrelease"), "kernel release to build the module for, it can be found by executing 'uname -v'")
	flags.StringVarP(&rootOpts.Target, "target", "t", viper.GetString("target"), "the system to target the build for")
	flags.StringVar(&rootOpts.KernelConfigData, "kernelconfigdata", viper.GetString("kernelconfigdata"), "kernel config data, base64 encoded. In some systems this can be found under the /boot directory, in oder is gzip compressed under /proc")

	viper.BindPFlags(flags)

	// Subcommands
	rootCmd.AddCommand(NewKubernetesCmd())
	rootCmd.AddCommand(NewDockerCmd())

	return rootCmd
}

var logger *zap.Logger

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	logger, _ = zap.NewProduction()
	defer logger.Sync()
	root := NewRootCmd()
	if err := root.Execute(); err != nil {
		logger.Fatal("error", zap.Error(err))
	}
}

// initConfig reads in config file and ENV variables if set.
func initConfig(configFile string) {
	if filepath.IsAbs(configFile) {
		viper.SetConfigFile(configFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		viper.SetConfigFile(filepath.Join(home, strings.TrimPrefix(configFile, "~/")))
	}

	viper.AutomaticEnv()
	viper.SetEnvPrefix("driverkit")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	} else {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error if desired
		} else {
			// Config file was found but another error was produced
		}
	}
}
