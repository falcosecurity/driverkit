package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "build-service",
	Short: "Falco Build Service",
	Long:  "Command line tool to build Falco Kernel modules",
}

var logger *zap.Logger

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	logger, _ = zap.NewProduction()
	defer logger.Sync()
	if err := rootCmd.Execute(); err != nil {
		logger.Fatal("error", zap.Error(err))
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	pf := rootCmd.PersistentFlags()
	pf.StringVar(&cfgFile, "config", "", "config file (default is $HOME/.falco-build-service.yaml)")
	pf.StringP("output", "o", "", "filepath where to save the resulting kernel module")
	pf.String("moduleversion", "dev", "kernel module version as a git reference")
	pf.String("kernelversion", "1", "kernel version to build the module for, it's the numeric value after the hash when you execute 'uname -v'")
	pf.String("kernelrelease", "", "kernel release to build the module for, it can be found by executing 'uname -v'")
	pf.String("buildtype", "", "type of build to execute")
	pf.String("kernelconfigdata", "", "kernel config data, base64 encoded. In some systems this can be found under the /boot directory, in oder is gzip compressed under /proc")

	_ = cobra.MarkFlagRequired(pf, "output")
	_ = cobra.MarkFlagRequired(pf, "moduleversion")
	_ = cobra.MarkFlagRequired(pf, "kernelrelease")
	_ = cobra.MarkFlagRequired(pf, "kernelversion")
	_ = cobra.MarkFlagRequired(pf, "buildtype")

}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".falco-build-service" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".falco-build-service")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
