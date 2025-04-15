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
	"errors"
	"github.com/falcosecurity/falcoctl/pkg/output"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"io"
	"os"
	"strings"

	"github.com/creasty/defaults"
	"github.com/falcosecurity/driverkit/validate"
	"github.com/go-playground/validator/v10"
	"github.com/pterm/pterm"
)

var validProcessors = []string{"docker", "kubernetes", "kubernetes-in-cluster", "local"}
var aliasProcessors = []string{"docker", "k8s", "k8s-ic"}

// ConfigOptions represent the persistent configuration flags of driverkit.
type ConfigOptions struct {
	configFile string
	Timeout    int    `validate:"number,min=30" default:"120" name:"timeout"`
	ProxyURL   string `validate:"omitempty,proxy" name:"proxy url"`
	dryRun     bool

	// Printer used by all commands to output messages.
	Printer *output.Printer
	// writer is used to write the output of the printer.
	writer         io.Writer
	logLevel       *output.LogLevel
	disableStyling bool
}

func (co *ConfigOptions) initPrinter() {
	// DisableStyling is only enforced by tests.
	if co.disableStyling {
		pterm.DisableStyling()
	}
	co.Printer = output.NewPrinter(co.logLevel.ToPtermLogLevel(), pterm.LogFormatterColorful, co.writer)
	if co.disableStyling {
		// Disable time print for tests
		co.Printer.Logger = co.Printer.Logger.WithTime(false)
	}

}

// Called by tests to disable styling and set bytes buffer as output
func (co *ConfigOptions) setOutput(writer io.Writer, disableStyling bool) {
	co.writer = writer
	co.disableStyling = disableStyling
	co.initPrinter()
}

// NewConfigOptions creates an instance of ConfigOptions.
func NewConfigOptions() (*ConfigOptions, error) {
	o := &ConfigOptions{
		writer:         os.Stdout,
		logLevel:       output.NewLogLevel(),
		disableStyling: false,
	}
	o.initPrinter()
	if err := defaults.Set(o); err != nil {
		// Return ConfigOptions anyway because we need the logger
		return o, err
	}
	return o, nil
}

// Validate validates the ConfigOptions fields.
func (co *ConfigOptions) validate() []error {
	if err := validate.V.Struct(co); err != nil {
		var errs validator.ValidationErrors
		errors.As(err, &errs)
		var errArr []error
		for _, e := range errs {
			// Translate each error one at a time
			errArr = append(errArr, errors.New(e.Translate(validate.T)))
		}
		return errArr
	}
	return nil
}

// AddFlags registers the common flags.
func (co *ConfigOptions) AddFlags(flags *pflag.FlagSet) {
	flags.StringVarP(&co.configFile, "config", "c", co.configFile, "config file path (default $HOME/.driverkit.yaml if exists)")
	flags.VarP(co.logLevel, "loglevel", "l", "set level for logs "+co.logLevel.Allowed())
	flags.IntVar(&co.Timeout, "timeout", co.Timeout, "timeout in seconds")
	flags.StringVar(&co.ProxyURL, "proxy", co.ProxyURL, "the proxy to use to download data")
	flags.BoolVar(&co.dryRun, "dryrun", co.dryRun, "do not actually perform the action")
}

// Init reads in config file and ENV variables if set.
func (co *ConfigOptions) Init() bool {
	configErr := false
	if errs := co.validate(); errs != nil {
		for _, err := range errs {
			co.Printer.Logger.Error("error validating config options",
				co.Printer.Logger.Args("err", err.Error()))
		}
		configErr = true
	}
	if co.configFile != "" {
		viper.SetConfigFile(co.configFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			co.Printer.Logger.Error("error getting the home directory",
				co.Printer.Logger.Args("err", err.Error()))
			// not setting configErr = true because we fallback to `$HOME/.driverkit.yaml` and try with it
		}

		viper.AddConfigPath(home)
		viper.SetConfigName(".driverkit")
	}

	viper.AutomaticEnv()
	viper.SetEnvPrefix("driverkit")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	// If a config file is found, read it in.
	err := viper.ReadInConfig()
	// Init printer with either read or existent one,
	// so that we can further log considering log level set.
	co.initPrinter()
	if err == nil {
		co.Printer.Logger.Info("using config file",
			co.Printer.Logger.Args("file", viper.ConfigFileUsed()))
	} else {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if errors.As(err, &configFileNotFoundError) {
			// Config file not found, ignore ...
			co.Printer.Logger.Debug("running without a configuration file")
		}
	}
	return configErr
}
