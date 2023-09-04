package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/creasty/defaults"
	"github.com/falcosecurity/driverkit/validate"
	"github.com/go-playground/validator/v10"
)

var validProcessors = []string{"docker", "kubernetes", "kubernetes-in-cluster"}
var aliasProcessors = []string{"docker", "k8s", "k8s-ic"}
var configOptions *ConfigOptions

// ConfigOptions represent the persistent configuration flags of driverkit.
type ConfigOptions struct {
	ConfigFile string
	LogLevel   string `validate:"loglevel" name:"log level" default:"INFO"`
	Timeout    int    `validate:"number,min=30" default:"120" name:"timeout"`
	ProxyURL   string `validate:"omitempty,proxy" name:"proxy url"`
	DryRun     bool

	configErrors bool
}

// NewConfigOptions creates an instance of ConfigOptions.
func NewConfigOptions() *ConfigOptions {
	o := &ConfigOptions{}
	if err := defaults.Set(o); err != nil {
		slog.With("err", err.Error(), "options", "ConfigOptions").Error("error setting driverkit options defaults")
		os.Exit(1)
	}
	return o
}

// Validate validates the ConfigOptions fields.
func (co *ConfigOptions) Validate() []error {
	if err := validate.V.Struct(co); err != nil {
		errors := err.(validator.ValidationErrors)
		errArr := []error{}
		for _, e := range errors {
			// Translate each error one at a time
			errArr = append(errArr, fmt.Errorf(e.Translate(validate.T)))
		}
		co.configErrors = true
		return errArr
	}
	return nil
}
