package cmd

import (
	"fmt"
	"github.com/falcosecurity/driverkit/validate"
	"github.com/go-playground/validator/v10"
)

var configOptions ConfigOptions

type ConfigOptions struct {
	ConfigFile string
	LogLevel   string `validate:"logrus" name:"log level"`
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
		return errArr
	}
	return nil
}
