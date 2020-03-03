package cmd

import (
	"fmt"
	"log"
	"strings"

	"github.com/creasty/defaults"
	"github.com/falcosecurity/driverkit/validate"
	"github.com/go-playground/validator/v10"
)

// RootOptions ...
type RootOptions struct {
	Output           string `validate:"file" name:"output"`
	ModuleVersion    string `default:"dev" validate:"ascii" name:"module version"` // todo > semver validator?
	KernelVersion    string `validate:"number" name:"kernel version"`              // todo > semver validator?
	KernelRelease    string `validate:"required,ascii" name:"kernel release"`
	Target           string `validate:"oneof=vanilla ubuntu-generic ubuntu-aws" name:"target"`
	KernelConfigData string `validate:"omitempty,base64" name:"kernel config data"` // fixme > tag "name" does not seem to work when used at struct level, but works when used at inner level
}

func init() {
	validate.V.RegisterStructValidation(RootOptionsLevelValidation, RootOptions{})
}

// NewRootOptions ...
func NewRootOptions() *RootOptions {
	rootOpts := &RootOptions{}
	if err := defaults.Set(rootOpts); err != nil {
		log.Fatal(err)
	}
	// V.RegisterStructValidation(RootOptionsLevelValidation, RootOptions{})
	return rootOpts
}

// Validate validates the RootOptions fields.
func (ro *RootOptions) Validate() error {
	if err := validate.V.Struct(ro); err != nil {
		errors := err.(validator.ValidationErrors)
		errstr := ""
		for _, e := range errors {
			// Translate each error one at a time
			errstr += fmt.Sprintf("%s\n", e.Translate(validate.T))
		}
		strings.TrimSuffix(errstr, "\n")
		return fmt.Errorf(errstr)
	}
	return nil
}

// RootOptionsLevelValidation validates KernelConfigData and Target at the same time.
//
// It reports an error when `KernelConfigData` is empty and `Target` is `vanilla`.
func RootOptionsLevelValidation(level validator.StructLevel) {
	opts := level.Current().Interface().(RootOptions)

	if len(opts.KernelConfigData) == 0 && opts.Target == "vanilla" {
		level.ReportError(opts.KernelConfigData, "kernelConfigData", "KernelConfigData", "required_kernelconfigdata_with_target_vanilla", "")
	}
}
