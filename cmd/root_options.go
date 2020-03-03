package cmd

import (
	"log"

	"github.com/creasty/defaults"
	"github.com/falcosecurity/driverkit/validate"
	"github.com/go-playground/validator/v10"
)

// RootOptions ...
type RootOptions struct {
	Output           string `validate:"required,file"`
	ModuleVersion    string `default:"dev" validate:"required,ascii"` // todo > semver validator?
	KernelVersion    string `validate:"required,number"`              // todo > semver validator?
	KernelRelease    string `validate:"required,ascii"`
	Target           string `validate:"oneof=vanilla ubuntu-generic ubuntu-aws"`
	KernelConfigData string `validate:"omitempty,base64"` // todo > tie to target field - e.g, `required_without_ubuntu`
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
	return validate.V.Struct(ro)
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
