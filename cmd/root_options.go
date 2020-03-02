package cmd

import (
	"log"

	"github.com/creasty/defaults"
	"github.com/falcosecurity/driverkit/validate"
)

// RootOptions ...
type RootOptions struct {
	Output           string `validate:"required,file"`
	ModuleVersion    string `default:"dev" validate:"required,ascii"` // todo > semver validator?
	KernelVersion    string `validate:"required,number"`              // todo > semver validator?
	KernelRelease    string `validate:"required,ascii"`
	Target           string `validate:"oneof=vanilla ubuntu-generic ubuntu-aws"`
	KernelConfigData string `validate:"base64"` // todo > tie to target field - e.g, `required_without_ubuntu`
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
