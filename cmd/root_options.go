package cmd

import (
	"fmt"
	"github.com/creasty/defaults"
	"github.com/falcosecurity/driverkit/pkg/modulebuilder/build"
	"github.com/falcosecurity/driverkit/pkg/modulebuilder/buildtype"
	"github.com/falcosecurity/driverkit/validate"
	"github.com/go-playground/validator/v10"
	"log"
)

// RootOptions ...
type RootOptions struct {
	Output           string `validate:"filepath" name:"output"`
	Architecture     string `default:"x86_64" validate:"oneof=x86_64" name:"architecture"`
	ModuleVersion    string `default:"dev" validate:"ascii" name:"module version"` // todo > semver validator?
	KernelVersion    uint16 `validate:"number" name:"kernel version"`              // todo > semver validator?
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
	return rootOpts
}

// Validate validates the RootOptions fields.
func (ro *RootOptions) Validate() []error {
	if err := validate.V.Struct(ro); err != nil {
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


func (ro *RootOptions) toBuild() *build.Build {
	kernelConfigData := ro.KernelConfigData
	if len(kernelConfigData) == 0 {
		kernelConfigData = "bm8tZGF0YQ==" // no-data
	}

	return &build.Build{
		ModuleVersion:    ro.ModuleVersion,
		KernelVersion:    ro.KernelVersion,
		KernelRelease:    ro.KernelRelease,
		Architecture:     ro.Architecture,
		BuildType:        buildtype.BuildType(ro.Target),
		KernelConfigData: kernelConfigData,
		OutputFilePath:   ro.Output,
	}
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
