package cmd

import (
	"fmt"

	"github.com/creasty/defaults"
	"github.com/falcosecurity/driverkit/pkg/driverbuilder/builder"
	"github.com/falcosecurity/driverkit/validate"
	"github.com/go-playground/validator/v10"
	logger "github.com/sirupsen/logrus"
)

// OutputOptions wraps the two drivers that driverkit builds.
type OutputOptions struct {
	Module string `validate:"required_without=Probe|required_without=Kernel,filepath,omitempty,endswith=.ko" name:"output module path"`
	Probe  string `validate:"required_without=Module|required_without=Kernel,filepath,omitempty,endswith=.o" name:"output probe path"`
	Kernel string `validate:"omitempty,required_without=Module|required_without=Probe,filepath,endswith=.tar" name:"kernel archive path"`
}

// RootOptions ...
type RootOptions struct {
	Architecture     string `default:"x86_64" validate:"required,oneof=x86_64" name:"architecture"`
	DriverVersion    string `default:"dev" validate:"required,eq=dev|sha1|semver" name:"driver version"`
	KernelVersion    uint16 `default:"1" validate:"omitempty,number" name:"kernel version"`
	KernelRelease    string `validate:"required,ascii" name:"kernel release"`
	Target           string `validate:"required,target" name:"target"`
	KernelConfigData string `validate:"omitempty,base64" name:"kernel config data"` // fixme > tag "name" does not seem to work when used at struct level, but works when used at inner level
	Output           OutputOptions
}

func init() {
	validate.V.RegisterStructValidation(RootOptionsLevelValidation, RootOptions{})
}

// NewRootOptions ...
func NewRootOptions() *RootOptions {
	rootOpts := &RootOptions{}
	if err := defaults.Set(rootOpts); err != nil {
		logger.WithError(err).WithField("options", "RootOptions").Fatal("error setting driverkit options defaults")
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

// Log emits a log line containing the receiving RootOptions for debugging purposes.
//
// Call it only **after** successfull validation.
func (ro *RootOptions) Log() {
	fields := logger.Fields{}
	if _, ok := ignoring["output.module"]; !ok && ro.Output.Module != "" {
		fields["output.module"] = ro.Output.Module
	}
	if _, ok := ignoring["output.probe"]; !ok && ro.Output.Probe != "" {
		fields["output.probe"] = ro.Output.Probe
	}
	if _, ok := ignoring["output.kernel"]; !ok && ro.Output.Kernel != "" {
		fields["output.kernel"] = ro.Output.Kernel
	}
	fields["driverversion"] = fmt.Sprintf("%.7s", ro.DriverVersion)
	fields["kernelrelease"] = ro.KernelRelease
	if _, ok := ignoring["kernelversion"]; !ok {
		fields["kernelversion"] = ro.KernelVersion
	}
	fields["target"] = ro.Target
	if _, ok := ignoring["kernelconfigdata"]; !ok {
		fields["kernelconfigdata"] = fmt.Sprintf("%.7s", ro.KernelConfigData)
	}

	logger.WithFields(fields).Debug("running with options")

	if len(ignoring) > 0 {
		logger.WithFields(ignoring).Debug("ignoring options")
	}
}

func (ro *RootOptions) toBuild() *builder.Build {
	return &builder.Build{
		TargetType:        builder.Type(ro.Target),
		DriverVersion:     ro.DriverVersion,
		KernelVersion:     ro.KernelVersion,
		KernelRelease:     ro.KernelRelease,
		Architecture:      ro.Architecture,
		KernelConfigData:  ro.KernelConfigData,
		ModuleFilePath:    ro.Output.Module,
		ProbeFilePath:     ro.Output.Probe,
		KernelArchivePath: ro.Output.Kernel,
	}
}

var ignoring logger.Fields

// RootOptionsLevelValidation validates KernelConfigData and Target at the same time.
//
// It reports an error when `KernelConfigData` is empty and `Target` is `vanilla`.
func RootOptionsLevelValidation(level validator.StructLevel) {
	o := level.Current().Interface().(RootOptions)
	ignoring = logger.Fields{}

	if len(o.KernelConfigData) == 0 && o.Target == builder.TargetTypeVanilla.String() {
		level.ReportError(o.KernelConfigData, "kernelconfigdata", "KernelConfigData", "required_kernelconfigdata_with_target_vanilla", "")
	}

	if o.KernelVersion <= 1 && (o.Target == builder.TargetTypeUbuntuAWS.String() || o.Target == builder.TargetTypeUbuntuGeneric.String()) {
		level.ReportError(o.KernelVersion, "kernelversion", "KernelVersion", "required_kernelversion_with_target_ubuntu", "")
	}

	// Ignoring
	if o.KernelVersion > 0 && o.Target != builder.TargetTypeUbuntuAWS.String() && o.Target != builder.TargetTypeUbuntuGeneric.String() {
		ignoring["kernelversion"] = o.KernelVersion
	}
	if len(o.Output.Kernel) > 0 && o.Target != builder.TargetTypeVanilla.String() {
		ignoring["output.kernel"] = o.Output.Kernel
	}
	if len(o.KernelConfigData) > 0 && o.Target != builder.TargetTypeVanilla.String() {
		ignoring["kernelconfigdata"] = fmt.Sprintf("%.7s", o.KernelConfigData)
	}
	if len(o.KernelConfigData) > 0 && o.Target == builder.TargetTypeVanilla.String() && len(o.Output.Module) == 0 && len(o.Output.Kernel) == 0 {
		ignoring["kernelconfigdata"] = fmt.Sprintf("%.7s", o.KernelConfigData)
	}
}
