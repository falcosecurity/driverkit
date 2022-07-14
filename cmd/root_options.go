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
	Module string `validate:"required_without=Probe,filepath,omitempty,endswith=.ko" name:"output module path"`
	Probe  string `validate:"required_without=Module,filepath,omitempty,endswith=.o" name:"output probe path"`
}

// RootOptions ...
type RootOptions struct {
	Architecture     string   `validate:"required,architecture" name:"architecture"`
	DriverVersion    string   `default:"master" validate:"eq=master|sha1|semver" name:"driver version"`
	KernelVersion    string   `default:"1" validate:"omitempty" name:"kernel version"`
	ModuleDriverName string   `default:"falco" validate:"max=60" name:"kernel module driver name"`
	ModuleDeviceName string   `default:"falco" validate:"excludes=/,max=255" name:"kernel module device name"`
	KernelRelease    string   `validate:"required,ascii" name:"kernel release"`
	Target           string   `validate:"required,target" name:"target"`
	KernelConfigData string   `validate:"omitempty,base64" name:"kernel config data"` // fixme > tag "name" does not seem to work when used at struct level, but works when used at inner level
	BuilderImage     string   `validate:"imagename" name:"builder image"`
	KernelUrls       []string `name:"kernel header urls"`
	Output           OutputOptions
}

func init() {
	validate.V.RegisterStructValidation(RootOptionsLevelValidation, RootOptions{})
}

func (ro *RootOptions) SetDefaults() {
	if defaults.CanUpdate(ro.BuilderImage) {
		ro.BuilderImage = builder.BaseImage
	}
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
// Call it only after validation.
func (ro *RootOptions) Log() {
	fields := logger.Fields{}
	if ro.Output.Module != "" {
		fields["output-module"] = ro.Output.Module
	}
	if ro.Output.Probe != "" {
		fields["output-probe"] = ro.Output.Probe

	}
	if ro.DriverVersion != "" {
		fields["driverversion"] = ro.DriverVersion
	}
	if ro.KernelRelease != "" {
		fields["kernelrelease"] = ro.KernelRelease
	}
	if ro.KernelVersion != "" {
		fields["kernelversion"] = ro.KernelVersion
	}
	if ro.Target != "" {
		fields["target"] = ro.Target
	}
	fields["arch"] = ro.Architecture
	if len(ro.KernelUrls) > 0 {
		fields["kernelurls"] = ro.KernelUrls
	}

	logger.WithFields(fields).Debug("running with options")
}

func (ro *RootOptions) toBuild() *builder.Build {
	kernelConfigData := ro.KernelConfigData
	if len(kernelConfigData) == 0 {
		kernelConfigData = "bm8tZGF0YQ==" // no-data
	}

	return &builder.Build{
		TargetType:         builder.Type(ro.Target),
		DriverVersion:      ro.DriverVersion,
		KernelVersion:      ro.KernelVersion,
		KernelRelease:      ro.KernelRelease,
		Architecture:       ro.Architecture,
		KernelConfigData:   kernelConfigData,
		ModuleFilePath:     ro.Output.Module,
		ProbeFilePath:      ro.Output.Probe,
		ModuleDriverName:   ro.ModuleDriverName,
		ModuleDeviceName:   ro.ModuleDeviceName,
		CustomBuilderImage: ro.BuilderImage,
		KernelUrls:         ro.KernelUrls,
	}
}

// RootOptionsLevelValidation validates KernelConfigData and Target at the same time.
//
// It reports an error when `KernelConfigData` is empty and `Target` is `vanilla`.
func RootOptionsLevelValidation(level validator.StructLevel) {
	opts := level.Current().Interface().(RootOptions)

	if len(opts.KernelConfigData) == 0 && opts.Target == builder.TargetTypeVanilla.String() {
		level.ReportError(opts.KernelConfigData, "kernelConfigData", "KernelConfigData", "required_kernelconfigdata_with_target_vanilla", "")
	}

	if opts.KernelVersion == "" && (opts.Target == builder.TargetTypeUbuntu.String()) {
		level.ReportError(opts.KernelVersion, "kernelVersion", "KernelVersion", "required_kernelversion_with_target_ubuntu", "")
	}

	// Target redhat requires a valid build image (has to be registered in order to download packages)
	if opts.Target == builder.TargetTypeRedhat.String() && opts.BuilderImage == builder.BaseImage {
		level.ReportError(opts.BuilderImage, "builderimage", "builderimage", "required_builderimage_with_target_redhat", "")
	}
}
