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
	"os"
	"runtime"
	"strings"

	"github.com/falcosecurity/falcoctl/pkg/output"
	"github.com/spf13/pflag"

	"github.com/creasty/defaults"
	"github.com/falcosecurity/driverkit/pkg/driverbuilder/builder"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"github.com/falcosecurity/driverkit/validate"
	"github.com/go-playground/validator/v10"
)

// OutputOptions wraps the driver that driverkit builds.
type OutputOptions struct {
	Module string `validate:"required,filepath,omitempty,endswith=.ko" name:"output module path"`
}

func (oo *OutputOptions) HasOutputs() bool {
	return oo.Module != ""
}

type RepoOptions struct {
	Org  string `default:"falcosecurity" name:"organization name"`
	Name string `default:"libs" name:"repo name"`
}

type Registry struct {
	Name      string `validate:"required_with=Username Password" name:"registry name"`
	Username  string `validate:"required_with=Registry Password" name:"registry username"`
	Password  string `validate:"required_with=Username Registry" name:"registry password"`
	PlainHTTP bool   `default:"false" name:"registry plain http"`
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
	BuilderImage     string   `validate:"omitempty,imagename" name:"builder image"`
	BuilderRepos     []string `default:"[\"docker.io/falcosecurity/driverkit-builder\"]" validate:"omitempty" name:"docker repositories to look for builder images or absolute path pointing to a yaml file containing builder images index"`
	GCCVersion       string   `validate:"omitempty,semvertolerant" name:"gcc version"`
	KernelUrls       []string `name:"kernel header urls"`
	Repo             RepoOptions
	Output           OutputOptions
	Registry         Registry
}

func init() {
	validate.V.RegisterStructValidation(RootOptionsLevelValidation, RootOptions{})
}

// NewRootOptions ...
func NewRootOptions() (*RootOptions, error) {
	rootOpts := &RootOptions{}
	if err := defaults.Set(rootOpts); err != nil {
		return nil, err
	}
	return rootOpts, nil
}

// Validate validates the RootOptions fields.
func (ro *RootOptions) Validate() []error {
	if err := validate.V.Struct(ro); err != nil {
		var errs validator.ValidationErrors
		errors.As(err, &errs)
		errArr := []error{}
		for _, e := range errs {
			// Translate each error one at a time.
			errArr = append(errArr, errors.New(e.Translate(validate.T)))
		}
		return errArr
	}

	// check that the kernel versions supports the module.
	kr := kernelrelease.FromString(ro.KernelRelease)
	kr.Architecture = kernelrelease.Architecture(ro.Architecture)
	if !kr.SupportsModule() {
		return []error{errors.New("module is not supported by given options")}
	}

	return nil
}

func (ro *RootOptions) AddFlags(flags *pflag.FlagSet, targets []string) {
	flags.StringVar(&ro.Output.Module, "output-module", ro.Output.Module, "filepath where to save the resulting kernel module")
	flags.StringVar(&ro.Architecture, "architecture", runtime.GOARCH, "target architecture for the built driver, one of "+kernelrelease.SupportedArchs.String())
	flags.StringVar(&ro.DriverVersion, "driverversion", ro.DriverVersion, "driver version as a git commit hash or as a git tag")
	flags.StringVar(&ro.KernelVersion, "kernelversion", ro.KernelVersion, "kernel version to build the module for, it's the numeric value after the hash when you execute 'uname -v'")
	flags.StringVar(&ro.KernelRelease, "kernelrelease", ro.KernelRelease, "kernel release to build the module for, it can be found by executing 'uname -v'")
	flags.StringVarP(&ro.Target, "target", "t", ro.Target, "the system to target the build for, one of ["+strings.Join(targets, ",")+"]")
	flags.StringVar(&ro.KernelConfigData, "kernelconfigdata", ro.KernelConfigData, "base64 encoded kernel config data: in some systems it can be found under the /boot directory, in other it is gzip compressed under /proc")
	flags.StringVar(&ro.ModuleDeviceName, "moduledevicename", ro.ModuleDeviceName, "kernel module device name (the default is falco, so the device will be under /dev/falco*)")
	flags.StringVar(&ro.ModuleDriverName, "moduledrivername", ro.ModuleDriverName, "kernel module driver name, i.e. the name you see when you check installed modules via lsmod")
	flags.StringVar(&ro.BuilderImage, "builderimage", ro.BuilderImage, "docker image to be used to build the kernel module. If not provided, an automatically selected image will be used.")
	flags.StringSliceVar(&ro.BuilderRepos, "builderrepo", ro.BuilderRepos, "list of docker repositories or yaml file (absolute path) containing builder images index with the format 'images: [ { target:<target>, name:<image-name>, arch: <arch>, tag: <imagetag>, gcc_versions: [ <gcc-tag> ] },...]', in descending priority order. Used to search for builder images. eg: --builderrepo myorg/driverkit-builder --builderrepo falcosecurity/driverkit-builder --builderrepo '/path/to/my/index.yaml'.")
	flags.StringVar(&ro.GCCVersion, "gccversion", ro.GCCVersion, "enforce a specific gcc version for the build")

	flags.StringSliceVar(&ro.KernelUrls, "kernelurls", nil, "list of kernel header urls (e.g. --kernelurls <URL1> --kernelurls <URL2> --kernelurls \"<URL3>,<URL4>\")")

	flags.StringVar(&ro.Repo.Org, "repo-org", ro.Repo.Org, "repository github organization")
	flags.StringVar(&ro.Repo.Name, "repo-name", ro.Repo.Name, "repository github name")

	flags.StringVar(&ro.Registry.Name, "registry-name", ro.Registry.Name, "registry name to which authenticate")
	flags.StringVar(&ro.Registry.Username, "registry-user", ro.Registry.Username, "registry username")
	flags.StringVar(&ro.Registry.Password, "registry-password", ro.Registry.Password, "registry password")
	flags.BoolVar(&ro.Registry.PlainHTTP, "registry-plain-http", ro.Registry.PlainHTTP, "allows interacting with remote registry via plain http requests")
}

// Log emits a log line containing the receiving RootOptions for debugging purposes.
//
// Call it only after validation.
func (ro *RootOptions) Log(printer *output.Printer) {
	printer.Logger.Debug("running with options",
		printer.Logger.Args(
			"output-module", ro.Output.Module,
			"driverversion", ro.DriverVersion,
			"kernelrelease", ro.KernelRelease,
			"kernelversion", ro.KernelVersion,
			"target", ro.Target,
			"arch", ro.Architecture,
			"kernelurls", ro.KernelUrls,
			"repo-org", ro.Repo.Org,
			"repo-name", ro.Repo.Name,
		))
}

func (ro *RootOptions) ToBuild(printer *output.Printer) *builder.Build {
	kernelConfigData := ro.KernelConfigData
	if len(kernelConfigData) == 0 {
		kernelConfigData = "bm8tZGF0YQ==" // no-data
	}

	build := &builder.Build{
		TargetType:        builder.Type(ro.Target),
		DriverVersion:     ro.DriverVersion,
		KernelVersion:     ro.KernelVersion,
		KernelRelease:     ro.KernelRelease,
		Architecture:      ro.Architecture,
		KernelConfigData:  kernelConfigData,
		ModuleFilePath:    ro.Output.Module,
		ModuleDriverName:  ro.ModuleDriverName,
		ModuleDeviceName:  ro.ModuleDeviceName,
		GCCVersion:        ro.GCCVersion,
		BuilderImage:      ro.BuilderImage,
		BuilderRepos:      ro.BuilderRepos,
		KernelUrls:        ro.KernelUrls,
		RepoOrg:           ro.Repo.Org,
		RepoName:          ro.Repo.Name,
		Images:            make(builder.ImagesMap),
		RegistryName:      ro.Registry.Name,
		RegistryUser:      ro.Registry.Username,
		RegistryPassword:  ro.Registry.Password,
		RegistryPlainHTTP: ro.Registry.PlainHTTP,
		Printer:           printer,
	}

	// loop over BuilderRepos to build the list ImagesListers based on the value of the builderRepo:
	// if it's a local path use FileImagesLister, otherwise use RepoImagesLister
	var (
		imageLister builder.ImagesLister
		err         error
	)
	for _, builderRepo := range build.BuilderRepos {
		if _, err = os.Stat(builderRepo); err == nil {
			imageLister, err = builder.NewFileImagesLister(builderRepo, build)
		} else {
			imageLister, err = builder.NewRepoImagesLister(builderRepo, build)
		}
		if err != nil {
			printer.Logger.Warn("skipping repo",
				printer.Logger.Args("repo", builderRepo, "err", err.Error()))
		} else {
			build.ImagesListers = append(build.ImagesListers, imageLister)
		}
	}

	// attempt the build in case it comes from an invalid config
	kr := build.KernelReleaseFromBuildConfig()
	if len(build.ModuleFilePath) > 0 && !kr.SupportsModule() {
		build.ModuleFilePath = ""
		printer.Logger.Warn("skipping build attempt of module for unsupported kernel release",
			printer.Logger.Args("kernelrelease", kr.String()))
	}
	return build
}

// RootOptionsLevelValidation validates KernelConfigData and Target at the same time.
//
// It reports an error when `KernelConfigData` is empty and `Target` is `vanilla`.
func RootOptionsLevelValidation(level validator.StructLevel) {
	opts := level.Current().Interface().(RootOptions)

	if opts.Target == builder.TargetTypeVanilla.String() ||
		opts.Target == builder.TargetTypeMinikube.String() ||
		opts.Target == builder.TargetTypeFlatcar.String() {
		if len(opts.KernelConfigData) == 0 {
			level.ReportError(opts.KernelConfigData, "kernelConfigData", "KernelConfigData", "required_kernelconfigdata_with_target_vanilla", "")
		}
	}

	if opts.KernelVersion == "" && (opts.Target == builder.TargetTypeUbuntu.String()) {
		level.ReportError(opts.KernelVersion, "kernelVersion", "KernelVersion", "required_kernelversion_with_target_ubuntu", "")
	}

	// Target redhat requires a valid build image (has to be registered in order to download packages)
	if opts.Target == builder.TargetTypeRedhat.String() && opts.BuilderImage == "" {
		level.ReportError(opts.BuilderImage, "builderimage", "builderimage", "required_builderimage_with_target_redhat", "")
	}
}
