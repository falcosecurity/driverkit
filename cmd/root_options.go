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
	"fmt"
	"log/slog"
	"os"

	"github.com/creasty/defaults"
	"github.com/falcosecurity/driverkit/pkg/driverbuilder/builder"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"github.com/falcosecurity/driverkit/validate"
	"github.com/go-playground/validator/v10"
)

// OutputOptions wraps the two drivers that driverkit builds.
type OutputOptions struct {
	Module string `validate:"required_without=Probe,filepath,omitempty,endswith=.ko" name:"output module path"`
	Probe  string `validate:"required_without=Module,filepath,omitempty,endswith=.o" name:"output probe path"`
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
func NewRootOptions() *RootOptions {
	rootOpts := &RootOptions{}
	if err := defaults.Set(rootOpts); err != nil {
		slog.With("err", err.Error(), "options", "RootOptions").Error("error setting driverkit options defaults")
		os.Exit(1)
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

	// check that the kernel versions supports at least one of probe and module
	kr := kernelrelease.FromString(ro.KernelRelease)
	kr.Architecture = kernelrelease.Architecture(ro.Architecture)
	if !kr.SupportsModule() && !kr.SupportsProbe() {
		return []error{fmt.Errorf("both module and probe are not supported by given options")}
	}

	return nil
}

// Log emits a log line containing the receiving RootOptions for debugging purposes.
//
// Call it only after validation.
func (ro *RootOptions) Log() {
	slog.Debug("running with options",
		"output-module", ro.Output.Module,
		"output-probe", ro.Output.Probe,
		"driverversion", ro.DriverVersion,
		"kernelrelease", ro.KernelRelease,
		"kernelversion", ro.KernelVersion,
		"target", ro.Target,
		"arch", ro.Architecture,
		"kernelurls", ro.KernelUrls,
		"repo-org", ro.Repo.Org,
		"repo-name", ro.Repo.Name,
	)
}

func (ro *RootOptions) ToBuild() *builder.Build {
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
		ProbeFilePath:     ro.Output.Probe,
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
			slog.With("err", err.Error()).Warn("Skipping repo", "repo", builderRepo)
		} else {
			build.ImagesListers = append(build.ImagesListers, imageLister)
		}
	}

	// attempt the build in case it comes from an invalid config
	kr := build.KernelReleaseFromBuildConfig()
	if len(build.ModuleFilePath) > 0 && !kr.SupportsModule() {
		build.ModuleFilePath = ""
		slog.Warn("Skipping build attempt of module for unsupported kernel release", "kernelrelease", kr.String())
	}
	if len(build.ProbeFilePath) > 0 && !kr.SupportsProbe() {
		build.ProbeFilePath = ""
		slog.Warn("Skipping build attempt of probe for unsupported kernel release", "kernelrelease", kr.String())
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
