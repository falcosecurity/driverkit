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

package builder

import (
	_ "embed"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

//go:embed templates/sles_kernel.sh
var slesKernelTemplate string

//go:embed templates/sles.sh
var slesTemplate string

// TargetTypeSLES identifies the sles target.
const TargetTypeSLES Type = "sles"

// sles is a driverkit target.
type sles struct {
}

func init() {
	byTarget[TargetTypeSLES] = &sles{}
}

type slesTemplateData struct {
	KernelPackage string
}

func (v *sles) Name() string {
	return TargetTypeSLES.String()
}

func (v *sles) TemplateKernelUrlsScript() string {
	return slesKernelTemplate
}

func (v *sles) TemplateScript() string {
	return slesTemplate
}

func (v *sles) URLs(_ kernelrelease.KernelRelease) ([]string, error) {
	return nil, nil
}

func (v *sles) MinimumURLs() int {
	// We don't need any url
	return 0
}

func (v *sles) KernelTemplateData(kr kernelrelease.KernelRelease, _ []string) interface{} {
	return slesTemplateData{
		KernelPackage: kr.Fullversion + kr.FullExtraversion,
	}
}

// sles requires docker to run with `--net=host` for builder images to work
// for more info, see the suse container connect README: https://github.com/SUSE/container-suseconnect
func (v *sles) BuilderImageNetMode() string {
	return "host"
}
