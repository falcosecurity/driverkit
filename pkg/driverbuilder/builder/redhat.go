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

//go:embed templates/redhat_kernel.sh
var redhatKernelTemplate string

//go:embed templates/redhat.sh
var redhatTemplate string

// TargetTypeRedhat identifies the redhat target.
const TargetTypeRedhat Type = "redhat"

// redhat is a driverkit target.
type redhat struct {
}

func init() {
	byTarget[TargetTypeRedhat] = &redhat{}
}

type redhatTemplateData struct {
	KernelPackage string
}

func (v *redhat) Name() string {
	return TargetTypeRedhat.String()
}

func (v *redhat) TemplateKernelUrlsScript() string {
	return redhatKernelTemplate
}

func (v *redhat) TemplateScript() string {
	return redhatTemplate
}

func (v *redhat) URLs(_ kernelrelease.KernelRelease) ([]string, error) {
	return nil, nil
}

func (v *redhat) MinimumURLs() int {
	// We don't need any url
	return 0
}

func (v *redhat) KernelTemplateData(kr kernelrelease.KernelRelease, _ []string) interface{} {
	return redhatTemplateData{
		KernelPackage: kr.Fullversion + kr.FullExtraversion,
	}
}
