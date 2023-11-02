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

//go:embed templates/sle.sh
var sleTemplate string

// TargetTypeSLE identifies the sle target.
const TargetTypeSLE Type = "sle"

// sle is a driverkit target.
type sle struct {
}

func init() {
	byTarget[TargetTypeSLE] = &sle{}
}

type sleTemplateData struct {
	commonTemplateData
	KernelPackage string
}

func (v *sle) Name() string {
	return TargetTypeSLE.String()
}

func (v *sle) TemplateScript() string {
	return sleTemplate
}

func (v *sle) URLs(kr kernelrelease.KernelRelease) ([]string, error) {
	return nil, nil
}

func (v *sle) MinimumURLs() int {
	// We don't need any url
	return 0
}

func (v *sle) TemplateData(c Config, kr kernelrelease.KernelRelease, _ []string) interface{} {
	return sleTemplateData{
		commonTemplateData: c.toTemplateData(v, kr),
		KernelPackage:      kr.Fullversion + kr.FullExtraversion,
	}
}
