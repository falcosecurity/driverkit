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
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

// TargetTypeTalos identifies the Talos target.
const TargetTypeTalos Type = "talos"

func init() {
	BuilderByTarget[TargetTypeTalos] = &talos{
		vanilla{},
	}
}

type talos struct {
	vanilla
}

func (b *talos) Name() string {
	return TargetTypeTalos.String()
}

func (b *talos) TemplateData(c Config, kr kernelrelease.KernelRelease, urls []string) interface{} {
	return vanillaTemplateData{
		commonTemplateData: c.toTemplateData(b, kr),
		KernelDownloadURL:  urls[0],
		KernelLocalVersion: kr.FullExtraversion,
	}
}
