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
	"github.com/blang/semver"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

// TargetTypeMinikube identifies the Minikube target.
const TargetTypeMinikube Type = "minikube"

func init() {
	BuilderByTarget[TargetTypeMinikube] = &minikube{
		vanilla{},
	}
}

type minikube struct {
	vanilla
}

func (m *minikube) Name() string {
	return TargetTypeMinikube.String()
}

func (m *minikube) TemplateData(c Config, kr kernelrelease.KernelRelease, urls []string) interface{} {
	return vanillaTemplateData{
		commonTemplateData: c.toTemplateData(m, kr),
		KernelDownloadURL:  urls[0],
		KernelLocalVersion: kr.FullExtraversion,
	}
}

func (m *minikube) GCCVersion(kr kernelrelease.KernelRelease) semver.Version {
	// The supported versions of minikube use kernels > 4.19.
	switch kr.Major {
	case 5:
		return semver.Version{Major: 10}
	case 4:
		return semver.Version{Major: 8}
	default:
		return semver.Version{Major: 12}
	}
}
