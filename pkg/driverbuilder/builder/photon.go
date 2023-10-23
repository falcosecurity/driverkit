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
	"fmt"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

// TargetTypePhoton identifies the Photon target.
const TargetTypePhoton Type = "photon"

//go:embed templates/photonos.sh
var photonTemplate string

func init() {
	byTarget[TargetTypePhoton] = &photon{}
}

// photon is a driverkit target.
type photon struct {
}

type photonTemplateData struct {
	commonTemplateData
	KernelDownloadURL string
}

func (p *photon) Name() string {
	return TargetTypePhoton.String()
}

func (p *photon) TemplateScript() string {
	return photonTemplate
}

func (p *photon) URLs(kr kernelrelease.KernelRelease) ([]string, error) {
	return fetchPhotonKernelURLS(kr), nil
}

func (p *photon) TemplateData(cfg Config, kr kernelrelease.KernelRelease, urls []string) interface{} {
	return photonTemplateData{
		commonTemplateData: cfg.toTemplateData(p, kr),
		KernelDownloadURL:  urls[0],
	}
}

func fetchPhotonKernelURLS(kr kernelrelease.KernelRelease) []string {
	photonReleases := []string{
		"3.0",
		"4.0",
		"5.0",
	}

	var urls []string
	for _, r := range photonReleases {
		urls = append(urls, fmt.Sprintf(
			"https://packages.vmware.com/photon/%s/photon_%s_%s/%s/linux-devel-%s%s.x86_64.rpm",
			r,
			r,
			kr.Architecture.ToNonDeb(),
			kr.Architecture.ToNonDeb(),
			kr.Fullversion,
			kr.FullExtraversion,
		))
		urls = append(urls, fmt.Sprintf(
			"https://packages.vmware.com/photon/%s/photon_release_%s_%s/%s/linux-devel-%s%s.x86_64.rpm",
			r,
			r,
			kr.Architecture.ToNonDeb(),
			kr.Architecture.ToNonDeb(),
			kr.Fullversion,
			kr.FullExtraversion,
		))
		urls = append(urls, fmt.Sprintf(
			"https://packages.vmware.com/photon/%s/photon_updates_%s_%s/%s/linux-devel-%s%s.x86_64.rpm",
			r,
			r,
			kr.Architecture.ToNonDeb(),
			kr.Architecture.ToNonDeb(),
			kr.Fullversion,
			kr.FullExtraversion,
		))
	}
	return urls
}
