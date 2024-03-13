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
	"strings"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

//go:embed templates/fedora_kernel.sh
var fedoraKernelTemplate string

//go:embed templates/fedora.sh
var fedoraTemplate string

// TargetTypeFedora identifies the Fedora target.
const TargetTypeFedora Type = "fedora"

func init() {
	byTarget[TargetTypeFedora] = &fedora{}
}

// fedora is a driverkit target.
type fedora struct {
}

type fedoraTemplateData struct {
	KernelDownloadURL string
}

func (c *fedora) Name() string {
	return TargetTypeFedora.String()
}

func (c *fedora) TemplateKernelUrlsScript() string { return fedoraKernelTemplate }

func (c *fedora) TemplateScript() string {
	return fedoraTemplate
}

func (c *fedora) URLs(kr kernelrelease.KernelRelease) ([]string, error) {

	// fedora FullExtraversion looks like "-200.fc36.x86_64"
	// need to get the "fc36" out of the middle
	fedoraVersion := strings.Split(kr.FullExtraversion, ".")[1]

	// trim off the "fc" from fedoraVersion
	version := strings.Trim(fedoraVersion, "fc")

	// template the kernel info into all possible URL strings
	urls := []string{
		fmt.Sprintf( // updates
			"https://mirrors.kernel.org/fedora/updates/%s/Everything/%s/Packages/k/kernel-devel-%s%s.rpm",
			version,
			kr.Architecture.ToNonDeb(),
			kr.Fullversion,
			kr.FullExtraversion,
		),
		fmt.Sprintf( // releases
			"https://mirrors.kernel.org/fedora/releases/%s/Everything/%s/os/Packages/k/kernel-devel-%s%s.rpm",
			version,
			kr.Architecture.ToNonDeb(),
			kr.Fullversion,
			kr.FullExtraversion,
		),
		fmt.Sprintf( // development
			"https://mirrors.kernel.org/fedora/development/%s/Everything/%s/os/Packages/k/kernel-devel-%s%s.rpm",
			version,
			kr.Architecture.ToNonDeb(),
			kr.Fullversion,
			kr.FullExtraversion,
		),
	}

	// return out all possible urls
	return urls, nil
}

func (c *fedora) KernelTemplateData(_ kernelrelease.KernelRelease, urls []string) interface{} {
	return fedoraTemplateData{
		KernelDownloadURL: urls[0],
	}
}
