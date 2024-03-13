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

//go:embed templates/alinux_kernel.sh
var alinuxKernelTemplate string

//go:embed templates/alinux.sh
var alinuxTemplate string

// TargetTypeAlinux identifies the AliyunLinux 2 and 3 target.
const TargetTypeAlinux Type = "alinux"

func init() {
	byTarget[TargetTypeAlinux] = &alinux{}
}

type alinuxTemplateData struct {
	KernelDownloadURL string
}

type alinux struct {
}

func (c *alinux) Name() string {
	return TargetTypeAlinux.String()
}

func (c *alinux) TemplateKernelUrlsScript() string {
	return alinuxKernelTemplate
}

func (c *alinux) TemplateScript() string {
	return alinuxTemplate
}

func (c *alinux) URLs(kr kernelrelease.KernelRelease) ([]string, error) {
	return fetchAlinuxKernelURLS(kr), nil
}

func (c *alinux) KernelTemplateData(_ kernelrelease.KernelRelease, urls []string) interface{} {
	return alinuxTemplateData{
		KernelDownloadURL: urls[0],
	}
}

func fetchAlinuxKernelURLS(kr kernelrelease.KernelRelease) []string {
	alinuxReleases := []string{
		"2",
		"2.1903",
		"3",
	}

	urls := []string{}
	for _, r := range alinuxReleases {
		urls = append(urls, fmt.Sprintf(
			"http://mirrors.aliyun.com/alinux/%s/os/%s/Packages/kernel-devel-%s%s.rpm",
			r,
			kr.Architecture.ToNonDeb(),
			kr.Fullversion,
			kr.FullExtraversion,
		))
	}
	return urls
}
