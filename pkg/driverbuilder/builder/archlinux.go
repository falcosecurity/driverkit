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

//go:embed templates/archlinux_kernel.sh
var archlinuxKernelTemplate string

//go:embed templates/archlinux.sh
var archlinuxTemplate string

// TargetTypeArchlinux identifies the Archlinux target.
const TargetTypeArchlinux Type = "arch"

func init() {
	byTarget[TargetTypeArchlinux] = &archlinux{}
}

// archlinux is a driverkit target.
type archlinux struct {
}

type archlinuxTemplateData struct {
	KernelDownloadURL string
}

func (c *archlinux) Name() string {
	return TargetTypeArchlinux.String()
}

func (c *archlinux) TemplateKernelUrlsScript() string { return archlinuxKernelTemplate }

func (c *archlinux) TemplateScript() string {
	return archlinuxTemplate
}

func (c *archlinux) URLs(kr kernelrelease.KernelRelease) ([]string, error) {
	// uname -r returns "6.8.1-arch1-1" but headers URL is "6.8.1.arch1-1"
	// Also, for 0-patch releases, like: "6.8.0-arch1-1", headers url is "6.8.arch1-1"
	kr.FullExtraversion = strings.Replace(kr.FullExtraversion, "-arch", ".arch", 1)
	if kr.Patch == 0 {
		kr.Fullversion = strings.TrimSuffix(kr.Fullversion, ".0")
	}

	urls := []string{}
	possibleCompressionSuffixes := []string{
		"xz",
		"zst",
	}

	// check the architecture, which limits the mirror options
	if kr.Architecture.ToNonDeb() == "x86_64" {
		if strings.Contains(kr.FullExtraversion, "arch") { // arch stable kernel
			baseURL := "https://archive.archlinux.org/packages/l/linux-headers"
			for _, compressionAlgo := range possibleCompressionSuffixes {
				urls = append(
					urls,
					fmt.Sprintf(
						"%s/linux-headers-%s-%s-%s.pkg.tar.%s",
						baseURL,
						kr.String(),
						kr.KernelVersion,
						kr.Architecture.ToNonDeb(),
						compressionAlgo,
					),
				)
			}
		} else if strings.Contains(kr.FullExtraversion, "hardened") || strings.Contains(kr.FullExtraversion, ".a-1") { // arch hardened kernel ("a-1" is old naming standard)
			baseURL := "https://archive.archlinux.org/packages/l/linux-hardened-headers"
			for _, compressionAlgo := range possibleCompressionSuffixes {
				urls = append(
					urls,
					fmt.Sprintf(
						"%s/linux-hardened-headers-%s-%s-%s.pkg.tar.%s",
						baseURL,
						kr.String(),
						kr.KernelVersion,
						kr.Architecture.ToNonDeb(),
						compressionAlgo,
					),
				)
			}
		} else if strings.Contains(kr.FullExtraversion, "zen") { // arch zen kernel
			baseURL := "https://archive.archlinux.org/packages/l/linux-zen-headers"
			for _, compressionAlgo := range possibleCompressionSuffixes {
				urls = append(
					urls,
					fmt.Sprintf(
						"%s/linux-zen-headers-%s-%s-%s.pkg.tar.%s",
						baseURL,
						kr.String(),
						kr.KernelVersion,
						kr.Architecture.ToNonDeb(),
						compressionAlgo,
					),
				)
			}
		} else { // arch LTS kernel
			baseURL := "https://archive.archlinux.org/packages/l/linux-lts-headers"
			for _, compressionAlgo := range possibleCompressionSuffixes {
				urls = append(
					urls,
					fmt.Sprintf(
						"%s/linux-lts-headers-%s-%s-%s.pkg.tar.%s",
						baseURL,
						kr.String(),
						kr.KernelVersion,
						kr.Architecture.ToNonDeb(),
						compressionAlgo,
					),
				)
			}
		}
	} else if kr.Architecture.ToNonDeb() == "aarch64" {
		baseURL := "https://alaa.ad24.cz/packages/l/linux-aarch64-headers/"
		for _, compressionAlgo := range possibleCompressionSuffixes {
			urls = append(
				urls,
				fmt.Sprintf(
					"%s/linux-aarch64-headers-%s-%s-%s.pkg.tar.%s",
					baseURL,
					kr.String(),
					kr.KernelVersion,
					kr.Architecture.ToNonDeb(),
					compressionAlgo,
				),
			)
		}
	}

	return urls, nil
}

func (c *archlinux) KernelTemplateData(_ kernelrelease.KernelRelease, urls []string) interface{} {
	return archlinuxTemplateData{
		KernelDownloadURL: urls[0],
	}
}
