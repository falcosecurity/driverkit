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

//go:embed templates/vanilla.sh
var vanillaTemplate string

// vanilla is a driverkit target.
type vanilla struct {
}

// TargetTypeVanilla identifies the Vanilla target.
const TargetTypeVanilla Type = "vanilla"

func init() {
	BuilderByTarget[TargetTypeVanilla] = &vanilla{}
}

type vanillaTemplateData struct {
	commonTemplateData
	KernelDownloadURL  string
	KernelLocalVersion string
	IsTarGz            bool
}

func (v *vanilla) Name() string {
	return TargetTypeVanilla.String()
}

func (v *vanilla) TemplateScript() string {
	return vanillaTemplate
}

func (v *vanilla) URLs(kr kernelrelease.KernelRelease) ([]string, error) {
	return []string{fetchVanillaKernelURLFromKernelVersion(kr)}, nil
}

func (v *vanilla) TemplateData(c Config, kr kernelrelease.KernelRelease, urls []string) interface{} {
	return vanillaTemplateData{
		commonTemplateData: c.toTemplateData(v, kr),
		KernelDownloadURL:  urls[0],
		KernelLocalVersion: kr.FullExtraversion,
		IsTarGz:            strings.HasSuffix(urls[0], ".tar.gz"), // Since RC have a tar.gz format, we need to inform the build script
	}
}

func fetchVanillaKernelURLFromKernelVersion(kv kernelrelease.KernelRelease) string {
	// Note: even non RC are available as tar.gz; but tar.xz are much smaller
	// and thus much quicker to download. Let's keep tar.xz for non RC!
	// Numbers: 110M (tar.gz) vs 75M (tar.xz)
	if isRC(kv) {
		return fmt.Sprintf("https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/snapshot/linux-%s%s.tar.gz", kv.Fullversion, kv.FullExtraversion)
	}
	return fmt.Sprintf("https://cdn.kernel.org/pub/linux/kernel/v%d.x/linux-%s.tar.xz", kv.Major, kv.Fullversion)
}

func isRC(kv kernelrelease.KernelRelease) bool {
	return strings.Contains(kv.Extraversion, "rc")
}
