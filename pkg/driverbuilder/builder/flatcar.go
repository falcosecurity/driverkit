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
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/blang/semver/v4"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

//go:embed templates/flatcar_kernel.sh
var flatcarKernelTemplate string

//go:embed templates/flatcar.sh
var flatcarTemplate string

// TargetTypeFlatcar identifies the Flatcar target.
const TargetTypeFlatcar Type = "flatcar"

func init() {
	byTarget[TargetTypeFlatcar] = &flatcar{}
}

type flatcarTemplateData struct {
	KernelDownloadURL string
}

// flatcar is a driverkit target.
type flatcar struct {
	info *flatcarReleaseInfo
}

func (f *flatcar) Name() string {
	return TargetTypeFlatcar.String()
}

func (f *flatcar) TemplateKernelUrlsScript() string {
	return flatcarKernelTemplate
}

func (f *flatcar) TemplateScript() string {
	return flatcarTemplate
}

func (f *flatcar) URLs(kr kernelrelease.KernelRelease) ([]string, error) {
	if err := f.fillFlatcarInfos(kr); err != nil {
		return nil, err
	}
	return fetchFlatcarKernelURLS(f.info.KernelVersion), nil
}

func (f *flatcar) KernelTemplateData(kr kernelrelease.KernelRelease, urls []string) interface{} {
	// This happens when `kernelurls` option is passed,
	// therefore URLs() method is not called.
	if f.info == nil {
		if err := f.fillFlatcarInfos(kr); err != nil {
			return err
		}
	}

	return flatcarTemplateData{
		KernelDownloadURL: urls[0],
	}
}

func (f *flatcar) GCCVersion(_ kernelrelease.KernelRelease) semver.Version {
	return f.info.GCCVersion
}

func (f *flatcar) fillFlatcarInfos(kr kernelrelease.KernelRelease) error {
	if kr.Extraversion != "" {
		return fmt.Errorf("unexpected extraversion: %s", kr.Extraversion)
	}

	// convert string to int
	if kr.Major < 1500 {
		return fmt.Errorf("not a valid flatcar release version: %d", kr.Major)
	}

	var err error
	f.info, err = fetchFlatcarMetadata(kr)
	return err
}

func fetchFlatcarKernelURLS(kernelVersion string) []string {
	kv := kernelrelease.FromString(kernelVersion)
	return []string{fetchVanillaKernelURLFromKernelVersion(kv)}
}

func fetchFlatcarMetadata(kr kernelrelease.KernelRelease) (*flatcarReleaseInfo, error) {
	flatcarInfo := flatcarReleaseInfo{}
	flatcarVersion := kr.Fullversion
	packageIndexUrl, err := GetResolvingURLs(fetchFlatcarPackageListURL(kr.Architecture, flatcarVersion))
	if err != nil {
		return nil, err
	}
	// first part of the URL is the channel
	flatcarInfo.Channel = strings.Split(packageIndexUrl[0], ".")[0][len("https://"):]
	resp, err := http.Get(packageIndexUrl[0])
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	packageListBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	packageList := string(packageListBytes)
	if len(packageListBytes) == 0 {
		return nil, fmt.Errorf("missing package list for %s", flatcarVersion)
	}

	gccVersion := ""
	kernelVersion := ""
	// structure of a package line is: category/name-version(-revision)::repository
	for _, pkg := range strings.Split(string(packageList), "\n") {
		if strings.HasPrefix(pkg, "sys-devel/gcc") {
			gccVersion = pkg[len("sys-devel/gcc-"):]
			gccVersion = strings.Split(gccVersion, "::")[0]
			gccVersion = strings.Split(gccVersion, "-")[0]
		}
		if strings.HasPrefix(pkg, "sys-kernel/coreos-kernel") {
			kernelVersion = pkg[len("sys-kernel/coreos-kernel-"):]
			kernelVersion = strings.Split(kernelVersion, "::")[0]
			kernelVersion = strings.Split(kernelVersion, "-")[0]
		}
	}
	flatcarInfo.GCCVersion, err = semver.ParseTolerant(gccVersion)
	if err != nil {
		return nil, err
	}
	flatcarInfo.KernelVersion = kernelVersion

	return &flatcarInfo, nil
}

func fetchFlatcarPackageListURL(architecture kernelrelease.Architecture, flatcarVersion string) []string {
	pattern := "https://%s.release.flatcar-linux.net/%s-usr/%s/flatcar_production_image_packages.txt"
	channels := []string{
		"stable",
		"beta",
		"alpha",
	}
	urls := []string{}
	for _, channel := range channels {
		urls = append(urls, fmt.Sprintf(pattern, channel, architecture.String(), flatcarVersion))
	}
	return urls
}

type flatcarReleaseInfo struct {
	Channel       string
	GCCVersion    semver.Version
	KernelVersion string
}
