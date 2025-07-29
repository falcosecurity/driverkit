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

package kernelrelease

import (
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"

	"github.com/blang/semver/v4"
)

var (
	kernelVersionPattern = regexp.MustCompile(`(?P<fullversion>^(?P<version>0|[1-9]\d*)\.(?P<patchlevel>0|[1-9]\d*)[.+]?(?P<sublevel>0|[1-9]\d*)?)(?P<fullextraversion>[-.+](?P<extraversion>\d+|\d*[a-zA-Z-][0-9a-zA-Z-]*)?([\.+~](\d+|\d*[a-zA-Z-][0-9a-zA-Z-_]*))*)?(\+[0-9a-zA-Z-]+(\.[0-9a-zA-Z-]+)*)?$`)
)

const (
	ArchitectureAmd64 = "amd64"
	ArchitectureArm64 = "arm64"
)

// Architectures is a Map [Architecture] -> non-deb-ArchitectureString
type Architectures map[Architecture]string

// SupportedArchs enforces the duality of architecture->non-deb one when adding a new one
var SupportedArchs = Architectures{
	ArchitectureAmd64: "x86_64",
	ArchitectureArm64: "aarch64",
}

// Privately cached at startup for quicker access
var supportedArchsSlice []string

// Represents the minimum kernel version for which building the module
// is supported, depending on the architecture.
// See compatibility matrix: https://falco.org/docs/event-sources/drivers/
var moduleMinKernelVersion = map[Architecture]semver.Version{
	ArchitectureAmd64: semver.MustParse("2.6.0"),
	ArchitectureArm64: semver.MustParse("3.16.0"),
}

// Represents the minimum kernel version for which building the probe
// is supported, depending on the architecture.
// See compatibility matrix: https://falco.org/docs/event-sources/drivers/
var probeMinKernelVersion = map[Architecture]semver.Version{
	ArchitectureAmd64: semver.MustParse("4.14.0"),
	ArchitectureArm64: semver.MustParse("4.17.0"),
}

func init() {
	i := 0
	supportedArchsSlice = make([]string, len(SupportedArchs))
	for k := range SupportedArchs {
		supportedArchsSlice[i] = k.String()
		i++
	}
}

func (aa Architectures) String() string {
	return "[" + strings.Join(supportedArchsSlice, ",") + "]"
}

func (aa Architectures) Strings() []string {
	return supportedArchsSlice
}

type Architecture string

func (a Architecture) ToNonDeb() string {
	if val, ok := SupportedArchs[a]; ok {
		return val
	}
	panic(fmt.Errorf("missing non-deb name for arch: %s", a.String()))
}

func (a Architecture) String() string {
	return string(a)
}

// KernelRelease contains all the version parts.
// NOTE: we cannot fetch Architecture from kernel string
// because it is not always provided.
// Instead, rely on the global option
// (it it set for builders in kernelReleaseFromBuildConfig())
type KernelRelease struct {
	Fullversion string
	semver.Version
	Extraversion     string
	FullExtraversion string
	Architecture     Architecture
	KernelVersion    string
}

// FromString extracts a KernelRelease object from string.
func FromString(kernelVersionStr string) KernelRelease {
	kv := KernelRelease{}
	match := kernelVersionPattern.FindStringSubmatch(kernelVersionStr)
	for i, name := range kernelVersionPattern.SubexpNames() {
		if i > 0 && i <= len(match) {
			var err error
			switch name {
			case "fullversion":
				kv.Fullversion = match[i]
			case "version":
				kv.Major, err = strconv.ParseUint(match[i], 10, 64)
			case "patchlevel":
				kv.Minor, err = strconv.ParseUint(match[i], 10, 64)
			case "sublevel":
				if len(match[i]) > 0 {
					// We accept a missing sublevel (defaulting to 0)
					// eg: 6.1.arch1-1
					kv.Patch, err = strconv.ParseUint(match[i], 10, 64)
				}
			case "extraversion":
				kv.Extraversion = match[i]
			case "fullextraversion":
				kv.FullExtraversion = match[i]
			}

			if err != nil {
				log.Fatal(err)
			}
		}
	}
	return kv
}

func (k *KernelRelease) SupportsModule() bool {
	return k.GTE(moduleMinKernelVersion[k.Architecture])
}

func (k *KernelRelease) SupportsProbe() bool {
	return k.GTE(probeMinKernelVersion[k.Architecture])
}

func (k *KernelRelease) String() string {
	return fmt.Sprintf("%s%s", k.Fullversion, k.FullExtraversion)
}
