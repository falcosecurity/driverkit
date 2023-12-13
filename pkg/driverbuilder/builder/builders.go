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
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"text/template"

	"github.com/blang/semver"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

// DriverDirectory is the directory the processor uses to store the driver.
const (
	DriverDirectory = "/tmp/driver"
	cmakeCmdFmt     = `cmake -Wno-dev \
  -DUSE_BUNDLED_DEPS=On \
  -DCREATE_TEST_TARGETS=Off \
  -DBUILD_LIBSCAP_GVISOR=Off \
  -DBUILD_LIBSCAP_MODERN_BPF=Off \
  -DENABLE_DRIVERS_TESTS=Off \
  -DDRIVER_NAME=%s \
  -DPROBE_NAME=%s \
  -DBUILD_BPF=On \
  -DDRIVER_VERSION=%s \
  -DPROBE_VERSION=%s \
  -DGIT_COMMIT=%s \
  -DDRIVER_DEVICE_NAME=%s \
  -DPROBE_DEVICE_NAME=%s \
  .. && \
  sed -i s/'DRIVER_COMMIT ""'/'DRIVER_COMMIT "%s"'/g driver/src/driver_config.h`
)

var HeadersNotFoundErr = errors.New("kernel headers not found")

// Config contains all the configurations needed to build the kernel module or the eBPF probe.
type Config struct {
	DriverName      string
	DeviceName      string
	DownloadBaseURL string
	*Build
}

func (c Config) ToDriverFullPath() string {
	return path.Join(DriverDirectory, "build", "driver", fmt.Sprintf("%s.ko", c.DriverName))
}

func (c Config) ToProbeFullPath() string {
	return path.Join(DriverDirectory, "build", "driver", "bpf", "probe.o")
}

type commonTemplateData struct {
	DriverBuildDir    string
	ModuleDownloadURL string
	ModuleDriverName  string
	ModuleFullPath    string
	BuildModule       bool
	BuildProbe        bool
	GCCVersion        string
	CmakeCmd          string
}

// Builder represents a builder capable of generating a script for a driverkit target.
type Builder interface {
	Name() string
	TemplateScript() string
	URLs(kr kernelrelease.KernelRelease) ([]string, error)
	TemplateData(c Config, kr kernelrelease.KernelRelease, urls []string) interface{} // error return type is managed
}

// MinimumURLsBuilder is an optional interface
// to specify minimum number of requested headers urls
type MinimumURLsBuilder interface {
	MinimumURLs() int
}

func Script(b Builder, c Config, kr kernelrelease.KernelRelease) (string, error) {
	t := template.New(b.Name())
	parsed, err := t.Parse(b.TemplateScript())
	if err != nil {
		return "", err
	}

	var urls []string
	minimumURLs := 1
	if bb, ok := b.(MinimumURLsBuilder); ok {
		minimumURLs = bb.MinimumURLs()
	}

	if c.KernelUrls == nil {
		urls, err = b.URLs(kr)
		if err != nil {
			return "", err
		}
		// Only if returned urls array is not empty
		// Otherwise, it is up to the builder to return an error
		if len(urls) > 0 {
			// Check (and filter) existing kernels before continuing
			urls, err = GetResolvingURLs(urls)
		}
	} else {
		urls, err = GetResolvingURLs(c.KernelUrls)
	}
	if err != nil {
		return "", err
	}

	if len(urls) < minimumURLs {
		return "", fmt.Errorf("not enough headers packages found; expected %d, found %d", minimumURLs, len(urls))
	}

	td := b.TemplateData(c, kr, urls)
	if tdErr, ok := td.(error); ok {
		return "", tdErr
	}

	buf := bytes.NewBuffer(nil)
	err = parsed.Execute(buf, td)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

type GCCVersionRequestor interface {
	// GCCVersion returns the GCC version to be used.
	// If the returned value is empty, the default algorithm will be enforced.
	GCCVersion(kr kernelrelease.KernelRelease) semver.Version
}

func defaultGCC(kr kernelrelease.KernelRelease) semver.Version {
	switch kr.Major {
	case 6:
		if kr.Minor >= 6 {
			return semver.Version{Major: 13}
		}
		return semver.Version{Major: 12}
	case 5:
		if kr.Minor >= 15 {
			return semver.Version{Major: 12}
		}
		return semver.Version{Major: 11}
	case 4:
		return semver.Version{Major: 8}
	case 3:
		if kr.Minor >= 18 {
			return semver.Version{Major: 5}
		}
		return semver.Version{Major: 4, Minor: 9}
	case 2:
		return semver.Version{Major: 4, Minor: 8}
	default:
		return semver.Version{Major: 13}
	}
}

func mustParseTolerant(gccStr string) semver.Version {
	g, err := semver.ParseTolerant(gccStr)
	if err != nil {
		panic(err)
	}
	return g
}

// Algorithm.
// * always load images (note that it loads only images that provide gccversion, if set by user)
// * if user set a fixed gccversion, we are good to go
// * otherwise, try to fix the best-match gcc version provided by any of the loaded images;
// see below for algorithm explanation
func (b *Build) setGCCVersion(builder Builder, kr kernelrelease.KernelRelease) {
	if !b.hasCustomBuilderImage() {
		b.LoadImages()
	}

	if len(b.GCCVersion) > 0 {
		// If set from user, go on
		return
	}

	b.GCCVersion = "8" // default value

	// if builder implements "GCCVersionRequestor" interface -> use it
	// Else, fetch the best builder available from the kernelrelease version
	// using the deadly simple defaultGCC() algorithm
	// Always returns the nearest one
	var targetGCC semver.Version
	if bb, ok := builder.(GCCVersionRequestor); ok {
		targetGCC = bb.GCCVersion(kr)
	}
	// If builder implements GCCVersionRequestor but returns an empty semver.Version
	// it means that it does not want to manage this kernelrelease,
	// and instead wants to fallback to default algorithm
	if targetGCC.EQ(semver.Version{}) {
		targetGCC = defaultGCC(kr)
	}

	if b.hasCustomBuilderImage() {
		b.GCCVersion = targetGCC.String()
		return
	}

	// Step 1:
	// If we are able to either find a specific-target image,
	// or "any" target image that provide desired gcc,
	// we are over.
	image, ok := b.Images.findImage(b.TargetType, targetGCC)
	if ok {
		b.GCCVersion = image.GCCVersion.String()
	} else {
		// Step 2:
		// Build the list of "proposed" GCC versions,
		// that is, the list of available gccs from images
		// for each builder image
		proposedGCCs := make([]semver.Version, 0)
		for _, img := range b.Images {
			proposedGCCs = append(proposedGCCs, img.GCCVersion)
			slog.With("image", img.Name, "targetGCC", targetGCC.String()).
				Debug("proposedGCC", "version", img.GCCVersion.String())
		}

		// Now, sort versions and fetch
		// the nearest gcc, that is also < targetGCC
		semver.Sort(proposedGCCs)
		lastGCC := proposedGCCs[0]
		for _, gcc := range proposedGCCs {
			if gcc.GT(targetGCC) {
				break
			}
			lastGCC = gcc
		}
		b.GCCVersion = lastGCC.String()
	}
	slog.With("targetGCC", targetGCC.String()).
		Debug("foundGCC", "version", b.GCCVersion)
}

type BuilderImageNetworkMode interface {
	// sets the network mode of the builder image, allows individual builders to override
	BuilderImageNetMode() string
}

func (b *Build) GetBuilderImage() string {
	if b.hasCustomBuilderImage() {
		// BuilderImage MUST have requested GCC installed inside
		return b.BuilderImage
	}

	// NOTE: here below we are already sure that we are going
	// to find an image, because setGCCVersion()
	// has already set an existent gcc version
	// (ie: one provided by an image) for us
	image, _ := b.Images.findImage(b.TargetType, mustParseTolerant(b.GCCVersion))
	return image.Name
}

// Factory returns a builder for the given target.
func Factory(target Type) (Builder, error) {
	// Workaround for "local" target (that is not exposed to users,
	// nor registered in byTarget map)".
	if target.String() == "local" {
		return &LocalBuilder{}, nil
	}

	// Driverkit builder is named "ubuntu"; there is no ubuntu-foo
	if strings.HasPrefix(target.String(), "ubuntu") {
		target = Type("ubuntu")
	}

	b, ok := byTarget[target]
	if !ok {
		return nil, fmt.Errorf("no builder found for target: %s", target)
	}
	return b, nil
}

// Targets returns the list of all the supported targets.
func Targets() []string {
	res := []string{}
	for k := range byTarget {
		res = append(res, k.String())
	}
	return res
}

func (c Config) toTemplateData(b Builder, kr kernelrelease.KernelRelease) commonTemplateData {
	c.setGCCVersion(b, kr)
	return commonTemplateData{
		DriverBuildDir:    DriverDirectory,
		ModuleDownloadURL: fmt.Sprintf("%s/%s.tar.gz", c.DownloadBaseURL, c.DriverVersion),
		ModuleDriverName:  c.DriverName,
		ModuleFullPath:    c.ToDriverFullPath(),
		BuildModule:       len(c.ModuleFilePath) > 0,
		BuildProbe:        len(c.ProbeFilePath) > 0,
		GCCVersion:        c.GCCVersion,
		CmakeCmd: fmt.Sprintf(cmakeCmdFmt,
			c.DriverName,
			c.DriverName,
			c.DriverVersion,
			c.DriverVersion,
			c.DriverVersion,
			c.DeviceName,
			c.DeviceName,
			c.DriverVersion),
	}
}

func resolveURLReference(u string) string {
	uu, err := url.Parse(u)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	base, err := url.Parse(uu.Host)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	return base.ResolveReference(uu).String()
}

func GetResolvingURLs(urls []string) ([]string, error) {
	var results []string
	for _, u := range urls {
		// in case url has some relative paths
		// (kernel-crawler does not resolve them for us,
		// neither it is expected, because they are effectively valid urls),
		// resolve the absolute one.
		// HEAD would fail otherwise.
		u = resolveURLReference(u)
		res, err := http.Head(u)
		if err != nil {
			continue
		}
		if res.StatusCode == http.StatusOK {
			results = append(results, u)
			slog.With("url", u).Debug("kernel header url found")
		}
	}
	if len(results) == 0 {
		return nil, HeadersNotFoundErr
	}
	return results, nil
}
