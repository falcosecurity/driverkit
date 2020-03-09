package builder

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"github.com/falcosecurity/driverkit/pkg/driverbuilder/buildtype"
)

const BuildTypeCentos = "centos"

func init() {
	buildtype.EnabledBuildTypes[BuildTypeCentos] = true
}

type Centos struct {
}

func (c Centos) Script(bc BuilderConfig) (string, error) {
	t := template.New(string(BuildTypeCentos))
	parsed, err := t.Parse(centosTemplate)
	if err != nil {
		return "", err
	}

	kr := kernelrelease.FromString(bc.Build.KernelRelease)

	// Check (and filter) existing kernels before continuing
	urls, err := getResolvingURLs(fetchCentosKernelURLS(kr))
	if err != nil {
		return "", err
	}

	td := centosTemplateData{
		ModuleBuildDir:    ModuleDirectory,
		ModuleDownloadURL: moduleDownloadURL(bc),
		KernelDownloadURL: urls[0],
		GCCVersion:        centosGccVersionFromKernelRelease(kr),
	}

	buf := bytes.NewBuffer(nil)
	err = parsed.Execute(buf, td)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func fetchCentosKernelURLS(kr kernelrelease.KernelRelease) []string {
	vaultReleases := []string{
		"6.0/os",
		"6.0/updates",
		"6.1/os",
		"6.1/updates",
		"6.2/os",
		"6.2/updates",
		"6.3/os",
		"6.3/updates",
		"6.4/os",
		"6.4/updates",
		"6.5/os",
		"6.5/updates",
		"6.6/os",
		"6.6/updates",
		"6.7/os",
		"6.7/updates",
		"6.8/os",
		"6.8/updates",
		"6.9/os",
		"6.9/updates",
		"6.10/os",
		"6.10/updates",
		"7.0.1406/os",
		"7.0.1406/updates",
		"7.1.1503/os",
		"7.1.1503/updates",
		"7.2.1511/os",
		"7.2.1511/updates",
		"7.3.1611/os",
		"7.3.1611/updates",
		"7.4.1708/os",
		"7.4.1708/updates",
		"7.5.1804/os",
		"7.5.1804/updates",
		"7.6.1810/os",
		"7.6.1810/updates",
		"7.7.1908/os",
		"7.7.1908/updates",
		"8.0.1905/os",
		"8.0.1905/updates",
		"8.1.1911/os",
		"8.1.1911/updates",
	}

	edgeReleases := []string{
		"6/os",
		"6/updates",
		"7/os",
		"7/updates",
	}

	streamReleases := []string{
		"8-stream/BaseOS",
		"8.0.1905/BaseOS",
	}

	urls := []string{}
	for _, r := range edgeReleases {
		urls = append(urls, fmt.Sprintf(
			"https://mirrors.edge.kernel.org/centos/%s/x86_64/Packages/kernel-devel-%s%s.rpm",
			r,
			kr.Fullversion,
			kr.FullExtraversion,
		))
	}
	for _, r := range streamReleases {
		urls = append(urls, fmt.Sprintf(
			"https://mirrors.edge.kernel.org/centos/%s/x86_64/os/Packages/kernel-devel-%s%s.rpm",
			r,
			kr.Fullversion,
			kr.FullExtraversion,
		))
	}
	for _, r := range vaultReleases {
		urls = append(urls, fmt.Sprintf(
			"http://vault.centos.org/%s/x86_64/Packages/kernel-devel-%s%s.rpm",
			r,
			kr.Fullversion,
			kr.FullExtraversion,
		))
	}
	return urls
}

type centosTemplateData struct {
	ModuleBuildDir    string
	ModuleDownloadURL string
	KernelDownloadURL string
	GCCVersion        string
}

const centosTemplate = `
#!/bin/bash
set -xeuo pipefail

rm -Rf {{ .ModuleBuildDir }}
mkdir {{ .ModuleBuildDir }}
rm -Rf /tmp/module-download
mkdir -p /tmp/module-download

curl --silent -SL {{ .ModuleDownloadURL }} | tar -xzf - -C /tmp/module-download
mv /tmp/module-download/*/driver/* {{ .ModuleBuildDir }}

cp /module-builder/module-Makefile {{ .ModuleBuildDir }}/Makefile
cp /module-builder/module-driver-config.h {{ .ModuleBuildDir }}/driver_config.h

# Fetch the kernel
mkdir /tmp/kernel-download
cd /tmp/kernel-download
curl --silent -o kernel-devel.rpm -SL {{ .KernelDownloadURL }}
rpm2cpio kernel-devel.rpm | cpio --extract --make-directories
rm -Rf /tmp/kernel
mkdir -p /tmp/kernel
mv usr/src/kernels/*/* /tmp/kernel

# Change current gcc
ln -sf /usr/bin/gcc-{{ .GCCVersion }} /usr/bin/gcc

# Build the module
cd {{ .ModuleBuildDir }}
make KERNELDIR=/tmp/kernel
# Print results
ls -la

modinfo falco.ko
`

func centosGccVersionFromKernelRelease(kr kernelrelease.KernelRelease) string {
	switch kr.Version {
	case "3":
		return "5"
	case "2":
		return "4.8"
	}
	return "8"
}
