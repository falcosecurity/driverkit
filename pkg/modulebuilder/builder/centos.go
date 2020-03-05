package builder

import (
	"bytes"
	"fmt"
	"net/http"
	"text/template"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"github.com/falcosecurity/driverkit/pkg/modulebuilder/buildtype"
)

const BuildTypeCentos = "centos"

func getResolvingURLs(urls []string) []string {
	results := []string{}
	for _, u := range urls {
		res, err := http.Head(u)
		if err != nil {
			continue
		}
		if res.StatusCode == http.StatusOK {
			results = append(results, u)
		}
	}
	return results
}

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
	urls := fetchCentosKernelURLS(kr, bc.Build.KernelVersion)
	urls = getResolvingURLs(urls)
	if len(urls) == 0 {
		return "", fmt.Errorf("kernel %s not found for centos", bc.Build.KernelRelease)
	}

	td := centosTemplateData{
		ModuleBuildDir:    ModuleDirectory,
		ModuleDownloadURL: moduleDownloadURL(bc),
		KernelDownloadURL: urls[0],
	}

	buf := bytes.NewBuffer(nil)
	err = parsed.Execute(buf, td)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func fetchCentosKernelURLS(kr kernelrelease.KernelRelease, kernelVersion uint16) []string {
	return []string{
		fmt.Sprintf(
			"https://mirrors.edge.kernel.org/centos/6/os/x86_64/Packages/kernel-devel-%s%s.rpm",
			kr.Fullversion,
			kr.FullExtraversion,
		),
		fmt.Sprintf(
			"https://mirrors.edge.kernel.org/centos/6/updates/x86_64/Packages/kernel-devel-%s%s.rpm",
			kr.Fullversion,
			kr.FullExtraversion,
		),
		fmt.Sprintf(
			"https://mirrors.edge.kernel.org/centos/7/os/x86_64/Packages/kernel-devel-%s%s.rpm",
			kr.Fullversion,
			kr.FullExtraversion,
		),
		fmt.Sprintf(
			"https://mirrors.edge.kernel.org/centos/7/updates/x86_64/Packages/kernel-devel-%s%s.rpm",
			kr.Fullversion,
			kr.FullExtraversion,
		),
		fmt.Sprintf(
			"https://mirrors.edge.kernel.org/centos/8-stream/BaseOS/x86_64/os/Packages/kernel-devel-%s%s.rpm",
			kr.Fullversion,
			kr.FullExtraversion,
		),
		fmt.Sprintf(
			"https://mirrors.edge.kernel.org/centos/8.0.1905/BaseOS/x86_64/os/Packages/kernel-devel-%s%s.rpm",
			kr.Fullversion,
			kr.FullExtraversion,
		),
	}
}

type centosTemplateData struct {
	ModuleBuildDir    string
	ModuleDownloadURL string
	KernelDownloadURL string
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

# Build the module
cd {{ .ModuleBuildDir }}
make KERNELDIR=/tmp/kernel
# Print results
ls -la

modinfo falco.ko
`
