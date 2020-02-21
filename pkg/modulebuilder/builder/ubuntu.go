package builder

import (
	"bytes"
	"fmt"
	"github.com/falcosecurity/build-service/pkg/modulebuilder/buildtype"
	"strings"
	"text/template"

	"github.com/falcosecurity/build-service/pkg/kernelrelease"
)

const BuildTypeUbuntuGeneric buildtype.BuildType = "ubuntu-generic"
const BuildTypeUbuntuAWS buildtype.BuildType = "ubuntu-aws"

func init() {
	buildtype.EnabledBuildTypes[BuildTypeUbuntuGeneric] = true
	buildtype.EnabledBuildTypes[BuildTypeUbuntuAWS] = true
}

type UbuntuGeneric struct {
}

func (v UbuntuGeneric) Script(bc BuilderConfig) (string, error) {
	t := template.New(string(BuildTypeUbuntuGeneric))
	parsed, err := t.Parse(ubuntuTemplate)
	if err != nil {
		return "", err
	}

	kr := kernelrelease.FromString(bc.Build.KernelRelease)

	td := ubuntuTemplateData{
		KernelBuildDir:     KernelDirectory,
		ModuleBuildDir:     ModuleDirectory,
		ModuleDownloadURL:  fmt.Sprintf("%s/%s.tar.gz", bc.ModuleConfig.DownloadBaseURL, bc.Build.ModuleVersion),
		KernelDownloadURL:  fetchUbuntuGenericKernelURL(kr, bc.Build.KernelVersion),
		KernelLocalVersion: kr.FullExtraversion,
	}

	buf := bytes.NewBuffer(nil)
	err = parsed.Execute(buf, td)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

type UbuntuAWS struct {
}

func (v UbuntuAWS) Script(bc BuilderConfig) (string, error) {
	t := template.New(string(BuildTypeUbuntuGeneric))
	parsed, err := t.Parse(ubuntuTemplate)
	if err != nil {
		return "", err
	}

	kr := kernelrelease.FromString(bc.Build.KernelRelease)

	td := ubuntuTemplateData{
		KernelBuildDir:     KernelDirectory,
		ModuleBuildDir:     ModuleDirectory,
		ModuleDownloadURL:  moduleDownloadURL(bc),
		KernelDownloadURL:  fetchUbuntuAWSKernelURL(kr, bc.Build.KernelVersion),
		KernelLocalVersion: kr.FullExtraversion,
	}

	buf := bytes.NewBuffer(nil)
	err = parsed.Execute(buf, td)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func fetchUbuntuGenericKernelURL(kr kernelrelease.KernelRelease, kernelVersion string) string {
	firstExtraSplit := strings.Split(kr.Extraversion, "-")
	firstExtra := ""
	if len(firstExtraSplit) > 0 {
		firstExtra = firstExtraSplit[0]
	}
	return fmt.Sprintf("https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-headers-%s%s_%s-%s.%s_amd64.deb", kr.Fullversion, kr.FullExtraversion, kr.Fullversion, firstExtra, kernelVersion)
}

func fetchUbuntuAWSKernelURL(kr kernelrelease.KernelRelease, kernelVersion string) string {
	firstExtraSplit := strings.Split(kr.Extraversion, "-")
	firstExtra := ""
	if len(firstExtraSplit) > 0 {
		firstExtra = firstExtraSplit[0]
	}
	return fmt.Sprintf("https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-aws/linux-headers-%s%s_%s-%s.%s_amd64.deb", kr.Fullversion, kr.FullExtraversion, kr.Fullversion, firstExtra, kernelVersion)
}

type ubuntuTemplateData struct {
	KernelBuildDir     string
	ModuleBuildDir     string
	ModuleDownloadURL  string
	KernelDownloadURL  string
	KernelLocalVersion string
}

const ubuntuTemplate = `
#!/bin/bash
set -euo pipefail

rm -Rf {{ .ModuleBuildDir }}
mkdir {{ .ModuleBuildDir }}
rm -Rf /tmp/module-download
mkdir -p /tmp/module-download

curl -SL {{ .ModuleDownloadURL }} | tar -xzf - -C /tmp/module-download
mv /tmp/module-download/*/driver/* {{ .ModuleBuildDir }}

cp /module-builder/module-Makefile {{ .ModuleBuildDir }}/Makefile
cp /module-builder/module-driver-config.h {{ .ModuleBuildDir }}/driver_config.h

# Fetch the kernel
cd /tmp
mkdir /tmp/kernel-download
curl -o kernel.deb -SL {{ .KernelDownloadURL }}
ar x kernel.deb
tar -xvf data.tar.xz
rm -Rf {{ .KernelBuildDir }}
mkdir -p {{ .KernelBuildDir }}
mv /tmp/kernel-download/usr/src/linux-headers-*/* {{ .KernelBuildDir }}



# Prepare the kernel

cd {{ .KernelBuildDir }}
cp /module-builder/kernel.config /tmp/kernel.config

{{ if .KernelLocalVersion}}
sed -i 's/^CONFIG_LOCALVERSION=.*$/CONFIG_LOCALVERSION="{{ .KernelLocalVersion }}"/' /tmp/kernel.config
{{ end }}

make KCONFIG_CONFIG=/tmp/kernel.config oldconfig
make KCONFIG_CONFIG=/tmp/kernel.config prepare
make KCONFIG_CONFIG=/tmp/kernel.config modules_prepare

# Build the module
cd {{ .ModuleBuildDir }}
make
# print results
ls -la

modinfo falco.ko
`
