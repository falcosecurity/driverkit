package builder

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"

	"github.com/falcosecurity/driverkit/pkg/driverbuilder/buildtype"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

// BuildTypeUbuntuGeneric identifies the UbuntuGeneric target.
const BuildTypeUbuntuGeneric buildtype.BuildType = "ubuntu-generic"

// BuildTypeUbuntuAWS identifies the UbuntuAWS target.
const BuildTypeUbuntuAWS buildtype.BuildType = "ubuntu-aws"

func init() {
	buildtype.EnabledBuildTypes[BuildTypeUbuntuGeneric] = true
	buildtype.EnabledBuildTypes[BuildTypeUbuntuAWS] = true
}

// UbuntuGeneric is a driverkit target.
type UbuntuGeneric struct {
}

// Script compiles the script to build the kernel module and/or the eBPF probe.
func (v UbuntuGeneric) Script(bc BuilderConfig) (string, error) {
	t := template.New(string(BuildTypeUbuntuGeneric))
	parsed, err := t.Parse(ubuntuTemplate)
	if err != nil {
		return "", err
	}

	kr := kernelrelease.FromString(bc.Build.KernelRelease)

	urls, err := getResolvingURLs(fetchUbuntuGenericKernelURL(kr, bc.Build.KernelVersion))
	if err != nil {
		return "", err
	}
	if len(urls) != 2 {
		return "", fmt.Errorf("specific kernel headers not found")
	}

	td := ubuntuTemplateData{
		ModuleBuildDir:       DriverDirectory,
		ModuleDownloadURL:    fmt.Sprintf("%s/%s.tar.gz", bc.ModuleConfig.DownloadBaseURL, bc.Build.DriverVersion),
		KernelDownloadURLS:   urls,
		KernelLocalVersion:   kr.FullExtraversion,
		KernelHeadersPattern: "*generic",
		BuildModule:          len(bc.Build.ModuleFilePath) > 0,
		BuildProbe:           len(bc.Build.ProbeFilePath) > 0,
	}

	buf := bytes.NewBuffer(nil)
	err = parsed.Execute(buf, td)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

// UbuntuAWS is a driverkit target.
type UbuntuAWS struct {
}

// Script compiles the script to build the kernel module and/or the eBPF probe.
func (v UbuntuAWS) Script(bc BuilderConfig) (string, error) {
	t := template.New(string(BuildTypeUbuntuGeneric))
	parsed, err := t.Parse(ubuntuTemplate)
	if err != nil {
		return "", err
	}

	kr := kernelrelease.FromString(bc.Build.KernelRelease)

	urls, err := getResolvingURLs(fetchUbuntuAWSKernelURLS(kr, bc.Build.KernelVersion))
	if err != nil {
		return "", err
	}
	if len(urls) != 2 {
		return "", fmt.Errorf("specific kernel headers not found")
	}

	td := ubuntuTemplateData{
		ModuleBuildDir:       DriverDirectory,
		ModuleDownloadURL:    moduleDownloadURL(bc),
		KernelDownloadURLS:   urls,
		KernelLocalVersion:   kr.FullExtraversion,
		KernelHeadersPattern: "*",
		BuildModule:          len(bc.Build.ModuleFilePath) > 0,
		BuildProbe:           len(bc.Build.ProbeFilePath) > 0,
	}

	buf := bytes.NewBuffer(nil)
	err = parsed.Execute(buf, td)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func fetchUbuntuGenericKernelURL(kr kernelrelease.KernelRelease, kernelVersion uint16) []string {
	firstExtra := extractExtraNumber(kr.Extraversion)
	return []string{
		fmt.Sprintf(
			"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-headers-%s-%s_%s-%s.%d_all.deb",
			kr.Fullversion,
			firstExtra,
			kr.Fullversion,
			firstExtra,
			kernelVersion,
		),
		fmt.Sprintf(
			"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-headers-%s%s_%s-%s.%d_amd64.deb",
			kr.Fullversion,
			kr.FullExtraversion,
			kr.Fullversion,
			firstExtra,
			kernelVersion,
		),
	}
}

func fetchUbuntuAWSKernelURLS(kr kernelrelease.KernelRelease, kernelVersion uint16) []string {
	firstExtra := extractExtraNumber(kr.Extraversion)
	return []string{
		fmt.Sprintf(
			"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-aws/linux-aws-headers-%s-%s_%s-%s.%d_all.deb",
			kr.Fullversion,
			firstExtra,
			kr.Fullversion,
			firstExtra,
			kernelVersion,
		),
		fmt.Sprintf(
			"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-aws/linux-headers-%s%s_%s-%s.%d_amd64.deb",
			kr.Fullversion,
			kr.FullExtraversion,
			kr.Fullversion,
			firstExtra,
			kernelVersion,
		),
	}
}

func extractExtraNumber(extraversion string) string {
	firstExtraSplit := strings.Split(extraversion, "-")
	if len(firstExtraSplit) > 0 {
		return firstExtraSplit[0]
	}
	return ""
}

type ubuntuTemplateData struct {
	ModuleBuildDir       string
	ModuleDownloadURL    string
	KernelDownloadURLS   []string
	KernelLocalVersion   string
	KernelHeadersPattern string
	BuildProbe           bool
	BuildModule          bool
}

const ubuntuTemplate = `
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
{{range $url := .KernelDownloadURLS}}
curl --silent -o kernel.deb -SL {{ $url }}
ar x kernel.deb
tar -xvf data.tar.xz
{{end}}
ls -la /tmp/kernel-download

cd /tmp/kernel-download/usr/src/
sourcedir=$(find . -type d -name "linux-headers{{ .KernelHeadersPattern }}" | head -n 1 | xargs readlink -f)

ls -la $sourcedir

{{ if .BuildModule }}
# Build the module
cd {{ .ModuleBuildDir }}
make KERNELDIR=$sourcedir
strip -g falco.ko
# Print results
modinfo falco.ko
{{ end }}

{{ if .BuildProbe }}
# Build the eBPF probe
cd {{ .DriverBuildDir }}/bpf
make LLC=/usr/bin/llc-7 CLANG=/usr/bin/clang-7 CC=/usr/bin/gcc-8 KERNELDIR=$sourcedir
file probe.o
{{ end }}
`
