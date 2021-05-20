package builder

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

// vanilla is a driverkit target.
type vanilla struct {
}

// TargetTypeVanilla identifies the Vanilla target.
const TargetTypeVanilla Type = "vanilla"

func init() {
	BuilderByTarget[TargetTypeVanilla] = &vanilla{}
}

const vanillaTemplate = `
#!/bin/bash
set -xeuo pipefail

rm -Rf {{ .DriverBuildDir }}
mkdir {{ .DriverBuildDir }}
rm -Rf /tmp/module-download
mkdir -p /tmp/module-download

curl --silent -SL {{ .ModuleDownloadURL }} | tar -xzf - -C /tmp/module-download
mv /tmp/module-download/*/driver/* {{ .DriverBuildDir }}

cp /driverkit/module-Makefile {{ .DriverBuildDir }}/Makefile
cp /driverkit/module-driver-config.h {{ .DriverBuildDir }}/driver_config.h

{{ if .KernelDownloadURL }}
# Fetch the kernel
cd /tmp
mkdir /tmp/kernel-download
curl --silent -SL {{ .KernelDownloadURL }} | tar -Jxf - -C /tmp/kernel-download
rm -Rf /tmp/kernel
mkdir -p /tmp/kernel
mv /tmp/kernel-download/*/* /tmp/kernel

# Prepare the kernel
cd /tmp/kernel
cp /driverkit/kernel.config /tmp/kernel.config


{{ if .KernelLocalVersion}}
sed -i 's/^CONFIG_LOCALVERSION=.*$/CONFIG_LOCALVERSION="{{ .KernelLocalVersion }}"/' /tmp/kernel.config
{{ end }}

make KCONFIG_CONFIG=/tmp/kernel.config oldconfig
make KCONFIG_CONFIG=/tmp/kernel.config prepare
make KCONFIG_CONFIG=/tmp/kernel.config modules_prepare
{{ end }}

# Change current gcc
ln -sf /usr/bin/gcc-{{ .GCCVersion }} /usr/bin/gcc

{{ if .BuildModule }}
# Build the kernel module
cd {{ .DriverBuildDir }}
make CC=clang HOSTCC=clang KERNELDIR=/tmp/kernel

# Print results
modinfo falco.ko
{{ end }}

{{ if .BuildProbe }}
# Build the eBPF probe
cd {{ .DriverBuildDir }}/bpf
make LLC=/usr/bin/llc-7 CLANG="/usr/bin/clang-7" KERNELDIR=/tmp/kernel
ls -l probe.o
{{ end }}
`

type vanillaTemplateData struct {
	DriverBuildDir     string
	ModuleDownloadURL  string
	KernelDownloadURL  string
	KernelLocalVersion string
	BuildModule        bool
	BuildProbe         bool
	GCCVersion         string
}

// Script compiles the script to build the kernel module and/or the eBPF probe.
func (v vanilla) Script(c Config) (string, error) {
	t := template.New(string(TargetTypeVanilla))
	parsed, err := t.Parse(vanillaTemplate)
	if err != nil {
		return "", err
	}

	kr := kernelrelease.FromString(c.Build.KernelRelease)

	kernelDownloadURL := ""

	// skip resolving the Kernel URL when building with a local provided one
	if len(c.LocalKernelBuildDir) == 0 {
		// Check (and filter) existing kernels before continuing
		urls, err := getResolvingURLs([]string{fetchVanillaKernelURLFromKernelRelease(kr)})
		if err != nil {
			return "", err
		}
		kernelDownloadURL = urls[0]
	}

	td := vanillaTemplateData{
		DriverBuildDir:     DriverDirectory,
		ModuleDownloadURL:  moduleDownloadURL(c),
		KernelDownloadURL:  kernelDownloadURL,
		KernelLocalVersion: kr.FullExtraversion,
		GCCVersion:         vanillaGCCVersionFromKernelRelease(kr),
		BuildModule:        len(c.Build.ModuleFilePath) > 0,
		BuildProbe:         len(c.Build.ProbeFilePath) > 0,
	}

	buf := bytes.NewBuffer(nil)
	err = parsed.Execute(buf, td)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func fetchVanillaKernelURLFromKernelRelease(kr kernelrelease.KernelRelease) string {
	return fmt.Sprintf("https://cdn.kernel.org/pub/linux/kernel/v%s.x/linux-%s.tar.xz", kr.Version, kr.Fullversion)
}

func vanillaGCCVersionFromKernelRelease(kr kernelrelease.KernelRelease) string {
	switch kr.Version {
	case "3":
		return "5"
	case "2":
		return "4.8"
	}
	return "8"
}
