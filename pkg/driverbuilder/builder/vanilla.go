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

# Fetch the kernel
cd /tmp
mkdir /tmp/kernel-download
curl --silent -SL {{ .KernelDownloadURL }} | tar -Jxf - -C /tmp/kernel-download
rm -Rf /tmp/kernel-src
mkdir -p /tmp/kernel-src
mv /tmp/kernel-download/*/* /tmp/kernel-src

# Prepare the kernel
mkdir -p /tmp/kernel
cp /driverkit/kernel.config /tmp/kernel/.config
cd /tmp/kernel-src


{{ if .KernelLocalVersion}}
sed -i 's/^CONFIG_LOCALVERSION=.*$/CONFIG_LOCALVERSION="{{ .KernelLocalVersion }}"/' /tmp/kernel/.config
{{ end }}

make KCONFIG_CONFIG=/tmp/kernel/.config O=/tmp/kernel oldconfig
make KCONFIG_CONFIG=/tmp/kernel/.config O=/tmp/kernel prepare
make KCONFIG_CONFIG=/tmp/kernel/.config O=/tmp/kernel modules_prepare

{{ if .BuildKernel }}
make KCONFIG_CONFIG=/tmp/kernel/.config O=/tmp/kernel kvmconfig
make KCONFIG_CONFIG=/tmp/kernel/.config O=/tmp/kernel -j$(nproc)
ls -l /tmp/kernel/arch/x86_64/boot
{{ end }}

{{ if .BuildModule }}
# Build the kernel module
cd {{ .DriverBuildDir }}
make KERNELDIR=/tmp/kernel
# Print results
modinfo falco.ko
{{ end }}

{{ if .BuildProbe }}
# Build the eBPF probe
cd {{ .DriverBuildDir }}/bpf
make LLC=/usr/bin/llc-7 CLANG=/usr/bin/clang-7 CC=/usr/bin/gcc-8 KERNELDIR=/tmp/kernel
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
	BuildKernel        bool
}

// Script compiles the script to build the kernel module and/or the eBPF probe.
func (v vanilla) Script(c Config) (string, error) {
	t := template.New(string(TargetTypeVanilla))
	parsed, err := t.Parse(vanillaTemplate)
	if err != nil {
		return "", err
	}

	kv := kernelrelease.FromString(c.Build.KernelRelease)

	// Check (and filter) existing kernels before continuing
	urls, err := getResolvingURLs([]string{fetchVanillaKernelURLFromKernelVersion(kv)})
	if err != nil {
		return "", err
	}

	td := vanillaTemplateData{
		DriverBuildDir:     DriverDirectory,
		ModuleDownloadURL:  moduleDownloadURL(c),
		KernelDownloadURL:  urls[0],
		KernelLocalVersion: kv.FullExtraversion,
		BuildModule:        len(c.Build.ModuleFilePath) > 0,
		BuildProbe:         len(c.Build.ProbeFilePath) > 0,
		BuildKernel:        len(c.Build.KernelArchivePath) > 0,
	}

	buf := bytes.NewBuffer(nil)
	err = parsed.Execute(buf, td)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func fetchVanillaKernelURLFromKernelVersion(kv kernelrelease.KernelRelease) string {
	return fmt.Sprintf("https://cdn.kernel.org/pub/linux/kernel/v%s.x/linux-%s.tar.xz", kv.Version, kv.Fullversion)
}
