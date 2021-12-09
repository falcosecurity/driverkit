package builder

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

// TargetTypeCentos identifies the Centos target.
const TargetTypeCentos Type = "centos"

func init() {
	BuilderByTarget[TargetTypeCentos] = &centos{}
}

// centos is a driverkit target.
type centos struct {
}

// Script compiles the script to build the kernel module and/or the eBPF probe.
func (c centos) Script(cfg Config) (string, error) {
	t := template.New(string(TargetTypeCentos))
	parsed, err := t.Parse(centosTemplate)
	if err != nil {
		return "", err
	}

	kr := kernelrelease.FromString(cfg.Build.KernelRelease)

	// Check (and filter) existing kernels before continuing
	urls, err := getResolvingURLs(fetchCentosKernelURLS(kr))
	if err != nil {
		return "", err
	}

	td := centosTemplateData{
		DriverBuildDir:    DriverDirectory,
		ModuleDownloadURL: moduleDownloadURL(cfg),
		KernelDownloadURL: urls[0],
		GCCVersion:        centosGccVersionFromKernelRelease(kr),
		ModuleDriverName:  cfg.DriverName,
		ModuleFullPath:    ModuleFullPath,
		BuildModule:       len(cfg.Build.ModuleFilePath) > 0,
		BuildProbe:        len(cfg.Build.ProbeFilePath) > 0,
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
		"7.8.2003/os",
		"7.8.2003/updates",
		"8.0.1905/os",
		"8.0.1905/updates",
		"8.1.1911/os",
		"8.1.1911/updates",
	}

	centos8VaultReleases := []string{
		"8.0.1905/BaseOS",
		"8.1.1911/BaseOS",
		"8.2.2004/BaseOS",
		"8.3.2011/BaseOS",
		"8.4.2105/BaseOS",
	}

	edgeReleases := []string{
		"6/os",
		"6/updates",
		"7/os",
		"7/updates",
	}

	streamReleases := []string{
		"8/BaseOS",
		"8-stream/BaseOS",
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
	for _, r := range centos8VaultReleases {
		urls = append(urls, fmt.Sprintf(
			"http://vault.centos.org/%s/x86_64/os/Packages/kernel-devel-%s%s.rpm",
			r,
			kr.Fullversion,
			kr.FullExtraversion,
		))
	}
	return urls
}

type centosTemplateData struct {
	DriverBuildDir    string
	ModuleDownloadURL string
	KernelDownloadURL string
	GCCVersion        string
	ModuleDriverName  string
	ModuleFullPath    string
	BuildModule       bool
	BuildProbe        bool
}

const centosTemplate = `
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
mkdir /tmp/kernel-download
cd /tmp/kernel-download
curl --silent -o kernel-devel.rpm -SL {{ .KernelDownloadURL }}
rpm2cpio kernel-devel.rpm | cpio --extract --make-directories
rm -Rf /tmp/kernel
mkdir -p /tmp/kernel
mv usr/src/kernels/*/* /tmp/kernel

# Change current gcc
ln -sf /usr/bin/gcc-{{ .GCCVersion }} /usr/bin/gcc

{{ if .BuildModule }}
# Build the module
cd {{ .DriverBuildDir }}
make KERNELDIR=/tmp/kernel
mv {{ .ModuleDriverName }}.ko {{ .ModuleFullPath }}
strip -g {{ .ModuleFullPath }}
# Print results
modinfo {{ .ModuleFullPath }}
{{ end }}

{{ if .BuildProbe }}
# Build the eBPF probe
cd {{ .DriverBuildDir }}/bpf
make LLC=/usr/bin/llc-7 CLANG=/usr/bin/clang-7 CC=/usr/bin/gcc KERNELDIR=/tmp/kernel
ls -l probe.o
{{ end }}
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
