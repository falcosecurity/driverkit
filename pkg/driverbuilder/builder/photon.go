package builder

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

// TargetTypePhoton identifies the Photon target.
const TargetTypePhoton Type = "photon"

func init() {
	BuilderByTarget[TargetTypePhoton] = &photon{}
}

// photon is a driverkit target.
type photon struct {
}

// Script compiles the script to build the kernel module and/or the eBPF probe.
func (c photon) Script(cfg Config) (string, error) {
	t := template.New(string(TargetTypePhoton))
	parsed, err := t.Parse(photonTemplate)
	if err != nil {
		return "", err
	}

	kr := kernelrelease.FromString(cfg.Build.KernelRelease)

	// Check (and filter) existing kernels before continuing
	urls, err := getResolvingURLs(fetchPhotonKernelURLS(kr))
	if err != nil {
		return "", err
	}

	td := photonTemplateData{
		DriverBuildDir:    DriverDirectory,
		ModuleDownloadURL: moduleDownloadURL(cfg),
		KernelDownloadURL: urls[0],
		GCCVersion:        photonGccVersionFromKernelRelease(kr),
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

func fetchPhotonKernelURLS(kr kernelrelease.KernelRelease) []string {
	photonReleases := []string{
		"3.0",
		"4.0",
	}

	urls := []string{}
	for _, r := range photonReleases {
		switch r {
		case "3.0":
			urls = append(urls, fmt.Sprintf(
				"https://packages.vmware.com/photon/%s/photon_updates_%s_x86_64/x86_64/linux-devel-%s%s.x86_64.rpm",
				r,
				r,
				kr.Fullversion,
				kr.FullExtraversion,
			))
            urls = append(urls, fmt.Sprintf(
				"https://packages.vmware.com/photon/%s/photon_release_%s_x86_64/x86_64/linux-devel-%s%s.x86_64.rpm",
				r,
				r,
				kr.Fullversion,
				kr.FullExtraversion,
			))

		case "4.0":
			urls = append(urls, fmt.Sprintf(
				"https://packages.vmware.com/photon/%s/photon_%s_x86_64/x86_64/linux-devel-%s%s.x86_64.rpm",
				r,
				r,
				kr.Fullversion,
				kr.FullExtraversion,
			))
            urls = append(urls, fmt.Sprintf(
				"https://packages.vmware.com/photon/%s/photon_release_%s_x86_64/x86_64/linux-devel-%s%s.x86_64.rpm",
				r,
				r,
				kr.Fullversion,
				kr.FullExtraversion,
			))
		}
	}
	return urls
}

type photonTemplateData struct {
	DriverBuildDir    string
	ModuleDownloadURL string
	KernelDownloadURL string
	GCCVersion        string
	ModuleDriverName  string
	ModuleFullPath    string
	BuildModule       bool
	BuildProbe        bool
}

const photonTemplate = `
#!/bin/bash
set -xeuo pipefail
rm -Rf {{ .DriverBuildDir }}
mkdir {{ .DriverBuildDir }}
rm -Rf /tmp/module-download
mkdir -p /tmp/module-download
curl --silent -SL {{ .ModuleDownloadURL }} | tar -xzf - -C /tmp/module-download
mv /tmp/module-download/*/driver/* {{ .DriverBuildDir }}
cp /driverkit/module-Makefile {{ .DriverBuildDir }}/Makefile
bash /driverkit/fill-driver-config.sh {{ .DriverBuildDir }}
# Fetch the kernel
mkdir /tmp/kernel-download
cd /tmp/kernel-download
curl --silent -o kernel-devel.rpm -SL {{ .KernelDownloadURL }}
rpm2cpio kernel-devel.rpm | cpio --extract --make-directories
rm -Rf /tmp/kernel
mkdir -p /tmp/kernel
mv usr/src/linux-headers-*/* /tmp/kernel
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

func photonGccVersionFromKernelRelease(kr kernelrelease.KernelRelease) string {
	switch kr.Version {
	default:
		return "8"
	}
}
