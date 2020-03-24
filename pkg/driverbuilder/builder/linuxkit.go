package builder

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

// linuxkit is a driverkit target.
type linuxkit struct {
}

// TargetTypeLinuxKit identifies the LinuxKit target.
const TargetTypeLinuxKit Type = "linuxkit"

func init() {
	BuilderByTarget[TargetTypeLinuxKit] = &linuxkit{}
}

const linuxkitTemplate = `
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

# Prepare the kernel
rm -Rf /tmp/kernel
mkdir -p /tmp/kernel
tar --strip-components=3 -xf /kernel-dev.tar --directory /tmp/kernel

{{ if .BuildModule }}
# Build the kernel module
cd {{ .DriverBuildDir }}
make KERNELDIR=/tmp/kernel
{{ end }}

{{ if .BuildProbe }}
# Build the eBPF probe
cd {{ .DriverBuildDir }}/bpf
make KERNELDIR=/tmp/kernel
file probe.o
{{ end }}
`

type linuxkitTemplateData struct {
	DriverBuildDir     string
	ModuleDownloadURL  string
	KernelDownloadURL  string
	KernelFullVersion  string
	KernelLocalVersion string
	BuildModule        bool
	BuildProbe         bool
}

// Script compiles the script to build the kernel module and/or the eBPF probe.
func (v linuxkit) Script(c Config) (string, error) {
	t := template.New(string(TargetTypeLinuxKit))
	parsed, err := t.Parse(linuxkitTemplate)
	if err != nil {
		return "", err
	}

	kv := kernelrelease.FromString(c.Build.KernelRelease)

	// Check (and filter) existing kernels before continuing
	urls, err := getResolvingURLs([]string{getLinuxKitKernelDockerImageURL(kv)})
	if err != nil {
		return "", err
	}

	td := linuxkitTemplateData{
		DriverBuildDir:     DriverDirectory,
		ModuleDownloadURL:  moduleDownloadURL(c),
		KernelDownloadURL:  urls[0],
		KernelFullVersion:  kv.Fullversion,
		KernelLocalVersion: kv.FullExtraversion,
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

func getLinuxKitKernelDockerImageURL(kr kernelrelease.KernelRelease) string {
	return fmt.Sprintf("https://hub.docker.com/v2/repositories/linuxkit/kernel/tags/%s-amd64", kr.Fullversion)
}