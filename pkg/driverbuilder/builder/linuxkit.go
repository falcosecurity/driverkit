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

# rm -Rf /tmp/kernel-download
# mkdir /tmp/kernel-download
# CID=$(docker create linuxkit/kernel:{{ .KernelFullVersion }} top)
# docker cp "${CID}:/kernel-dev.tar" /tmp/kernel-download/src.tar
# docker rm -f "${CID}"

# Prepare the kernel
rm -Rf /tmp/kernel
mkdir -p /tmp/kernel
tar --strip-components 3 -xf /kernel-dev.tar --directory /tmp/kernel

# {{ if .BuildModule }}
# Build the kernel module
# cd {{ .DriverBuildDir }}
# make KERNELDIR=/tmp/kernel
#{{ end }}

sleep 1212317823178712
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


// make -C /tmp/kernel/usr/src/linux-headers-4.14.171-linuxkit M=/tmp/driver modules
// make[1]: Entering directory '/tmp/kernel/usr/src/linux-headers-4.14.171-linuxkit'
//   CC [M]  /tmp/driver/main.o
// cc1: error: cannot load plugin ./scripts/gcc-plugins/structleak_plugin.so
//    libc.musl-x86_64.so.1: cannot open shared object file: No such file or directory
// cc1: error: cannot load plugin ./scripts/gcc-plugins/randomize_layout_plugin.so
//    libc.musl-x86_64.so.1: cannot open shared object file: No such file or directory
// make[2]: *** [scripts/Makefile.build:327: /tmp/driver/main.o] Error 1
// make[1]: *** [Makefile:1544: _module_/tmp/driver] Error 2
// make[1]: Leaving directory '/tmp/kernel/usr/src/linux-headers-4.14.171-linuxkit'
// make: *** [Makefile:7: all] Error 2