#!/bin/bash
set -xeuo pipefail

rm -Rf {{ .DriverBuildDir }}
mkdir {{ .DriverBuildDir }}
rm -Rf /tmp/module-download
mkdir -p /tmp/module-download

curl --silent -SL {{ .ModuleDownloadURL }} | tar -xzf - -C /tmp/module-download
mv /tmp/module-download/*/driver/* {{ .DriverBuildDir }}

bash /driverkit/fill-driver-config.sh {{ .DriverBuildDir }}

# Fetch the kernel
cd /tmp
mkdir /tmp/kernel-download
{{ if .IsTarGz}}
curl --silent -SL {{ .KernelDownloadURL }} | tar -zxf - -C /tmp/kernel-download
{{ else }}
curl --silent -SL {{ .KernelDownloadURL }} | tar -Jxf - -C /tmp/kernel-download
{{ end }}
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

export KBUILD_MODPOST_WARN=1

{{ if .BuildModule }}
# Build the kernel module
cp /driverkit/module-Makefile {{ .DriverBuildDir }}/Makefile
cd {{ .DriverBuildDir }}
make CC=/usr/bin/gcc-{{ .GCCVersion }} KERNELDIR=/tmp/kernel
mv {{ .ModuleDriverName }}.ko {{ .ModuleFullPath }}
strip -g {{ .ModuleFullPath }}
# Print results
modinfo {{ .ModuleFullPath }}
{{ end }}

{{ if .BuildProbe }}
# Build the eBPF probe
cp /driverkit/bpf-Makefile {{ .DriverBuildDir }}/bpf/Makefile
cd {{ .DriverBuildDir }}/bpf
ln -s ../*{.c,.h} .
make KERNELDIR=/tmp/kernel
ls -l probe.o
{{ end }}
