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
curl --silent -o kernel-devel.pkg.tar.xz -SL {{ .KernelDownloadURL }}
tar -xf kernel-devel.pkg.tar.xz
rm -Rf /tmp/kernel
mkdir -p /tmp/kernel
mv usr/lib/modules/*/build/* /tmp/kernel

{{ if .BuildModule }}
# Build the module
cd {{ .DriverBuildDir }}
make CC=/usr/bin/gcc-{{ .GCCVersion }} KERNELDIR=/tmp/kernel
mv {{ .ModuleDriverName }}.ko {{ .ModuleFullPath }}
strip -g {{ .ModuleFullPath }}
# Print results
modinfo {{ .ModuleFullPath }}
{{ end }}

{{ if .BuildProbe }}
# Build the eBPF probe
cd {{ .DriverBuildDir }}/bpf
make LLC=/usr/bin/llc-7 CLANG=/usr/bin/clang-7 KERNELDIR=/tmp/kernel
ls -l probe.o
{{ end }}