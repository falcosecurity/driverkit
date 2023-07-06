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
rm -Rf /tmp/kernel-download
mkdir /tmp/kernel-download
cd /tmp/kernel-download
yum install -y --downloadonly --downloaddir=/tmp/kernel-download kernel-devel-0:{{ .KernelPackage }}
rpm2cpio kernel-devel-{{ .KernelPackage }}.rpm | cpio --extract --make-directories

rm -Rf /tmp/kernel
mkdir -p /tmp/kernel
mv usr/src/kernels/*/* /tmp/kernel

{{ if .BuildModule }}
# Build the module
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