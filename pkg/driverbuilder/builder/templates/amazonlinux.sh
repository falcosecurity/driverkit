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
{{ range $url := .KernelDownloadURLs }}
curl --silent -o kernel.rpm -SL {{ $url }}
rpm2cpio kernel.rpm | cpio --extract --make-directories
rm -rf kernel.rpm
{{ end }}
rm -Rf /tmp/kernel
mkdir -p /tmp/kernel
mv usr/src/kernels/*/* /tmp/kernel

{{ if .BuildModule }}
# Build the kernel module
cd {{ .DriverBuildDir }}

make KERNELDIR=/tmp/kernel CC=/usr/bin/gcc LD=/usr/bin/ld.bfd CROSS_COMPILE=""
mv {{ .ModuleDriverName }}.ko {{ .ModuleFullPath }}
# Print results
modinfo {{ .ModuleFullPath }}
{{ end }}

{{ if .BuildProbe }}
# Build the eBPF probe
cd {{ .DriverBuildDir }}/bpf
make LLC=/usr/bin/llc-{{ .LLVMVersion }} CLANG=/usr/bin/clang-{{ .LLVMVersion }} KERNELDIR=/tmp/kernel
ls -l probe.o
{{ end }}