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
cp /driverkit/module-Makefile {{ .DriverBuildDir }}/Makefile
cd {{ .DriverBuildDir }}
make KERNELDIR=/tmp/kernel CC=/usr/bin/gcc-{{ .GCCVersion }} LD=/usr/bin/ld.bfd CROSS_COMPILE=""
mv {{ .ModuleDriverName }}.ko {{ .ModuleFullPath }}
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