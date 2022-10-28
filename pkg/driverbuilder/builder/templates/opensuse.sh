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
{{range $url := .KernelDownloadURLs}}
curl --silent -o kernel-devel.rpm -SL {{ $url }}
# cpio will warn *extremely verbose* when trying to duplicate over the same directory - redirect stderr to null
rpm2cpio kernel-devel.rpm | cpio --quiet --extract --make-directories 2> /dev/null
{{end}}
cd /tmp/kernel-download/usr/src
ls -alh /tmp/kernel-download/usr/src
sourcedir="$(find . -type d -name "linux-*-obj" | head -n 1 | xargs readlink -f)/*/default"

{{ if .BuildModule }}
# Build the module
cd {{ .DriverBuildDir }}
make CC=/usr/bin/gcc-{{ .GCCVersion }} KERNELDIR=$sourcedir
mv {{ .ModuleDriverName }}.ko {{ .ModuleFullPath }}
strip -g {{ .ModuleFullPath }}
# Print results
modinfo {{ .ModuleFullPath }}
{{ end }}

{{ if .BuildProbe }}
# Build the eBPF probe
cd {{ .DriverBuildDir }}/bpf
make KERNELDIR=/tmp/kernel
ls -l probe.o
{{ end }}