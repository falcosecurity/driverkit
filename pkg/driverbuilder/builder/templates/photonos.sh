#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 The Falco Authors.
#
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Simple script that desperately tries to load the kernel instrumentation by
# looking for it in a bunch of ways. Convenient when running Falco inside
# a container or in other weird environments.
#
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
# eg: linux-aws-headers-$kernelrelease
# eg: linux-headers-$kernelrelease-rt
# eg: linux-headers-$kernelrelease
mv usr/src/linux-*headers-*/* /tmp/kernel

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
make KERNELDIR=/tmp/kernel
ls -l probe.o
{{ end }}