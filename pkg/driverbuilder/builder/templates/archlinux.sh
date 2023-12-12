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
mv /tmp/module-download/*/* {{ .DriverBuildDir }}

# Fetch the kernel
mkdir /tmp/kernel-download
cd /tmp/kernel-download
curl --silent -o kernel-devel.pkg.tar.xz -SL {{ .KernelDownloadURL }}
tar -xf kernel-devel.pkg.tar.xz
rm -Rf /tmp/kernel
mkdir -p /tmp/kernel
mv usr/lib/modules/*/build/* /tmp/kernel

cd {{ .DriverBuildDir }}
mkdir -p build && cd build
cmake -DUSE_BUNDLED_DEPS=On -DCREATE_TEST_TARGETS=Off -DBUILD_LIBSCAP_GVISOR=Off -DBUILD_LIBSCAP_MODERN_BPF=Off -DENABLE_DRIVERS_TESTS=Off -DDRIVER_NAME={{ .ModuleDriverName }} -DBUILD_BPF=On ..

{{ if .BuildModule }}
# Build the module
make CC=/usr/bin/gcc-{{ .GCCVersion }} KERNELDIR=/tmp/kernel driver
strip -g {{ .ModuleFullPath }}
# Print results
modinfo {{ .ModuleFullPath }}
{{ end }}

{{ if .BuildProbe }}
# Build the eBPF probe
make KERNELDIR=/tmp/kernel bpf
ls -l driver/bpf/probe.o
{{ end }}