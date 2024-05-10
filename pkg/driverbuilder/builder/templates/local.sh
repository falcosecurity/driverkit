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
set -xeo pipefail

{{ if or .BuildProbe (and  .BuildModule (not .UseDKMS)) }}
cd {{ .DriverBuildDir }}
{{ if .DownloadSrc }}
echo "* Configuring sources with cmake"
mkdir -p build && cd build
{{ .CmakeCmd }}
{{ end }}
{{ end }}

{{ if .BuildModule }}
{{ if .UseDKMS }}
echo "* Building kmod with DKMS"
# Build the module using DKMS
echo "#!/usr/bin/env bash" > "/tmp/falco-dkms-make"
echo "make CC={{ .GCCVersion }} \$@" >> "/tmp/falco-dkms-make"
chmod +x "/tmp/falco-dkms-make"
if [[ -n "${KERNELDIR}" ]]; then
  dkms install --kernelsourcedir ${KERNELDIR} --directive="MAKE='/tmp/falco-dkms-make'" -m "{{ .ModuleDriverName }}" -v "{{ .DriverVersion }}" -k "{{ .KernelRelease }}"
else
  dkms install --directive="MAKE='/tmp/falco-dkms-make'" -m "{{ .ModuleDriverName }}" -v "{{ .DriverVersion }}" -k "{{ .KernelRelease }}"
fi
rm -Rf "/tmp/falco-dkms-make"
{{ else }}
echo "* Building kmod"
{{ if .DownloadSrc }}
# Build the module - cmake configured
make CC={{ .GCCVersion }} driver
{{ else }}
# Build the module - preconfigured sources
make CC={{ .GCCVersion }}
{{ end }}
strip -g {{ .ModuleFullPath }}
# Print results
modinfo {{ .ModuleFullPath }}
{{ end }}
{{ end }}

{{ if .BuildProbe }}
echo "* Building eBPF probe"
if [ ! -d /sys/kernel/debug/tracing ]; then
  echo "* Mounting debugfs"
  # Do not fail if this fails.
  mount -t debugfs nodev /sys/kernel/debug || :
fi

{{ if .DownloadSrc }}
# Build the eBPF probe - cmake configured
make bpf
ls -l driver/bpf/probe.o
{{ else }}
# Build the eBPF probe - preconfigured sources
cd bpf
make
ls -l probe.o
{{ end }}
{{ end }}