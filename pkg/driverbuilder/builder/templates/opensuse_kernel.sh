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

# Fetch the kernel
mkdir /tmp/kernel-download
cd /tmp/kernel-download
{{range $url := .KernelDownloadURLs}}
curl --silent -o kernel-devel.rpm -SL {{ $url }}
# cpio will warn *extremely verbose* when trying to duplicate over the same directory - redirect stderr to null
rpm2cpio kernel-devel.rpm | cpio --quiet --extract --make-directories 2> /dev/null
{{end}}
cd /tmp/kernel-download/usr/src
sourcedir="$(find . -type d -name "linux-*-obj" | head -n 1 | xargs readlink -f)/*/default"

# exit value
echo $sourcedir