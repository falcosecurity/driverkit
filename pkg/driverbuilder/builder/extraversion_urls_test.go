// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package builder

import (
	"os"
	"testing"

	"github.com/falcosecurity/falcoctl/pkg/output"
	"github.com/pterm/pterm"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

// The fedora and oracle builders both pull a distro release number out of the
// middle of the extraversion, which assumes the extraversion contains at least
// one dot. A kernel release without that shape has to come back as an error
// from URLs(), because every build processor treats a KernelDownloadScript
// error as "skip the automatic headers download".
var dotlessExtraversionReleases = []struct {
	name          string
	builder       Builder
	kernelRelease string
}{
	{"fedora/no extraversion", &fedora{}, "6.11.0"},
	{"fedora/dotless extraversion", &fedora{}, "6.11.0-1"},
	{"oracle/no extraversion", &oracle{}, "6.11.0"},
	{"oracle/dotless extraversion", &oracle{}, "6.11.0-1"},
}

func TestKernelDownloadScriptWithDotlessExtraversion(t *testing.T) {
	printer := output.NewPrinter(pterm.LogLevelInfo, pterm.LogFormatterColorful, os.Stdout)

	for _, test := range dotlessExtraversionReleases {
		t.Run(test.name, func(t *testing.T) {
			kr := kernelrelease.FromString(test.kernelRelease)
			kr.Architecture = kernelrelease.ArchitectureAmd64

			_, err := KernelDownloadScript(test.builder, nil, kr, printer)
			if err == nil {
				t.Fatalf("expected an error for kernel release %q (extraversion %q), got none",
					test.kernelRelease, kr.FullExtraversion)
			}
		})
	}
}
