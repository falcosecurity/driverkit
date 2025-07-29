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
	"testing"

	"github.com/blang/semver/v4"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

var gccTests = []struct {
	config      kernelrelease.KernelRelease
	expectedGCC semver.Version
}{
	{
		config: kernelrelease.KernelRelease{
			Fullversion: "4.15.0",
			Version: semver.Version{
				Major: 4,
				Minor: 15,
				Patch: 0,
			},
			Extraversion:     "188",
			FullExtraversion: "-188",
			Architecture:     kernelrelease.ArchitectureAmd64,
		},
		expectedGCC: semver.Version{
			Major: 8,
		},
	},
	{
		config: kernelrelease.KernelRelease{
			Fullversion: "5.15.0",
			Version: semver.Version{
				Major: 5,
				Minor: 15,
				Patch: 0,
			},
			Extraversion:     "1004-intel-iotg",
			FullExtraversion: "-1004-intel-iotg",
			Architecture:     kernelrelease.ArchitectureAmd64,
		},
		expectedGCC: semver.Version{
			Major: 12,
		},
	},
	{
		config: kernelrelease.KernelRelease{
			Fullversion: "3.13.0",
			Version: semver.Version{
				Major: 3,
				Minor: 13,
				Patch: 0,
			},
			Extraversion:     "100",
			FullExtraversion: "-100",
			Architecture:     kernelrelease.ArchitectureAmd64,
		},
		expectedGCC: semver.Version{
			Major: 4,
			Minor: 9,
		},
	},
	{
		config: kernelrelease.KernelRelease{
			Fullversion: "5.18.0",
			Version: semver.Version{
				Major: 5,
				Minor: 18,
				Patch: 0,
			},
			Extraversion:     "1001-kvm",
			FullExtraversion: "-1001-kvm",
			Architecture:     kernelrelease.ArchitectureAmd64,
		},
		expectedGCC: semver.Version{
			Major: 12,
		},
	},
}

func TestDefaultGCC(t *testing.T) {
	for _, test := range gccTests {
		// call function
		selectedGCC := defaultGCC(test.config)

		// compare errors
		// there are no official errors, so comparing fmt.Errorf() doesn't really work
		// compare error message text instead
		if test.expectedGCC.NE(selectedGCC) {
			t.Fatalf("SelectedGCC (%s) != expectedGCC (%s) with kernelrelease: '%v'", selectedGCC, test.expectedGCC, test.config)
		}
	}
}
