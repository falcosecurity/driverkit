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
	"fmt"
	"testing"

	"github.com/blang/semver"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

var tests = []struct {
	config        kernelrelease.KernelRelease
	kernelversion string
	expected      struct {
		headersURLs []string
		urls        []string
		gccVersion  semver.Version
		firstExtra  string
		flavor      string
		err         error
	}
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
		kernelversion: "199",
		expected: struct {
			headersURLs []string
			urls        []string
			gccVersion  semver.Version
			firstExtra  string
			flavor      string
			err         error
		}{
			headersURLs: []string{"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-headers-4.15.0-188-generic_4.15.0-188.199_amd64.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-headers-4.15.0-188_4.15.0-188.199_all.deb"},
			urls:        []string{"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-headers-4.15.0-188_4.15.0-188.199_amd64_all.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-headers-4.15.0-188-generic_4.15.0-188.199_amd64.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-generic-headers-4.15.0-188_4.15.0-188.199_all.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-headers-4.15.0-188_4.15.0-188.199_amd64.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-headers-4.15.0-188_4.15.0-188.199_all.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-generic/linux-headers-4.15.0-188_4.15.0-188.199_amd64_all.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-generic/linux-headers-4.15.0-188-generic_4.15.0-188.199_amd64.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-generic/linux-generic-headers-4.15.0-188_4.15.0-188.199_all.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-generic/linux-headers-4.15.0-188_4.15.0-188.199_amd64.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-generic/linux-headers-4.15.0-188_4.15.0-188.199_all.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-generic-4.15/linux-headers-4.15.0-188_4.15.0-188.199_amd64_all.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-generic-4.15/linux-headers-4.15.0-188-generic_4.15.0-188.199_amd64.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-generic-4.15/linux-generic-headers-4.15.0-188_4.15.0-188.199_all.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-generic-4.15/linux-headers-4.15.0-188_4.15.0-188.199_amd64.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-generic-4.15/linux-headers-4.15.0-188_4.15.0-188.199_all.deb"},
			gccVersion: semver.Version{
				Major: 8,
			},
			firstExtra: "188",
			flavor:     "generic",
			err:        fmt.Errorf("kernel headers not found"),
		},
	},
	{
		config: kernelrelease.KernelRelease{
			Fullversion: "4.15.0",
			Version: semver.Version{
				Major: 4,
				Minor: 15,
				Patch: 0,
			},
			Extraversion:     "1140-aws",
			FullExtraversion: "-1140-aws",
			Architecture:     kernelrelease.ArchitectureArm64,
		},
		kernelversion: "151",
		expected: struct {
			headersURLs []string
			urls        []string
			gccVersion  semver.Version
			firstExtra  string
			flavor      string
			err         error
		}{
			headersURLs: []string{"http://ports.ubuntu.com/ubuntu-ports/pool/main/l/linux-aws/linux-headers-4.15.0-1140-aws_4.15.0-1140.151_arm64.deb", "http://ports.ubuntu.com/ubuntu-ports/pool/main/l/linux-aws/linux-aws-headers-4.15.0-1140_4.15.0-1140.151_all.deb"},
			urls:        []string{"http://ports.ubuntu.com/ubuntu-ports/pool/main/l/linux/linux-headers-4.15.0-1140-aws_4.15.0-1140.151_arm64_all.deb", "http://ports.ubuntu.com/ubuntu-ports/pool/main/l/linux/linux-headers-4.15.0-1140-aws_4.15.0-1140.151_arm64.deb", "http://ports.ubuntu.com/ubuntu-ports/pool/main/l/linux/linux-aws-headers-4.15.0-1140_4.15.0-1140.151_all.deb", "http://ports.ubuntu.com/ubuntu-ports/pool/main/l/linux-aws/linux-headers-4.15.0-1140-aws_4.15.0-1140.151_arm64_all.deb", "http://ports.ubuntu.com/ubuntu-ports/pool/main/l/linux-aws/linux-headers-4.15.0-1140-aws_4.15.0-1140.151_arm64.deb", "http://ports.ubuntu.com/ubuntu-ports/pool/main/l/linux-aws/linux-aws-headers-4.15.0-1140_4.15.0-1140.151_all.deb", "http://ports.ubuntu.com/ubuntu-ports/pool/main/l/linux-aws-4.15/linux-headers-4.15.0-1140-aws_4.15.0-1140.151_arm64_all.deb", "http://ports.ubuntu.com/ubuntu-ports/pool/main/l/linux-aws-4.15/linux-headers-4.15.0-1140-aws_4.15.0-1140.151_arm64.deb", "http://ports.ubuntu.com/ubuntu-ports/pool/main/l/linux-aws-4.15/linux-aws-headers-4.15.0-1140_4.15.0-1140.151_all.deb"},
			gccVersion: semver.Version{
				Major: 8,
			},
			firstExtra: "1140",
			flavor:     "aws",
			err:        nil,
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
		kernelversion: "6",
		expected: struct {
			headersURLs []string
			urls        []string
			gccVersion  semver.Version
			firstExtra  string
			flavor      string
			err         error
		}{
			headersURLs: []string{"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-intel-iotg/linux-headers-5.15.0-1004-intel-iotg_5.15.0-1004.6_amd64.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-intel-iotg/linux-intel-iotg-headers-5.15.0-1004_5.15.0-1004.6_all.deb"},
			urls:        []string{"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-headers-5.15.0-1004-intel-iotg_5.15.0-1004.6_amd64_all.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-headers-5.15.0-1004-intel-iotg_5.15.0-1004.6_amd64.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-intel-iotg-headers-5.15.0-1004_5.15.0-1004.6_all.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-intel-iotg/linux-headers-5.15.0-1004-intel-iotg_5.15.0-1004.6_amd64_all.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-intel-iotg/linux-headers-5.15.0-1004-intel-iotg_5.15.0-1004.6_amd64.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-intel-iotg/linux-intel-iotg-headers-5.15.0-1004_5.15.0-1004.6_all.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-intel-iotg-5.15/linux-headers-5.15.0-1004-intel-iotg_5.15.0-1004.6_amd64_all.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-intel-iotg-5.15/linux-headers-5.15.0-1004-intel-iotg_5.15.0-1004.6_amd64.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-intel-iotg-5.15/linux-intel-iotg-headers-5.15.0-1004_5.15.0-1004.6_all.deb"},
			gccVersion: semver.Version{
				Major: 11,
			},
			firstExtra: "1004",
			flavor:     "intel-iotg",
			err:        nil,
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
			Extraversion:     "24-lowlatency-hwe-5.15",
			FullExtraversion: "-24-lowlatency-hwe-5.15",
			Architecture:     kernelrelease.ArchitectureAmd64,
		},
		kernelversion: "24~20.04.3",
		expected: struct {
			headersURLs []string
			urls        []string
			gccVersion  semver.Version
			firstExtra  string
			flavor      string
			err         error
		}{
			headersURLs: []string{},
			urls:        []string{"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-headers-5.15.0-24-lowlatency-hwe-5.15_5.15.0-24.24~20.04.3_amd64_all.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-headers-5.15.0-24-lowlatency-hwe_5.15.0-24.24~20.04.3_amd64.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-lowlatency-hwe-headers-5.15.0-24_5.15.0-24.24~20.04.3_all.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-headers-5.15.0-24-lowlatency-hwe-5.15_5.15.0-24.24~20.04.3_amd64.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-lowlatency-hwe/linux-headers-5.15.0-24-lowlatency-hwe-5.15_5.15.0-24.24~20.04.3_amd64_all.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-lowlatency-hwe/linux-headers-5.15.0-24-lowlatency-hwe_5.15.0-24.24~20.04.3_amd64.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-lowlatency-hwe/linux-lowlatency-hwe-headers-5.15.0-24_5.15.0-24.24~20.04.3_all.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-lowlatency-hwe/linux-headers-5.15.0-24-lowlatency-hwe-5.15_5.15.0-24.24~20.04.3_amd64.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-lowlatency-hwe-5.15/linux-headers-5.15.0-24-lowlatency-hwe-5.15_5.15.0-24.24~20.04.3_amd64_all.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-lowlatency-hwe-5.15/linux-headers-5.15.0-24-lowlatency-hwe_5.15.0-24.24~20.04.3_amd64.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-lowlatency-hwe-5.15/linux-lowlatency-hwe-headers-5.15.0-24_5.15.0-24.24~20.04.3_all.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-lowlatency-hwe-5.15/linux-headers-5.15.0-24-lowlatency-hwe-5.15_5.15.0-24.24~20.04.3_amd64.deb"},
			gccVersion: semver.Version{
				Major: 11,
			},
			firstExtra: "24",
			flavor:     "lowlatency-hwe",
			err:        fmt.Errorf("kernel headers not found"),
		},
	},
	{
		config: kernelrelease.KernelRelease{
			Fullversion: "6.5.0",
			Version: semver.Version{
				Major: 6,
				Minor: 5,
				Patch: 0,
			},
			Extraversion:     "9",
			FullExtraversion: "-9",
			Architecture:     kernelrelease.ArchitectureAmd64,
		},
		kernelversion: "9",
		expected: struct {
			headersURLs []string
			urls        []string
			gccVersion  semver.Version
			firstExtra  string
			flavor      string
			err         error
		}{
			headersURLs: []string{
				"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-headers-6.5.0-9-generic_6.5.0-9.9_amd64.deb",
				"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-headers-6.5.0-9_6.5.0-9.9_all.deb",
			},
			urls: []string{
				"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-headers-6.5.0-9_6.5.0-9.9_amd64_all.deb",
				"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-headers-6.5.0-9-generic_6.5.0-9.9_amd64.deb",
				"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-generic-headers-6.5.0-9_6.5.0-9.9_all.deb",
				"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-headers-6.5.0-9_6.5.0-9.9_amd64.deb",
				"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-headers-6.5.0-9_6.5.0-9.9_all.deb",
				"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-generic/linux-headers-6.5.0-9_6.5.0-9.9_amd64_all.deb",
				"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-generic/linux-headers-6.5.0-9-generic_6.5.0-9.9_amd64.deb",
				"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-generic/linux-generic-headers-6.5.0-9_6.5.0-9.9_all.deb",
				"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-generic/linux-headers-6.5.0-9_6.5.0-9.9_amd64.deb",
				"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-generic/linux-headers-6.5.0-9_6.5.0-9.9_all.deb",
				"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-generic-6.5/linux-headers-6.5.0-9_6.5.0-9.9_amd64_all.deb",
				"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-generic-6.5/linux-headers-6.5.0-9-generic_6.5.0-9.9_amd64.deb",
				"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-generic-6.5/linux-generic-headers-6.5.0-9_6.5.0-9.9_all.deb",
				"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-generic-6.5/linux-headers-6.5.0-9_6.5.0-9.9_amd64.deb",
				"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-generic-6.5/linux-headers-6.5.0-9_6.5.0-9.9_all.deb",
			},
			gccVersion: semver.Version{
				Major: 6,
				Minor: 3,
			},
			firstExtra: "9",
			flavor:     "generic",
			err:        nil,
		},
	},
	{
		config: kernelrelease.KernelRelease{
			Fullversion: "3.16.0",
			Version: semver.Version{
				Major: 3,
				Minor: 16,
				Patch: 0,
			},
			Extraversion:     "38-lts-utopic",
			FullExtraversion: "-38-lts-utopic",
			Architecture:     kernelrelease.ArchitectureAmd64,
		},
		kernelversion: "52~14.04.1",
		expected: struct {
			headersURLs []string
			urls        []string
			gccVersion  semver.Version
			firstExtra  string
			flavor      string
			err         error
		}{
			headersURLs: []string{},
			urls:        []string{"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-headers-3.16.0-38-lts-utopic_3.16.0-38.52~14.04.1_amd64_all.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-headers-3.16.0-38-lts-utopic_3.16.0-38.52~14.04.1_amd64.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-lts-utopic-headers-3.16.0-38_3.16.0-38.52~14.04.1_all.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-lts-utopic/linux-headers-3.16.0-38-lts-utopic_3.16.0-38.52~14.04.1_amd64_all.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-lts-utopic/linux-headers-3.16.0-38-lts-utopic_3.16.0-38.52~14.04.1_amd64.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-lts-utopic/linux-lts-utopic-headers-3.16.0-38_3.16.0-38.52~14.04.1_all.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-lts-utopic-3.16/linux-headers-3.16.0-38-lts-utopic_3.16.0-38.52~14.04.1_amd64_all.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-lts-utopic-3.16/linux-headers-3.16.0-38-lts-utopic_3.16.0-38.52~14.04.1_amd64.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-lts-utopic-3.16/linux-lts-utopic-headers-3.16.0-38_3.16.0-38.52~14.04.1_all.deb"},
			gccVersion: semver.Version{
				Major: 6,
			},
			firstExtra: "38",
			flavor:     "lts-utopic",
			err:        nil,
		},
	},
	{
		config: kernelrelease.KernelRelease{
			Fullversion: "5.19.0",
			Version: semver.Version{
				Major: 5,
				Minor: 19,
				Patch: 0,
			},
			Extraversion:     "1006-kvm",
			FullExtraversion: "-1006-kvm",
			Architecture:     kernelrelease.ArchitectureAmd64,
		},
		kernelversion: "6",
		expected: struct {
			headersURLs []string
			urls        []string
			gccVersion  semver.Version
			firstExtra  string
			flavor      string
			err         error
		}{
			headersURLs: []string{},
			urls:        []string{"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-headers-5.19.0-1006-kvm_5.19.0-1006.6_amd64_all.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-headers-5.19.0-1006-kvm_5.19.0-1006.6_amd64.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-kvm-headers-5.19.0-1006_5.19.0-1006.6_all.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-kvm/linux-headers-5.19.0-1006-kvm_5.19.0-1006.6_amd64_all.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-kvm/linux-headers-5.19.0-1006-kvm_5.19.0-1006.6_amd64.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-kvm/linux-kvm-headers-5.19.0-1006_5.19.0-1006.6_all.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-kvm-5.19/linux-headers-5.19.0-1006-kvm_5.19.0-1006.6_amd64_all.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-kvm-5.19/linux-headers-5.19.0-1006-kvm_5.19.0-1006.6_amd64.deb", "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-kvm-5.19/linux-kvm-headers-5.19.0-1006_5.19.0-1006.6_all.deb"},
			gccVersion: semver.Version{
				Major: 12,
			},
			firstExtra: "1006",
			flavor:     "kvm",
			err:        nil,
		},
	},
}

func TestUbuntuHeadersURLFromRelease(t *testing.T) {
	for _, test := range tests {
		expected := test.expected.headersURLs

		// setup input
		input := struct {
			config kernelrelease.KernelRelease
			kv     string
		}{
			test.config,
			test.kernelversion,
		}

		// call function
		gotURLs, err := ubuntuHeadersURLFromRelease(input.config, input.kv)
		// compare errors
		// there are no official errors, so comparing fmt.Errorf() doesn't really work
		// compare error message text instead
		if err != nil && test.expected.err != nil && err.Error() != test.expected.err.Error() {
			t.Fatalf("Unexpected error encountered with Test Input: '%v' | Error: '%s'", input, err)
		}

		// check length of URL slice returned
		if len(gotURLs) != len(expected) {
			t.Fatalf("Slice sizes don't match! Test Input: '%v' | Got: '%v' / Want: '%v'", input, gotURLs, expected)
		}

		// check values are exact match
		for i, v := range gotURLs {
			if v != expected[i] {
				t.Fatalf("Slice values don't match! Test Input: '%v' | Got: '%v' / Want: '%v'", input, gotURLs, expected)
			}
		}
	}
}

func TestFetchUbuntuKernelURL(t *testing.T) {
	for _, test := range tests {

		// setup baseURLs - leave out security for sake of simplicity
		var baseURLs []string
		if test.config.Architecture.String() == kernelrelease.ArchitectureAmd64 {
			baseURLs = []string{
				"https://mirrors.edge.kernel.org/ubuntu/pool/main/l",
			}
		} else {
			baseURLs = []string{
				"http://ports.ubuntu.com/ubuntu-ports/pool/main/l",
			}
		}

		for _, url := range baseURLs {
			expected := test.expected.urls

			// setup input
			input := struct {
				baseURL string
				config  kernelrelease.KernelRelease
				kv      string
			}{
				url,
				test.config,
				test.kernelversion,
			}

			// call function
			gotURLs, err := fetchUbuntuKernelURL(input.baseURL, input.config, input.kv)
			if err != nil {
				t.Fatalf("Unexpected error encountered with Test Input: '%v' | Error: '%s'", input, err)
			}

			// check length of URL slice returned
			if len(gotURLs) != len(expected) {
				t.Fatalf("Slice sizes don't match! Test Input: '%v' | Got: '%v' / Want: '%v'", input, gotURLs, expected)
			}

			// check values are exact match
			for i, v := range gotURLs {
				if v != expected[i] {
					t.Fatalf("Slice values don't match! Test Input: '%v' | Got: '%v' / Want: '%v'", input, gotURLs, expected)
				}
			}
		}
	}
}

func TestParseUbuntuExtraVersion(t *testing.T) {
	for _, test := range tests {
		input := test.config.Extraversion
		gotFirstExtra, gotFlavor := parseUbuntuExtraVersion(input)
		if gotFirstExtra != test.expected.firstExtra {
			t.Errorf(
				"Test Input: [ '%s' ] | Got: [ '%s' ] / Want: [ '%s' ]",
				input,
				gotFirstExtra,
				test.expected.firstExtra,
			)
		}
		if gotFlavor != test.expected.flavor {
			t.Errorf(
				"Test Input: [ '%s' ] | Got: [ '%s' ] / Want: [ '%s' ]",
				input,
				gotFlavor,
				test.expected.flavor,
			)
		}
	}
}
