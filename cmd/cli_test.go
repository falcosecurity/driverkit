//go:build !race
// +build !race

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

package cmd

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"text/template"

	"github.com/falcosecurity/driverkit/pkg/driverbuilder/builder"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"

	"github.com/acarl005/stripansi"
	"gotest.tools/assert"
)

type expect struct {
	err string
	out string
}

type testCase struct {
	descr  string
	env    map[string]string
	args   []string
	expect expect
}

var tests = []testCase{
	{
		args: []string{"help"},
		expect: expect{
			out: "testdata/help.txt",
		},
	},
	{
		args: []string{"-h"},
		expect: expect{
			out: "testdata/help-flag.txt",
		},
	},
	{
		descr: "empty",
		args:  []string{},
		expect: expect{
			out: "testdata/autohelp.txt",
		},
	},
	{
		descr: "invalid/processor",
		args:  []string{"abc"},
		expect: expect{
			out: "testdata/non-existent-processor.txt",
			err: `invalid argument "abc" for "driverkit"`,
		},
	},
	{
		descr: "invalid/config/proxy",
		args: []string{
			"--proxy",
			"wrong",
		},
		expect: expect{
			out: "testdata/invalid-proxyconfig.txt",
			err: "exiting for validation errors",
		},
	},
	{
		descr: "docker/all-flags",
		args: []string{
			"docker",
			"--kernelrelease",
			"4.15.0-1057-aws",
			"--kernelversion",
			"59",
			"--kernelurls",
			"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-aws/linux-aws-headers-4.15.0-1057_4.15.0-1057.59_all.deb",
			"--kernelurls",
			"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-aws/linux-headers-4.15.0-1057-aws_4.15.0-1057.59_amd64.deb",
			"--target",
			"ubuntu-aws",
			"--output-module",
			"/tmp/falco-ubuntu-aws.ko",
		},
		expect: expect{
			out: "testdata/docker-with-flags.txt",
		},
	},
	{
		descr: "docker/empty",
		args:  []string{"docker"},
		expect: expect{
			err: "exiting for validation errors",
			out: "testdata/dockernoopts.txt",
		},
	},
	{
		descr: "docker/all-flags-debug",
		args: []string{
			"docker",
			"--kernelrelease",
			"4.15.0-1057-aws",
			"--kernelversion",
			"59",
			"--kernelurls",
			"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-aws/linux-aws-headers-4.15.0-1057_4.15.0-1057.59_all.deb",
			"--kernelurls",
			"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-aws/linux-headers-4.15.0-1057-aws_4.15.0-1057.59_amd64.deb",
			"--target",
			"ubuntu-aws",
			"--output-module",
			"/tmp/falco-ubuntu-aws.ko",
			"--loglevel",
			"debug",
		},
		expect: expect{
			out: "testdata/docker-with-flags-debug.txt",
		},
	},
	{
		descr: "docker/merge-from-env",
		env: map[string]string{
			"DRIVERKIT_KERNELVERSION": "59",
			"DRIVERKIT_OUTPUT_MODULE": "/tmp/falco-ubuntu-aws.ko",
		},
		args: []string{
			"docker",
			"--kernelrelease",
			"4.15.0-1057-aws",
			"--kernelurls",
			"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-aws/linux-aws-headers-4.15.0-1057_4.15.0-1057.59_all.deb",
			"--kernelurls",
			"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-aws/linux-headers-4.15.0-1057-aws_4.15.0-1057.59_amd64.deb",
			"-t",
			"ubuntu-aws",
			"--loglevel",
			"debug",
		},
		expect: expect{
			out: "testdata/docker-with-flags-debug.txt",
		},
	},
	{
		descr: "docker/from-config-file",
		args: []string{
			"docker",
			"-c",
			"testdata/configs/1.yaml",
			"--loglevel",
			"debug",
		},
		expect: expect{
			out: "testdata/docker-from-config-debug.txt",
		},
	},
	{
		descr: "docker/from-config-file-using-urls",
		args: []string{
			"docker",
			"-c",
			"testdata/configs/2.yaml",
			"--loglevel",
			"debug",
		},
		expect: expect{
			out: "testdata/docker-override-urls-from-config-debug.txt",
		},
	},
	{
		descr: "docker/override-from-config-file",
		env: map[string]string{
			"DRIVERKIT_KERNELVERSION": "229",
			"DRIVERKIT_OUTPUT_MODULE": "/tmp/override.ko",
		},
		args: []string{
			"docker",
			"-c",
			"testdata/configs/1.yaml",
			"--loglevel",
			"debug",
		},
		expect: expect{
			out: "testdata/docker-override-from-config-debug.txt",
		},
	},
	{
		descr: "docker/build-related-target-azure",
		args: []string{
			"docker",
			"--kernelrelease",
			"4.15.0-1057-azure",
			"--kernelversion",
			"62",
			"--kernelurls",
			"http://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-azure/linux-azure-headers-4.15.0-1057_4.15.0-1057.62_all.deb",
			"--kernelurls",
			"http://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-azure/linux-headers-4.15.0-1057-azure_4.15.0-1057.62_amd64.deb",
			"--target",
			"ubuntu-azure",
			"--output-module",
			"/tmp/falco-ubuntu-azure.ko",
			"--loglevel",
			"debug",
		},
		expect: expect{
			out: "testdata/docker-related-target-debug.txt",
		},
	},
	{
		descr: "docker/build-target-check-validation-redhat",
		args: []string{
			"docker",
			"--kernelrelease",
			"4.18.0-348.el8.x86_64",
			"--target",
			"redhat",
			"--output-module",
			"/tmp/falco-redhat.ko",
			"--loglevel",
			"debug",
		},
		expect: expect{
			out: "testdata/docker-target-redhat-validation-error-debug.txt",
			err: "exiting for validation errors",
		},
	},
	{
		descr: "complete/docker/targets",
		args: []string{
			"__complete",
			"docker",
			"--target",
			"ENTER",
		},
		expect: expect{
			out: "testdata/completion-targets.txt",
		},
	},
	{
		descr: "complete/kubernetes-alias/targets",
		args: []string{
			"__complete",
			"k8s",
			"--target",
			"ENTER",
		},
		expect: expect{
			out: "testdata/completion-targets.txt",
		},
	},
	{
		descr: "complete/kubernetes/targets",
		args: []string{
			"__complete",
			"kubernetes",
			"--target",
			"ENTER",
		},
		expect: expect{
			out: "testdata/completion-targets.txt",
		},
	},
	{
		descr: "completion/empty",
		args: []string{
			"completion",
		},
		expect: expect{
			out: "testdata/completion-noargs.txt",
		},
	},
	{
		descr: "completion/help",
		args: []string{
			"completion",
			"help",
		},
		expect: expect{
			out: "testdata/completion-noargs.txt",
		},
	},
	{
		descr: "completion/help-short-flag",
		args: []string{
			"completion",
			"-h",
		},
		expect: expect{
			out: "testdata/completion-noargs.txt",
		},
	},
}

func run(t *testing.T, test testCase) {
	// Setup
	configOpts, err := NewConfigOptions()
	assert.NilError(t, err)
	rootOpts, err := NewRootOptions()
	assert.NilError(t, err)
	c := NewRootCmd(configOpts, rootOpts)
	b := bytes.NewBufferString("")
	configOpts.SetOutput(b)
	if len(test.args) == 0 || (test.args[0] != "__complete" && test.args[0] != "__completeNoDesc" && test.args[0] != "help" && test.args[0] != "completion") {
		test.args = append(test.args, "--dryrun")
	}
	c.SetArgs(test.args)
	for k, v := range test.env {
		if err := os.Setenv(k, v); err != nil {
			t.Fatalf("error setting env variables: %v", err)
		}
	}
	// Test
	err = c.Execute()
	if err != nil {
		if test.expect.err == "" {
			t.Fatalf("error executing CLI: %v", err)
		} else {
			assert.Error(t, err, test.expect.err)
		}
	}
	out, err := io.ReadAll(b)
	if err != nil {
		t.Fatalf("error reading CLI output: %v", err)
	}
	res := stripansi.Strip(string(out))
	assert.Equal(t, test.expect.out, res)
	// Teardown
	for k := range test.env {
		if err := os.Unsetenv(k); err != nil {
			t.Fatalf("error tearing down: %v", err)
		}
	}
}

// Simple explanation:
// basically we leverage text.template to execute templates for test data.
// testTemplateData is the actual template structure used to fill the test requested output.
// It internally stores all the help text, split in section { Desc, Usage, Commands, Flags, Info }
// plus the flagsTemplateData (that is the template data used to fill Flags fields basically).
type testTemplateData struct {
	Desc     string
	Usage    string
	Commands string
	Flags    string
	Info     string
	flagsTemplateData
}

func readTemplateFile(t *testing.T, s string) string {
	out, err := ioutil.ReadFile("testdata/templates/" + s)
	assert.NilError(t, err)
	return string(out)
}

func initTestTemplateData(t *testing.T, args []string) testTemplateData {
	td := initFlagsTemplateData(args)
	return testTemplateData{
		Usage:             readTemplateFile(t, "usage.txt"),
		Commands:          readTemplateFile(t, "commands.txt"),
		Flags:             runTemplate(t, readTemplateFile(t, "flags.txt"), td),
		Desc:              readTemplateFile(t, "desc.txt"),
		Info:              readTemplateFile(t, "info.txt"),
		flagsTemplateData: td,
	}
}

type flagsTemplateData struct {
	Targets             string
	CurrentArch         string
	Architectures       string
	TargetsVerticalList string

	// It is the subcmd being called, ie: driverkit (root) or docker,kubernetes.
	// It is automatically fetched by args passed to each test case
	Cmd string
}

func initFlagsTemplateData(args []string) flagsTemplateData {
	targets := builder.Targets()
	sort.Strings(targets)

	cmd := "driverkit"
	if len(args) > 0 {
		if args[0] == "docker" {
			cmd = "docker"
		} else if args[0] == "kubernetes" {
			cmd = "kubernetes"
		}
	}

	return flagsTemplateData{
		Targets:             "[" + strings.Join(targets, ",") + "]",
		CurrentArch:         runtime.GOARCH,
		Architectures:       kernelrelease.SupportedArchs.String(),
		TargetsVerticalList: strings.Join(targets, "\n"),
		Cmd:                 cmd,
	}
}

func runTemplate(t *testing.T, f string, td interface{}) string {
	tplate := template.New("test")
	parsed, err := tplate.Parse(f)
	assert.NilError(t, err)
	buf := bytes.NewBuffer(nil)
	err = parsed.Execute(buf, td)
	assert.NilError(t, err)
	return buf.String()
}

func TestCLI(t *testing.T) {
	for _, test := range tests {
		descr := test.descr
		if descr == "" {
			if test.expect.out == "" {
				t.Fatal("malformed test case: missing both descr and expect.out fields")
			}
			test.descr = strings.TrimSuffix(filepath.Base(test.expect.out), ".txt")
		}
		if test.expect.out != "" {
			out, err := os.ReadFile(test.expect.out)
			if err != nil {
				t.Fatalf("output fixture not found: %v", err)
			}
			td := initTestTemplateData(t, test.args)
			test.expect.out = runTemplate(t, string(out), td)
		}

		t.Run(test.descr, func(t *testing.T) {
			run(t, test)
		})
	}
}
