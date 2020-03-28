// +build !race

package cmd

import (
	"bytes"
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"

	"github.com/acarl005/stripansi"
	"gotest.tools/assert"
)

type expect struct {
	err string
	out string
}

type testCase struct {
	descr  string
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
		args: []string{},
		expect: expect{
			out: "testdata/autohelp.txt",
		},
	},
	{
		args: []string{"help", "--loglevel", "debug"},
		expect: expect{
			out: "testdata/help-debug.txt",
		},
	},
	{
		args: []string{"docker"},
		expect: expect{
			out: "testdata/noflags.txt",
		},
	},
	{
		descr: "invalid-processor",
		args:  []string{"abc"},
		expect: expect{
			out: "testdata/non-existent-processor.txt",
			err: `invalid argument "abc" for "driverkit"`,
		},
	},
}

func run(t *testing.T, test testCase) {
	// Setup
	c := NewRootCmd()
	b := bytes.NewBufferString("")
	c.SetOutput(b)
	c.SetArgs(test.args)
	// Test
	if err := c.Execute(); err != nil {
		if test.expect.err == "" {
			t.Fatalf("error executing CLI: %v", err)
		} else {
			assert.Error(t, err, test.expect.err)
		}
	}
	out, err := ioutil.ReadAll(b)
	if err != nil {
		t.Fatal(err)
	}
	res := stripansi.Strip(string(out))

	assert.Equal(t, test.expect.out, res)
}

func TestCLI(t *testing.T) {
	for _, test := range tests {
		descr := test.descr
		if descr == "" {
			test.descr = strings.TrimSuffix(filepath.Base(test.expect.out), ".txt")
		}
		if test.expect.out != "" {
			out, err := ioutil.ReadFile(test.expect.out)
			if err != nil {
				t.Fatalf("output fixture not found: %v", err)
			}
			test.expect.out = string(out)
		}

		t.Run(test.descr, func(t *testing.T) {
			t.Parallel()
			run(t, test)
		})
	}
}
