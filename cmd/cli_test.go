package cmd

import (
	"bytes"
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"

	"gotest.tools/assert"
)

type expect struct {
	err error
	out string
}

type testCase struct {
	args   []string
	expect expect
}

var tests = []testCase{
	{
		args: []string{"help"},
		expect: expect{
			err: nil,
			out: "testdata/help.txt",
		},
	},
}

func TestCLI(t *testing.T) {
	for _, test := range tests {
		if test.expect.out == "" {
			t.Fatal("each CLI test needs an output fixture")
		}
		name := strings.TrimSuffix(filepath.Base(test.expect.out), ".txt")

		out, err := ioutil.ReadFile(test.expect.out)
		if err != nil {
			t.Fatalf("output fixture not found: %v", err)
		}
		test.expect.out = string(out)

		t.Run(name, func(t *testing.T) {
			//t.Parallel()
			run(t, test)
		})
	}
}

func run(t *testing.T, test testCase) {
	c := NewRootCmd()
	b := bytes.NewBufferString("")
	c.SetOut(b)
	c.SetArgs(test.args)
	if err := c.Execute(); err != nil {
		t.Fatalf("error executing CLI: %v", err)
	}
	res, err := ioutil.ReadAll(b)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, test.expect.out, string(res))
}
