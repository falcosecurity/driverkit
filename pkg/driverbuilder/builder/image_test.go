package builder

import (
	"github.com/blang/semver"
	"github.com/docker/docker/testutil/registry"
	"gotest.tools/assert"
	"io"
	"net/http"
	"os"
	"testing"
)

var imagesTests = []struct {
	yamlData string
	jsonData string
	expected []Image
}{
	// Test that multiple gcc versions are correctly mapped to multiple images
	{
		yamlData: `
images:
  - name: foo/test:any-x86_64_gcc8.0.0_gcc6.0.0_gcc5.0.0_gcc4.9.0_gcc4.8.0-latest
    target: any
    arch: x86_64
    tag: latest
    gcc_versions:
      - 8.0.0
      - 6.0.0
      - 5.0.0
      - 4.9.0
      - 4.8.0
`,
		jsonData: `
{
  "name": "foo/test",
  "tags": [
    "any-x86_64_gcc8.0.0_gcc6.0.0_gcc5.0.0_gcc4.9.0_gcc4.8.0-latest"
  ]
}
`,
		expected: []Image{
			{
				Target:     "any",
				GCCVersion: semver.MustParse("8.0.0"),
				Name:       "foo/test:any-x86_64_gcc8.0.0_gcc6.0.0_gcc5.0.0_gcc4.9.0_gcc4.8.0-latest",
			},
			{
				Target:     "any",
				GCCVersion: semver.MustParse("6.0.0"),
				Name:       "foo/test:any-x86_64_gcc8.0.0_gcc6.0.0_gcc5.0.0_gcc4.9.0_gcc4.8.0-latest",
			},
			{
				Target:     "any",
				GCCVersion: semver.MustParse("5.0.0"),
				Name:       "foo/test:any-x86_64_gcc8.0.0_gcc6.0.0_gcc5.0.0_gcc4.9.0_gcc4.8.0-latest",
			},
			{
				Target:     "any",
				GCCVersion: semver.MustParse("4.9.0"),
				Name:       "foo/test:any-x86_64_gcc8.0.0_gcc6.0.0_gcc5.0.0_gcc4.9.0_gcc4.8.0-latest",
			},
			{
				Target:     "any",
				GCCVersion: semver.MustParse("4.8.0"),
				Name:       "foo/test:any-x86_64_gcc8.0.0_gcc6.0.0_gcc5.0.0_gcc4.9.0_gcc4.8.0-latest",
			},
		},
	},
	// Test that arm64 is correctly skipped on amd64 images listing
	{
		yamlData: `
images:
  - name: foo/test:any-x86_64_gcc8.0.0-latest
    target: any
    arch: x86_64
    tag: latest
    gcc_versions:
      - 8.0.0
  - name: foo/test:any-aarch64_gcc8.0.0-latest
    target: any
    arch: aarch64
    tag: latest
    gcc_versions:
      - 8.0.0
`,
		jsonData: `
{
  "name": "foo/test",
  "tags": [
    "any-x86_64_gcc8.0.0-latest",
	"any-aarch64_gcc8.0.0-latest"
  ]
}
`,
		expected: []Image{
			{
				Target:     "any",
				GCCVersion: semver.MustParse("8.0.0"),
				Name:       "foo/test:any-x86_64_gcc8.0.0-latest",
			},
		},
	},
	// Test empty gcc versions image is skipped
	{
		yamlData: `
images:
  - name: foo/test:any-x86_64_gcc8.0.0-latest
    target: any
    arch: x86_64
    tag: latest
    gcc_versions:
      - 8.0.0
  - name: bar/test:any-x86_64-latest
    target: any
    arch: x86_64
    tag: latest
`,
		jsonData: `
{
  "name": "foo/test",
  "tags": [
    "any-x86_64_gcc8.0.0-latest",
    "any-x86_64-latest"
  ]
}
`,
		expected: []Image{
			{
				Target:     "any",
				GCCVersion: semver.MustParse("8.0.0"),
				Name:       "foo/test:any-x86_64_gcc8.0.0-latest",
			},
		},
	},
	// Test wrong target image is skipped
	{
		yamlData: `
images:
  - name: foo/test:centos-x86_64_gcc8.0.0-latest
    target: centos
    arch: x86_64
    tag: latest
    gcc_versions:
      - 8.0.0
  - name: foo/test:wrongtarget-x86_64_gcc6.0.0-latest
    target: wrongtarget
    arch: x86_64
    tag: latest
    gcc_versions:
      - 6.0.0
`,
		jsonData: `
{
  "name": "foo/test",
  "tags": [
    "centos-x86_64_gcc8.0.0-latest",
    "wrongtarget-x86_64_gcc8.0.0-latest"
  ]
}
`,
		expected: []Image{
			{
				Target:     "centos",
				GCCVersion: semver.MustParse("8.0.0"),
				Name:       "foo/test:centos-x86_64_gcc8.0.0-latest",
			},
		},
	},
	// Test empty name image is skipped
	{
		yamlData: `
images:
  - name: foo/test:any-x86_64_gcc8.0.0-latest
    target: any
    arch: x86_64
    tag: latest
    gcc_versions:
      - 8.0.0
  - target: any
    arch: x86_64
    tag: latest
    gcc_versions:
      - 6.0.0
`,
		jsonData: "",
		expected: []Image{
			{
				Target:     "any",
				GCCVersion: semver.MustParse("8.0.0"),
				Name:       "foo/test:any-x86_64_gcc8.0.0-latest",
			},
		},
	},
	// Test empty list returned for yaml/json with no images
	{
		yamlData: `
images:
`,
		jsonData: `
{
  "name": "foo/test",
  "tags": [
  ]
}
`,
		expected: nil,
	},
	// Test empty list returned for malformed yaml/json answer
	{
		yamlData: `
images:
  * name: foo/test
    target: any
    arch: x86_64
    gcc_versions:
      * 8.0.0
`,
		jsonData: "malformedresponse",
		expected: nil,
	},
}

func TestFileImagesLister(t *testing.T) {
	// setup images file
	f, err := os.CreateTemp(t.TempDir(), "imagetest")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	lister, err := NewFileImagesLister(f.Name(), &Build{
		TargetType:   Type("centos"),
		Architecture: "amd64",
		BuilderImage: "auto:latest",
	})
	assert.NilError(t, err)

	for _, test := range imagesTests {
		if test.yamlData == "" {
			t.Log("Skipping unsuitable test for FileImagesLister")
			continue
		}

		err = f.Truncate(0)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.Seek(0, io.SeekStart)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.WriteString(test.yamlData)
		if err != nil {
			t.Fatal(err)
		}

		assert.DeepEqual(t, test.expected, lister.LoadImages())
	}
}

func TestRepoImagesLister(t *testing.T) {
	mock, err := registry.NewMock(t)
	assert.NilError(t, err)
	defer mock.Close()

	lister, err := NewRepoImagesLister(mock.URL()+"/foo/test", &Build{
		TargetType:        Type("centos"),
		Architecture:      "amd64",
		BuilderImage:      "auto:latest",
		RegistryPlainHTTP: true,
	})
	assert.NilError(t, err)

	for _, test := range imagesTests {
		if test.jsonData == "" {
			t.Log("Skipping unsuitable test for RepoImagesLister")
			continue
		}

		// Update expected names adding the mocked server URL as prefix
		for idx, _ := range test.expected {
			test.expected[idx].Name = mock.URL() + "/" + test.expected[idx].Name
		}

		mock.RegisterHandler("/v2/foo/test/tags/list", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(test.jsonData))
		})
		assert.DeepEqual(t, test.expected, lister.LoadImages())
	}
}
