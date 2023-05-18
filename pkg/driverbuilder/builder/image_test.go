package builder

import (
	"github.com/blang/semver"
	"gotest.tools/assert"
	"io"
	"os"
	"testing"
)

var imagesTests = []struct {
	yamlData string
	expected []Image
}{
	// Test that multiple gcc versions are correctly mapped to multiple images
	{
		yamlData: `
images:
  - name: foo/test
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
		expected: []Image{
			{
				Target:     "any",
				GCCVersion: semver.MustParse("8.0.0"),
				Name:       "foo/test",
			},
			{
				Target:     "any",
				GCCVersion: semver.MustParse("6.0.0"),
				Name:       "foo/test",
			},
			{
				Target:     "any",
				GCCVersion: semver.MustParse("5.0.0"),
				Name:       "foo/test",
			},
			{
				Target:     "any",
				GCCVersion: semver.MustParse("4.9.0"),
				Name:       "foo/test",
			},
			{
				Target:     "any",
				GCCVersion: semver.MustParse("4.8.0"),
				Name:       "foo/test",
			},
		},
	},
	// Test that arm64 is correctly skipped on amd64 FileImagesLister
	{
		yamlData: `
images:
  - name: foo/test_amd64
    target: any
    arch: x86_64
    tag: latest
    gcc_versions:
      - 8.0.0
  - name: foo/test_arm64
    target: any
    arch: aarch64
    tag: latest
    gcc_versions:
      - 8.0.0
`,
		expected: []Image{
			{
				Target:     "any",
				GCCVersion: semver.MustParse("8.0.0"),
				Name:       "foo/test_amd64",
			},
		},
	},
	// Test that if no arch is provided, the FileImagesLister one is used
	{
		yamlData: `
images:
  - name: foo/test
    target: any
    tag: latest
    gcc_versions:
      - 8.0.0
`,
		expected: []Image{
			{
				Target:     "any",
				GCCVersion: semver.MustParse("8.0.0"),
				Name:       "foo/test",
			},
		},
	},
	// Test that if no tag is provided, the FileImagesLister one is used
	{
		yamlData: `
images:
  - name: foo/test
    target: any
    arch: x86_64
    gcc_versions:
      - 8.0.0
`,
		expected: []Image{
			{
				Target:     "any",
				GCCVersion: semver.MustParse("8.0.0"),
				Name:       "foo/test",
			},
		},
	},
	// Test empty gcc versions image is skipped
	{
		yamlData: `
images:
  - name: foo/test
    target: any
    arch: x86_64
    gcc_versions:
      - 8.0.0
  - name: bar/test
    target: any
    arch: x86_64
`,
		expected: []Image{
			{
				Target:     "any",
				GCCVersion: semver.MustParse("8.0.0"),
				Name:       "foo/test",
			},
		},
	},
	// Test wrong target image is skipped
	{
		yamlData: `
images:
  - name: foo/test
    target: any
    arch: x86_64
    gcc_versions:
      - 8.0.0
  - name: bar/test
    target: testtarget
    arch: x86_64
    gcc_versions:
      - 6.0.0
`,
		expected: []Image{
			{
				Target:     "any",
				GCCVersion: semver.MustParse("8.0.0"),
				Name:       "foo/test",
			},
		},
	},
	// Test empty name image is skipped
	{
		yamlData: `
images:
  - name: foo/test
    target: any
    arch: x86_64
    gcc_versions:
      - 8.0.0
  - target: any
    arch: x86_64
    gcc_versions:
      - 6.0.0
`,
		expected: []Image{
			{
				Target:     "any",
				GCCVersion: semver.MustParse("8.0.0"),
				Name:       "foo/test",
			},
		},
	},
	// Test empty list returned for yaml with no images
	{
		yamlData: `
images:
`,
		expected: nil,
	},
	// Test empty list returned for malformed yaml
	{
		yamlData: `
images:
  * name: foo/test
    target: any
    arch: x86_64
    gcc_versions:
      * 8.0.0
`,
		expected: nil,
	},
}

func TestImagesListingFromFile(t *testing.T) {
	// setup images file
	f, err := os.CreateTemp(t.TempDir(), "imagetest")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	lister := FileImagesLister{
		FilePath: f.Name(),
		Arch:     "x86_64",
		Tag:      "latest",
	}

	for _, test := range imagesTests {
		expected := test.expected

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

		assert.DeepEqual(t, expected, lister.LoadImages())
	}
}
