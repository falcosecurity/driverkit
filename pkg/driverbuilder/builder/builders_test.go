package builder

import (
	"testing"

	"github.com/blang/semver"
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
