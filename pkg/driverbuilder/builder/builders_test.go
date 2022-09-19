package builder

import (
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"testing"
)

var gccTests = []struct {
	config      kernelrelease.KernelRelease
	expectedGCC float64
}{
	{
		config: kernelrelease.KernelRelease{
			Fullversion:      "4.15.0",
			Version:          4,
			PatchLevel:       15,
			Sublevel:         0,
			Extraversion:     "188",
			FullExtraversion: "-188",
			Architecture:     kernelrelease.ArchitectureAmd64,
		},
		expectedGCC: 8,
	},
	{
		config: kernelrelease.KernelRelease{
			Fullversion:      "5.15.0",
			Version:          5,
			PatchLevel:       15,
			Sublevel:         0,
			Extraversion:     "1004-intel-iotg",
			FullExtraversion: "-1004-intel-iotg",
			Architecture:     kernelrelease.ArchitectureAmd64,
		},
		expectedGCC: 11,
	},
	{
		config: kernelrelease.KernelRelease{
			Fullversion:      "3.13.0",
			Version:          3,
			PatchLevel:       13,
			Sublevel:         0,
			Extraversion:     "100",
			FullExtraversion: "-100",
			Architecture:     kernelrelease.ArchitectureAmd64,
		},
		expectedGCC: 4.9,
	},
	{
		config: kernelrelease.KernelRelease{
			Fullversion:      "5.18.0",
			Version:          5,
			PatchLevel:       18,
			Sublevel:         0,
			Extraversion:     "1001-kvm",
			FullExtraversion: "-1001-kvm",
			Architecture:     kernelrelease.ArchitectureAmd64,
		},
		expectedGCC: 12,
	},
}

func TestDefaultGCC(t *testing.T) {
	for _, test := range gccTests {
		// call function
		selectedGCC := defaultGCC(test.config)

		// compare errors
		// there are no official errors, so comparing fmt.Errorf() doesn't really work
		// compare error message text instead
		if test.expectedGCC != selectedGCC {
			t.Fatalf("SelectedGCC (%f) != expectedGCC (%f) with kernelrelease: '%v'", selectedGCC, test.expectedGCC, test.config)
		}
	}
}
