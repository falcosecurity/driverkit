package kernelrelease

import (
	"testing"

	"github.com/blang/semver"

	"gotest.tools/assert"
)

func TestFromString(t *testing.T) {
	tests := map[string]struct {
		kernelVersionStr string
		want             KernelRelease
	}{
		"version with local version": {
			kernelVersionStr: "5.5.2-arch1-1",
			want: KernelRelease{
				Fullversion: "5.5.2",
				Version: semver.Version{
					Major: 5,
					Minor: 5,
					Patch: 2,
				},
				Extraversion:     "arch1-1",
				FullExtraversion: "-arch1-1",
			},
		},
		"just kernel version": {
			kernelVersionStr: "5.5.2",
			want: KernelRelease{
				Fullversion: "5.5.2",
				Version: semver.Version{
					Major: 5,
					Minor: 5,
					Patch: 2,
				},
				Extraversion:     "",
				FullExtraversion: "",
			},
		},
		"an empty string": {
			kernelVersionStr: "",
			want: KernelRelease{
				Fullversion: "",
				Version: semver.Version{
					Major: 0,
					Minor: 0,
					Patch: 0,
				},
				Extraversion:     "",
				FullExtraversion: "",
			},
		},
		"version with aws local version": {
			kernelVersionStr: "4.15.0-1057-aws",
			want: KernelRelease{
				Fullversion: "4.15.0",
				Version: semver.Version{
					Major: 4,
					Minor: 15,
					Patch: 0,
				},
				Extraversion:     "1057-aws",
				FullExtraversion: "-1057-aws",
			},
		},
		"centos version updates": {
			kernelVersionStr: "3.10.0-957.12.2.el7.aarch64",
			want: KernelRelease{
				Fullversion: "3.10.0",
				Version: semver.Version{
					Major: 3,
					Minor: 10,
					Patch: 0,
				},
				Extraversion:     "957",
				FullExtraversion: "-957.12.2.el7.aarch64",
			},
		},
		"centos version os": {
			kernelVersionStr: "2.6.32-754.el6.x86_64",
			want: KernelRelease{
				Fullversion: "2.6.32",
				Version: semver.Version{
					Major: 2,
					Minor: 6,
					Patch: 32,
				},
				Extraversion:     "754",
				FullExtraversion: "-754.el6.x86_64",
			},
		},
		"debian jessie version": {
			kernelVersionStr: "3.16.0-10-amd64",
			want: KernelRelease{
				Fullversion: "3.16.0",
				Version: semver.Version{
					Major: 3,
					Minor: 16,
					Patch: 0,
				},
				Extraversion:     "10-amd64",
				FullExtraversion: "-10-amd64",
			},
		},
		"debian buster version": {
			kernelVersionStr: "4.19.0-6-amd64",
			want: KernelRelease{
				Fullversion: "4.19.0",
				Version: semver.Version{
					Major: 4,
					Minor: 19,
					Patch: 0,
				},
				Extraversion:     "6-amd64",
				FullExtraversion: "-6-amd64",
			},
		},
		"amazon linux 2 version": {
			kernelVersionStr: "4.14.171-136.231.amzn2.x86_64",
			want: KernelRelease{
				Fullversion: "4.14.171",
				Version: semver.Version{
					Major: 4,
					Minor: 14,
					Patch: 171,
				},
				Extraversion:     "136",
				FullExtraversion: "-136.231.amzn2.x86_64",
			},
		},
		"gke version": {
			kernelVersionStr: "4.15.0-1044-gke",
			want: KernelRelease{
				Fullversion: "4.15.0",
				Version: semver.Version{
					Major: 4,
					Minor: 15,
					Patch: 0,
				},
				Extraversion:     "1044-gke",
				FullExtraversion: "-1044-gke",
			},
		},
		"arch version": {
			kernelVersionStr: "5.19.3.arch1-1",
			want: KernelRelease{
				Fullversion: "5.19.3",
				Version: semver.Version{
					Major: 5,
					Minor: 19,
					Patch: 3,
				},
				Extraversion:     "arch1-1",
				FullExtraversion: ".arch1-1",
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := FromString(tt.kernelVersionStr)
			assert.DeepEqual(t, tt.want, got)
		})
	}
}

func TestSupportsModule(t *testing.T) {
	unsupported := []KernelRelease{
		{
			Version:      semver.Version{Major: 2, Minor: 5, Patch: 0},
			Architecture: ArchitectureAmd64,
		},
		{
			Version:      semver.Version{Major: 2, Minor: 5, Patch: 99},
			Architecture: ArchitectureAmd64,
		},
		{
			Version:      semver.Version{Major: 2, Minor: 6, Patch: 0},
			Architecture: ArchitectureArm64,
		},
		{
			Version:      semver.Version{Major: 3, Minor: 3, Patch: 99},
			Architecture: ArchitectureArm64,
		},
		{
			Version:      semver.Version{Major: 3, Minor: 3, Patch: 99},
			Architecture: ArchitectureArm64,
		},
	}
	supported := []KernelRelease{
		{
			Version:      semver.Version{Major: 2, Minor: 6, Patch: 0},
			Architecture: ArchitectureAmd64,
		},
		{
			Version:      semver.Version{Major: 2, Minor: 6, Patch: 1},
			Architecture: ArchitectureAmd64,
		},
		{
			Version:      semver.Version{Major: 3, Minor: 0, Patch: 0},
			Architecture: ArchitectureAmd64,
		},
		{
			Version:      semver.Version{Major: 5, Minor: 0, Patch: 0},
			Architecture: ArchitectureAmd64,
		},
		{
			Version:      semver.Version{Major: 3, Minor: 4, Patch: 0},
			Architecture: ArchitectureArm64,
		},
		{
			Version:      semver.Version{Major: 3, Minor: 4, Patch: 1},
			Architecture: ArchitectureArm64,
		},
		{
			Version:      semver.Version{Major: 5, Minor: 0, Patch: 0},
			Architecture: ArchitectureArm64,
		},
	}

	for _, r := range unsupported {
		if r.SupportsModule() {
			t.Errorf("building module should not be supported in kernel version %s", r.String())
		}
	}
	for _, r := range supported {
		if !r.SupportsModule() {
			t.Errorf("building module should be supported in kernel version %s", r.String())
		}
	}
}

func TestSupportsProbe(t *testing.T) {
	unsupported := []KernelRelease{
		{
			Version:      semver.Version{Major: 4, Minor: 13, Patch: 0},
			Architecture: ArchitectureAmd64,
		},
		{
			Version:      semver.Version{Major: 4, Minor: 13, Patch: 99},
			Architecture: ArchitectureAmd64,
		},
		{
			Version:      semver.Version{Major: 4, Minor: 14, Patch: 0},
			Architecture: ArchitectureArm64,
		},
		{
			Version:      semver.Version{Major: 4., Minor: 16, Patch: 0},
			Architecture: ArchitectureArm64,
		},
		{
			Version:      semver.Version{Major: 4, Minor: 16, Patch: 99},
			Architecture: ArchitectureArm64,
		},
	}
	supported := []KernelRelease{
		{
			Version:      semver.Version{Major: 4, Minor: 14, Patch: 0},
			Architecture: ArchitectureAmd64,
		},
		{
			Version:      semver.Version{Major: 4, Minor: 14, Patch: 1},
			Architecture: ArchitectureAmd64,
		},
		{
			Version:      semver.Version{Major: 5, Minor: 0, Patch: 0},
			Architecture: ArchitectureAmd64,
		},
		{
			Version:      semver.Version{Major: 4, Minor: 17, Patch: 0},
			Architecture: ArchitectureArm64,
		},
		{
			Version:      semver.Version{Major: 4, Minor: 17, Patch: 1},
			Architecture: ArchitectureArm64,
		},
		{
			Version:      semver.Version{Major: 5, Minor: 0, Patch: 0},
			Architecture: ArchitectureArm64,
		},
	}

	for _, r := range unsupported {
		if r.SupportsProbe() {
			t.Errorf("building probe should not be supported in kernel version %s", r.String())
		}
	}
	for _, r := range supported {
		if !r.SupportsProbe() {
			t.Errorf("building probe should be supported in kernel version %s", r.String())
		}
	}
}
