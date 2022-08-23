package kernelrelease

import (
	"encoding/json"
	"testing"

	"gotest.tools/assert"
)

func TestFromKrToJson(t *testing.T) {
	test := struct {
		kernelRelease KernelRelease
		want          string
	}{
		kernelRelease: KernelRelease{
			Fullversion:      "5.16.5",
			Version:          5,
			PatchLevel:       16,
			Sublevel:         5,
			Extraversion:     "arch1-1",
			FullExtraversion: "-arch1-1",
			Architecture:     "amd64",
		},
		want: `{"full_version":"5.16.5","version":5,"patch_level":16,"sublevel":5,"extra_version":"arch1-1","full_extra_version":"-arch1-1","architecture":"amd64"}`,
	}
	t.Run("version with local version", func(t *testing.T) {
		got, _ := json.Marshal(test.kernelRelease)
		assert.Equal(t, test.want, string(got))
	})
}

func TestFromString(t *testing.T) {
	tests := map[string]struct {
		kernelVersionStr string
		want             KernelRelease
	}{
		"version with local version": {
			kernelVersionStr: "5.5.2-arch1-1",
			want: KernelRelease{
				Fullversion:      "5.5.2",
				Version:          5,
				PatchLevel:       5,
				Sublevel:         2,
				Extraversion:     "arch1-1",
				FullExtraversion: "-arch1-1",
			},
		},
		"just kernel version": {
			kernelVersionStr: "5.5.2",
			want: KernelRelease{
				Fullversion:      "5.5.2",
				Version:          5,
				PatchLevel:       5,
				Sublevel:         2,
				Extraversion:     "",
				FullExtraversion: "",
			},
		},
		"an empty string": {
			kernelVersionStr: "",
			want: KernelRelease{
				Fullversion:      "",
				Version:          0,
				PatchLevel:       0,
				Sublevel:         0,
				Extraversion:     "",
				FullExtraversion: "",
			},
		},
		"version with aws local version": {
			kernelVersionStr: "4.15.0-1057-aws",
			want: KernelRelease{
				Fullversion:      "4.15.0",
				Version:          4,
				PatchLevel:       15,
				Sublevel:         0,
				Extraversion:     "1057-aws",
				FullExtraversion: "-1057-aws",
			},
		},
		"centos version updates": {
			kernelVersionStr: "3.10.0-957.12.2.el7.aarch64",
			want: KernelRelease{
				Fullversion:      "3.10.0",
				Version:          3,
				PatchLevel:       10,
				Sublevel:         0,
				Extraversion:     "957",
				FullExtraversion: "-957.12.2.el7.aarch64",
			},
		},
		"centos version os": {
			kernelVersionStr: "2.6.32-754.el6.x86_64",
			want: KernelRelease{
				Fullversion:      "2.6.32",
				Version:          2,
				PatchLevel:       6,
				Sublevel:         32,
				Extraversion:     "754",
				FullExtraversion: "-754.el6.x86_64",
			},
		},
		"debian jessie version": {
			kernelVersionStr: "3.16.0-10-amd64",
			want: KernelRelease{
				Fullversion:      "3.16.0",
				Version:          3,
				PatchLevel:       16,
				Sublevel:         0,
				Extraversion:     "10-amd64",
				FullExtraversion: "-10-amd64",
			},
		},
		"debian buster version": {
			kernelVersionStr: "4.19.0-6-amd64",
			want: KernelRelease{
				Fullversion:      "4.19.0",
				Version:          4,
				PatchLevel:       19,
				Sublevel:         0,
				Extraversion:     "6-amd64",
				FullExtraversion: "-6-amd64",
			},
		},
		"amazon linux 2 version": {
			kernelVersionStr: "4.14.171-136.231.amzn2.x86_64",
			want: KernelRelease{
				Fullversion:      "4.14.171",
				Version:          4,
				PatchLevel:       14,
				Sublevel:         171,
				Extraversion:     "136",
				FullExtraversion: "-136.231.amzn2.x86_64",
			},
		},
		"gke version": {
			kernelVersionStr: "4.15.0-1044-gke",
			want: KernelRelease{
				Fullversion:      "4.15.0",
				Version:          4,
				PatchLevel:       15,
				Sublevel:         0,
				Extraversion:     "1044-gke",
				FullExtraversion: "-1044-gke",
			},
		},
		"arch version": {
			kernelVersionStr: "5.19.3.arch1-1",
			want: KernelRelease{
				Fullversion:      "5.19.3",
				Version:          5,
				PatchLevel:       19,
				Sublevel:         3,
				Extraversion:     "arch1-1",
				FullExtraversion: ".arch1-1",
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := FromString(tt.kernelVersionStr)
			assert.Equal(t, tt.want, got)
		})
	}
}
