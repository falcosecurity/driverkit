package kernelrelease

import (
	"reflect"
	"testing"
)

func TestFromString(t *testing.T) {
	tests := map[string]struct {
		kernelVersionStr string
		want             KernelRelease
	}{
		"version with local version": {
			kernelVersionStr: "5.5.2-arch1-1",
			want: KernelRelease{
				Fullversion:      "5.5.2",
				Version:          "5",
				PatchLevel:       "5",
				Sublevel:         "2",
				Extraversion:     "arch1-1",
				FullExtraversion: "-arch1-1",
			},
		},
		"just kernel version": {
			kernelVersionStr: "5.5.2",
			want: KernelRelease{
				Fullversion:      "5.5.2",
				Version:          "5",
				PatchLevel:       "5",
				Sublevel:         "2",
				Extraversion:     "",
				FullExtraversion: "",
			},
		},
		"an empty string": {
			kernelVersionStr: "",
			want: KernelRelease{
				Fullversion:      "",
				Version:          "",
				PatchLevel:       "",
				Sublevel:         "",
				Extraversion:     "",
				FullExtraversion: "",
			},
		},
		"version with aws local version": {
			kernelVersionStr: "4.15.0-1057-aws",
			want: KernelRelease{
				Fullversion:      "4.15.0",
				Version:          "4",
				PatchLevel:       "15",
				Sublevel:         "0",
				Extraversion:     "1057-aws",
				FullExtraversion: "-1057-aws",
			},
		},
		"centos version updates": {
			kernelVersionStr: "3.10.0-957.12.2.el7.x86_64",
			want: KernelRelease{
				Fullversion:      "3.10.0",
				Version:          "3",
				PatchLevel:       "10",
				Sublevel:         "0",
				Extraversion:     "957",
				FullExtraversion: "-957.12.2.el7.x86_64",
			},
		},
		"centos version os": {
			kernelVersionStr: "2.6.32-754.el6.x86_64",
			want: KernelRelease{
				Fullversion:      "2.6.32",
				Version:          "2",
				PatchLevel:       "6",
				Sublevel:         "32",
				Extraversion:     "754",
				FullExtraversion: "-754.el6.x86_64",
			},
		},
		"debian jessie version": {
			kernelVersionStr: "3.16.0-10-amd64",
			want: KernelRelease{
				Fullversion:      "3.16.0",
				Version:          "3",
				PatchLevel:       "16",
				Sublevel:         "0",
				Extraversion:     "10-amd64",
				FullExtraversion: "-10-amd64",
			},
		},
		"debian buster version": {
			kernelVersionStr: "4.19.0-6-amd64",
			want: KernelRelease{
				Fullversion:      "4.19.0",
				Version:          "4",
				PatchLevel:       "19",
				Sublevel:         "0",
				Extraversion:     "6-amd64",
				FullExtraversion: "-6-amd64",
			},
		},
		"linuxkit version": {
			kernelVersionStr: "4.14.171-linuxkit",
			want: KernelRelease{
				Fullversion:      "4.14.171",
				Version:          "4",
				PatchLevel:       "14",
				Sublevel:         "171",
				Extraversion:     "linuxkit",
				FullExtraversion: "-linuxkit",
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := FromString(tt.kernelVersionStr)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FromString() = %v, want %v", got, tt.want)
			}
		})
	}
}
