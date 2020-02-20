package kernelversion

import (
	"reflect"
	"testing"
)

func TestFromString(t *testing.T) {
	tests := map[string]struct {
		kernelVersionStr string
		want             KernelVersion
	}{
		"version with local version": {
			kernelVersionStr: "5.5.2-arch1-1",
			want: KernelVersion{
				Fullversion: "5.5.2",
				Version:      "5",
				PatchLevel:   "5",
				Sublevel:     "2",
				Extraversion: "arch1-1",
				FullExtraversion: "-arch1-1",
			},
		},
		"just kernel version": {
			kernelVersionStr: "5.5.2",
			want: KernelVersion{
				Fullversion: "5.5.2",
				Version:      "5",
				PatchLevel:   "5",
				Sublevel:     "2",
				Extraversion: "",
				FullExtraversion: "",
			},
		},
		"an empty string": {
			kernelVersionStr: "",
			want: KernelVersion{
				Fullversion: "",
				Version:      "",
				PatchLevel:   "",
				Sublevel:     "",
				Extraversion: "",
				FullExtraversion: "",
			},
		},
		"version with aws local version": {
			kernelVersionStr: "4.15.0-1057-aws",
			want: KernelVersion{
				Fullversion: "4.15.0",
				Version:      "4",
				PatchLevel:   "15",
				Sublevel:     "0",
				Extraversion: "1057-aws",
				FullExtraversion: "-1057-aws",
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
