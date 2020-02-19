package kernelversion

import (
	"reflect"
	"testing"
)

func TestFromString(t *testing.T) {
	tests := map[string]struct {
		kernelVersionStr string
		want             KernelVersion
		wantErr          bool
	}{
		"version with local version": {
			kernelVersionStr: "5.5.2-arch1-1",
			want: KernelVersion{
				Version:      "5.5.2",
				LocalVersion: "arch1-1",
			},
		},
		"just kernel version": {
			kernelVersionStr: "5.5.2",
			want: KernelVersion{
				Version:      "5.5.2",
				LocalVersion: "",
			},
		},
		"an empty string": {
			kernelVersionStr: "",
			want: KernelVersion{
				Version:      "",
				LocalVersion: "",
			},
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := FromString(tt.kernelVersionStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("FromString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FromString() = %v, want %v", got, tt.want)
			}
		})
	}
}
