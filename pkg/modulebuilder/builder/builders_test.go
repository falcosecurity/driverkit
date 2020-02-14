package builder

import "testing"

func Test_isBuildTypeEnabled(t *testing.T) {
	tests := map[string]struct {
		str  string
		want bool
	}{
		"enabled and present": {
			str:  string(BuildTypeVanilla),
			want: true,
		},
		"not present": {
			str:  "something",
			want: false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := isBuildTypeEnabled(tt.str); got != tt.want {
				t.Errorf("isBuildTypeEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}
