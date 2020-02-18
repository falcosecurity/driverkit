package filesystem

import "testing"

func Test_stripPath(t *testing.T) {
	tests := map[string]struct {
		path string
		want string
	}{
		"simple paths is untouched": {
			path: "/tmp/test",
			want: "tmp/test",
		},
		"single shortcut is removed": {
			path: "/tmp/../test",
			want: "test",
		},
		"multiple shortcut is removed": {
			path: "/tmp/../../test",
			want: "test",
		},
		"path starting with dots and slash": {
			path: "../../test",
			want: "test",
		},
		"path just dots": {
			path: "..",
			want: "",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := stripPath(tt.path); got != tt.want {
				t.Errorf("stripPath() = %v, want %v", got, tt.want)
			}
		})
	}
}
