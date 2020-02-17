package kernelutils

import "strings"

func ExtractLocalVersion(kernelVersion string) string {
	sp := strings.SplitN(kernelVersion, "-", 2)
	if len(sp) == 2 {
		return sp[1]
	}
	return ""
}
