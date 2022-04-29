package kernelrelease

import (
	"regexp"
	"strings"
)

var (
	kernelVersionPattern = regexp.MustCompile(`(?P<fullversion>^(?P<version>0|[1-9]\d*)\.(?P<patchlevel>0|[1-9]\d*)\.(?P<sublevel>0|[1-9]\d*))(?P<fullextraversion>-(?P<extraversion>0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(\.(0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-_]*))*)?(\+[0-9a-zA-Z-]+(\.[0-9a-zA-Z-]+)*)?$`)
)

type Architecture string

func (a Architecture) ToDeb() string {
	switch a {
	case "aarch64":
		return "arm64"
	default:
		return "amd64"
	}
}

func (a Architecture) String() string {
	return string(a)
}

// KernelRelease contains all the version parts.
// NOTE: we cannot fetch Architecture from kernel string
// because it is not always provided.
// Instead, rely on the global option
// (it it set for builders in kernelReleaseFromBuildConfig())
type KernelRelease struct {
	Fullversion      string       `json:"full_version"`
	Version          string       `json:"version"`
	PatchLevel       string       `json:"patch_level"`
	Sublevel         string       `json:"sublevel"`
	Extraversion     string       `json:"extra_version"`
	FullExtraversion string       `json:"full_extra_version"`
	Architecture     Architecture `json:"architecture"`
}

// IsGKE tells whether the current kernel release is for GKE by looking at its name.
func (kr *KernelRelease) IsGKE() bool {
	return strings.HasSuffix(kr.Extraversion, "gke")
}

// FromString extracts a KernelRelease object from string.
func FromString(kernelVersionStr string) KernelRelease {
	kv := KernelRelease{}
	match := kernelVersionPattern.FindStringSubmatch(kernelVersionStr)
	identifiers := make(map[string]string)
	for i, name := range kernelVersionPattern.SubexpNames() {
		if i > 0 && i <= len(match) {
			identifiers[name] = match[i]
			switch name {
			case "fullversion":
				kv.Fullversion = match[i]
			case "version":
				kv.Version = match[i]
			case "patchlevel":
				kv.PatchLevel = match[i]
			case "sublevel":
				kv.Sublevel = match[i]
			case "extraversion":
				kv.Extraversion = match[i]
			case "fullextraversion":
				kv.FullExtraversion = match[i]
			}
		}
	}

	return kv
}
