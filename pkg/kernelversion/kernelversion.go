package kernelversion

import (
	"regexp"
)

var (
	kernelVersionPattern = regexp.MustCompile(`^(?P<version>0|[1-9]\d*)\.(?P<patchlevel>0|[1-9]\d*)\.(?P<sublevel>0|[1-9]\d*)(?P<fullextraversion>-(?P<extraversion>0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(\.(0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*)?(\+[0-9a-zA-Z-]+(\.[0-9a-zA-Z-]+)*)?$`)
)

type KernelVersion struct {
	Version      string
	PatchLevel string
	Sublevel string
	Extraversion string
	FullExtraversion string
}

func FromString(kernelVersionStr string) (KernelVersion) {
	kv := KernelVersion{}
	match := kernelVersionPattern.FindStringSubmatch(kernelVersionStr)
	identifiers := make(map[string]string)
	for i, name := range kernelVersionPattern.SubexpNames() {
		if i > 0 && i <= len(match) {
			identifiers[name] = match[i]
			switch name {
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