package kernelrelease

import (
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
)

var (
	kernelVersionPattern = regexp.MustCompile(`(?P<fullversion>^(?P<version>0|[1-9]\d*)\.(?P<patchlevel>0|[1-9]\d*)\.(?P<sublevel>0|[1-9]\d*))(?P<fullextraversion>-(?P<extraversion>0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(\.(0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-_]*))*)?(\+[0-9a-zA-Z-]+(\.[0-9a-zA-Z-]+)*)?$`)
)

// Architectures is a Map [Architecture] -> non-deb-ArchitectureString
type Architectures map[Architecture]string

// SupportedArchs enforces the duality of architecture->non-deb one when adding a new one
var SupportedArchs = Architectures{
	"amd64": "x86_64",
	"arm64": "aarch64",
}

// Privately cached at startup for quicker access
var supportedArchsSlice []string

func init() {
	i := 0
	supportedArchsSlice = make([]string, len(SupportedArchs))
	for k := range SupportedArchs {
		supportedArchsSlice[i] = k.String()
		i++
	}
}

func (aa Architectures) String() string {
	return "[" + strings.Join(supportedArchsSlice, ",") + "]"
}

func (aa Architectures) Strings() []string {
	return supportedArchsSlice
}

type Architecture string

func (a Architecture) ToNonDeb() string {
	if val, ok := SupportedArchs[a]; ok {
		return val
	}
	panic(fmt.Errorf("missing non-deb name for arch: %s", a.String()))
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
	Version          int          `json:"version"`
	PatchLevel       int          `json:"patch_level"`
	Sublevel         int          `json:"sublevel"`
	Extraversion     string       `json:"extra_version"`
	FullExtraversion string       `json:"full_extra_version"`
	Architecture     Architecture `json:"architecture"`
}

// FromString extracts a KernelRelease object from string.
func FromString(kernelVersionStr string) KernelRelease {
	kv := KernelRelease{}
	match := kernelVersionPattern.FindStringSubmatch(kernelVersionStr)
	identifiers := make(map[string]string)
	for i, name := range kernelVersionPattern.SubexpNames() {
		if i > 0 && i <= len(match) {
			var err error
			identifiers[name] = match[i]
			switch name {
			case "fullversion":
				kv.Fullversion = match[i]
			case "version":
				kv.Version, err = strconv.Atoi(match[i])
			case "patchlevel":
				kv.PatchLevel, err = strconv.Atoi(match[i])
			case "sublevel":
				kv.Sublevel, err = strconv.Atoi(match[i])
			case "extraversion":
				kv.Extraversion = match[i]
			case "fullextraversion":
				kv.FullExtraversion = match[i]
			}

			if err != nil {
				log.Fatal(err)
			}
		}
	}

	return kv
}
