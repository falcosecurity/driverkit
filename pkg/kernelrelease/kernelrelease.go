package kernelrelease

import (
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"

	"github.com/blang/semver"
)

var (
	kernelVersionPattern = regexp.MustCompile(`(?P<fullversion>^(?P<version>0|[1-9]\d*)\.(?P<patchlevel>0|[1-9]\d*)\.(?P<sublevel>0|[1-9]\d*))(?P<fullextraversion>[-|.](?P<extraversion>0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(\.(0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-_]*))*)?(\+[0-9a-zA-Z-]+(\.[0-9a-zA-Z-]+)*)?$`)
)

const (
	ArchitectureAmd64 = "amd64"
	ArchitectureArm64 = "arm64"
)

// Architectures is a Map [Architecture] -> non-deb-ArchitectureString
type Architectures map[Architecture]string

// SupportedArchs enforces the duality of architecture->non-deb one when adding a new one
var SupportedArchs = Architectures{
	ArchitectureAmd64: "x86_64",
	ArchitectureArm64: "aarch64",
}

// Privately cached at startup for quicker access
var supportedArchsSlice []string

// Represents the minimum kernel version for which building the module
// is supported, depending on the architecture
var moduleMinKernelVersion map[Architecture]semver.Version

// Represents the minimum kernel version for which building the probe
// is supported, depending on the architecture
var probeMinKernelVersion map[Architecture]semver.Version

func init() {
	i := 0
	supportedArchsSlice = make([]string, len(SupportedArchs))
	for k := range SupportedArchs {
		supportedArchsSlice[i] = k.String()
		i++
	}

	// see compatibility matrix: https://falco.org/docs/event-sources/drivers/
	// note: this does not make much sense for flatcar, which has a much
	// higher major version. In that case, we assume that the module/probe
	// is always supported, and eventually fail while building
	moduleMinKernelVersion = make(map[Architecture]semver.Version)
	probeMinKernelVersion = make(map[Architecture]semver.Version)
	moduleMinKernelVersion[ArchitectureAmd64] = semver.MustParse("2.6.0")
	moduleMinKernelVersion[ArchitectureArm64] = semver.MustParse("3.4.0")
	probeMinKernelVersion[ArchitectureAmd64] = semver.MustParse("4.14.0")
	probeMinKernelVersion[ArchitectureArm64] = semver.MustParse("4.17.0")
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
	Fullversion string
	semver.Version
	Extraversion     string
	FullExtraversion string
	Architecture     Architecture
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
				kv.Major, err = strconv.ParseUint(match[i], 10, 64)
			case "patchlevel":
				kv.Minor, err = strconv.ParseUint(match[i], 10, 64)
			case "sublevel":
				kv.Patch, err = strconv.ParseUint(match[i], 10, 64)
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

func (k *KernelRelease) SupportsModule() bool {
	return k.Compare(moduleMinKernelVersion[k.Architecture]) >= 0
}

func (k *KernelRelease) SupportsProbe() bool {
	return k.Compare(probeMinKernelVersion[k.Architecture]) >= 0
}
