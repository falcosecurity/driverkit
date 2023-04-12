package builder

import (
	"fmt"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"strings"
)

// Build contains the info about the on-going build.
type Build struct {
	TargetType       Type
	KernelConfigData string
	KernelRelease    string
	KernelVersion    string
	DriverVersion    string
	Architecture     string
	ModuleFilePath   string
	ProbeFilePath    string
	ModuleDriverName string
	ModuleDeviceName string
	BuilderImage     string
	BuilderRepos     []string
	ImagesListers    []ImagesLister
	KernelUrls       []string
	GCCVersion       string
	RepoOrg          string
	RepoName         string
	Images           ImagesMap
}

func (b *Build) KernelReleaseFromBuildConfig() kernelrelease.KernelRelease {
	kv := kernelrelease.FromString(b.KernelRelease)
	kv.Architecture = kernelrelease.Architecture(b.Architecture)
	return kv
}

func (b *Build) toGithubRepoArchive() string {
	return fmt.Sprintf("https://github.com/%s/%s/archive", b.RepoOrg, b.RepoName)
}

func (b *Build) ToConfig() Config {
	return Config{
		DriverName:      b.ModuleDriverName,
		DeviceName:      b.ModuleDeviceName,
		DownloadBaseURL: b.toGithubRepoArchive(),
		Build:           b,
	}
}

// hasCustomBuilderImage return true if a custom builder image has been set by the user.
func (b *Build) hasCustomBuilderImage() bool {
	if len(b.BuilderImage) > 0 {
		customNames := strings.Split(b.BuilderImage, ":")
		return customNames[0] != "auto"
	}

	return false
}

// builderImageTag returns the tag(latest, master or hash) to be used for the builder image.
func (b *Build) builderImageTag() string {
	if len(b.BuilderImage) > 0 {
		customNames := strings.Split(b.BuilderImage, ":")
		// Updated image tag if "auto:tag" is passed
		if len(customNames) > 1 {
			return customNames[1]
		}
	}

	return "latest"
}
