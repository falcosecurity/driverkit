package builder

import (
	"fmt"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

// Build contains the info about the on-going build.
type Build struct {
	TargetType         Type
	KernelConfigData   string
	KernelRelease      string
	KernelVersion      string
	DriverVersion      string
	Architecture       string
	ModuleFilePath     string
	ProbeFilePath      string
	ModuleDriverName   string
	ModuleDeviceName   string
	CustomBuilderImage string
	KernelUrls         []string
	GCCVersion         float64
	RepoOrg            string
	RepoName           string
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
