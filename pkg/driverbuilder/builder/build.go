package builder

import "github.com/falcosecurity/driverkit/pkg/kernelrelease"

// Build contains the info about the on-going build.
type Build struct {
	TargetType         Type
	KernelConfigData   string
	KernelRelease      string
	KernelVersion      uint16
	DriverVersion      string
	Architecture       string
	ModuleFilePath     string
	ProbeFilePath      string
	ModuleDriverName   string
	ModuleDeviceName   string
	CustomBuilderImage string
	KernelUrls         []string
}

func (b *Build) KernelReleaseFromBuildConfig() kernelrelease.KernelRelease {
	kv := kernelrelease.FromString(b.KernelRelease)
	kv.Architecture = kernelrelease.Architecture(b.Architecture)
	return kv
}
