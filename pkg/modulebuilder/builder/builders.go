package builder

import (
	"fmt"
)

const KernelDirectory = "/tmp/kernel"
const ModuleDirectory = "/tmp/module"

type BuildType string

const (
	BuildTypeVanilla BuildType = "vanilla"
	// BuildTypeCentOS BuildType = "centos" // not implemented
	// BuildTypeCoreOS BuildType = "coreos" // Not implemented
	// BuildTypeFedora BuildType = "fedora"  // Not implemented
	// BuildTypeUbuntu BuildType = "ubuntu"  // Not implemented
	// BuildTypeDebian BuildType = "debian"  // Not implemented
)

type BuilderConfig struct {
	ModuleConfig     ModuleConfig
	KernelConfigData string
	KernelVersion    string
}

type ModuleConfig struct {
	ModuleVersion   string
	ModuleName      string
	DeviceName      string
	DownloadBaseURL string
}

type Builder interface {
	Script(bc BuilderConfig) (string, error)
}

func Factory(buildType BuildType) (Builder, error) {
	switch buildType {
	case BuildTypeVanilla:
		return &Vanilla{}, nil
	}
	return nil, fmt.Errorf("build type not found: %s", buildType)
}
