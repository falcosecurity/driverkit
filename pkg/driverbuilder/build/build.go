package build

import (
	"github.com/falcosecurity/driverkit/pkg/driverbuilder/buildtype"
)

// Build contains the info about the on-going build.
type Build struct {
	BuildType        buildtype.BuildType
	KernelConfigData string
	KernelRelease    string
	KernelVersion    uint16
	DriverVersion    string
	Architecture     string
	ModuleFilePath   string
	ProbeFilePath    string
}