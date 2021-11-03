package builder

// Build contains the info about the on-going build.
type Build struct {
	TargetType       Type
	KernelConfigData string
	KernelRelease    string
	KernelVersion    uint16
	DriverVersion    string
	Architecture     string
	ModuleFilePath   string
	ProbeFilePath    string
	ModuleDriverName string
	ModuleDeviceName string
}
