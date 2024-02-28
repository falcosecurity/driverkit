package builder

import (
	_ "embed"
	"fmt"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"path/filepath"
)

// NOTE: since this is only used by local build,
// it is not exposed in `target` array,
// so no init() function to register it is present.

//go:embed templates/local.sh
var localTemplate string

type LocalBuilder struct {
	GccPath string
	UseDKMS bool
	SrcDir  string
}

func (l *LocalBuilder) Name() string {
	return "local"
}

func (l *LocalBuilder) TemplateScript() string {
	return localTemplate
}

func (l *LocalBuilder) URLs(_ kernelrelease.KernelRelease) ([]string, error) {
	return nil, nil
}

func (l *LocalBuilder) MinimumURLs() int {
	// We don't need any url
	return 0
}

type localTemplateData struct {
	commonTemplateData
	UseDKMS       bool
	DownloadSrc   bool
	DriverVersion string
	KernelRelease string
}

func (l *LocalBuilder) TemplateData(c Config, kr kernelrelease.KernelRelease, _ []string) interface{} {
	return localTemplateData{
		commonTemplateData: commonTemplateData{
			DriverBuildDir:    l.GetDriverBuildDir(),
			ModuleDownloadURL: fmt.Sprintf("%s/%s.tar.gz", c.DownloadBaseURL, c.DriverVersion),
			ModuleDriverName:  c.DriverName,
			ModuleFullPath:    l.GetModuleFullPath(c, kr),
			BuildModule:       len(c.ModuleFilePath) > 0,
			BuildProbe:        len(c.ProbeFilePath) > 0,
			GCCVersion:        l.GccPath,
			CmakeCmd: fmt.Sprintf(cmakeCmdFmt,
				c.DriverName,
				c.DriverName,
				c.DriverVersion,
				c.DriverVersion,
				c.DriverVersion,
				c.DeviceName,
				c.DeviceName,
				c.DriverVersion),
		},
		UseDKMS:       l.UseDKMS,
		DownloadSrc:   len(l.SrcDir) == 0, // if no srcdir is provided, download src!
		DriverVersion: c.DriverVersion,
		KernelRelease: c.KernelRelease,
	}
}

func (l *LocalBuilder) GetModuleFullPath(c Config, kr kernelrelease.KernelRelease) string {
	if l.UseDKMS {
		// When using dkms, we will use a GLOB to match the pattern; ModuleFullPath won't be used in the templated script anyway.
		return fmt.Sprintf("/var/lib/dkms/%s/%s/%s/%s/module/%s.*", c.DriverName, c.DriverVersion, kr.String(), kr.Architecture.ToNonDeb(), c.DriverName)
	}
	if l.SrcDir != "" {
		return filepath.Join(l.SrcDir, fmt.Sprintf("%s.ko", c.DriverName))
	}
	return c.ToDriverFullPath()
}

func (l *LocalBuilder) GetProbeFullPath(c Config) string {
	if l.SrcDir != "" {
		return filepath.Join(l.SrcDir, "bpf", "probe.o")
	}
	return c.ToProbeFullPath()
}

func (l *LocalBuilder) GetDriverBuildDir() string {
	driverBuildDir := DriverDirectory
	if l.SrcDir != "" {
		driverBuildDir = l.SrcDir
	}
	return driverBuildDir
}
