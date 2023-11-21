package builder

import (
	_ "embed"
	"fmt"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

// NOTE: since this is only used by local build,
// it is not exposed in `target` array,
// so no init() function to register it is present.

//go:embed templates/local.sh
var localTemplate string

type LocalBuilder struct {
	GccPath string
}

func (l *LocalBuilder) Name() string {
	return "local"
}

func (l *LocalBuilder) TemplateScript() string {
	return localTemplate
}

func (l *LocalBuilder) URLs(kr kernelrelease.KernelRelease) ([]string, error) {
	return nil, nil
}

func (l *LocalBuilder) MinimumURLs() int {
	// We don't need any url
	return 0
}

type localTemplateData struct {
	commonTemplateData
}

func (l *LocalBuilder) TemplateData(c Config, _ kernelrelease.KernelRelease, _ []string) interface{} {
	return localTemplateData{
		commonTemplateData: commonTemplateData{
			DriverBuildDir:    DriverDirectory,
			ModuleDownloadURL: fmt.Sprintf("%s/%s.tar.gz", c.DownloadBaseURL, c.DriverVersion),
			ModuleDriverName:  c.DriverName,
			ModuleFullPath:    ModuleFullPath,
			BuildModule:       len(c.ModuleFilePath) > 0,
			BuildProbe:        len(c.ProbeFilePath) > 0,
			GCCVersion:        l.GccPath,
		},
	}
}
