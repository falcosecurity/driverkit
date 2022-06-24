package builder

import (
	"bytes"
	_ "embed"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"text/template"
)

//go:embed templates/redhat.sh
var redhatTemplate string

// TargetTypeRedhat identifies the redhat target.
const TargetTypeRedhat Type = "redhat"

// redhat is a driverkit target.
type redhat struct {
}

func init() {
	BuilderByTarget[TargetTypeRedhat] = &redhat{}
}

type redhatTemplateData struct {
	DriverBuildDir    string
	KernelPackage     string
	ModuleDownloadURL string
	ModuleDriverName  string
	ModuleFullPath    string
	BuildModule       bool
	BuildProbe        bool
}

func (v redhat) Script(cfg Config, kr kernelrelease.KernelRelease) (string, error) {
	t := template.New(string(TargetTypeRedhat))
	parsed, err := t.Parse(redhatTemplate)
	if err != nil {
		return "", err
	}

	td := redhatTemplateData{
		DriverBuildDir:    DriverDirectory,
		KernelPackage:     kr.Fullversion + kr.FullExtraversion,
		ModuleDownloadURL: moduleDownloadURL(cfg),
		ModuleDriverName:  cfg.DriverName,
		ModuleFullPath:    ModuleFullPath,
		BuildModule:       len(cfg.Build.ModuleFilePath) > 0,
		BuildProbe:        len(cfg.Build.ProbeFilePath) > 0,
	}

	buf := bytes.NewBuffer(nil)
	err = parsed.Execute(buf, td)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
