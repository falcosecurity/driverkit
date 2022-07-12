package builder

import (
	_ "embed"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
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
	commonTemplateData
	KernelPackage string
}

func (v redhat) Name() string {
	return TargetTypeRedhat.String()
}

func (v redhat) TemplateScript() string {
	return redhatTemplate
}

func (v redhat) URLs(_ Config, _ kernelrelease.KernelRelease) ([]string, error) {
	return nil, nil
}

func (v redhat) TemplateData(c Config, kr kernelrelease.KernelRelease, _ []string) interface{} {
	return redhatTemplateData{
		commonTemplateData: c.toTemplateData(),
		KernelPackage:      kr.Fullversion + kr.FullExtraversion,
	}
}
