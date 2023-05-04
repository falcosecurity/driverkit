package builder

import (
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

// TargetTypeTalos identifies the Talos target.
const TargetTypeTalos Type = "talos"

func init() {
	BuilderByTarget[TargetTypeTalos] = &talos{
		vanilla{},
	}
}

type talos struct {
	vanilla
}

func (b *talos) Name() string {
	return TargetTypeTalos.String()
}

func (b *talos) TemplateData(c Config, kr kernelrelease.KernelRelease, urls []string) interface{} {
	return vanillaTemplateData{
		commonTemplateData: c.toTemplateData(b, kr),
		KernelDownloadURL:  urls[0],
		KernelLocalVersion: kr.FullExtraversion,
	}
}
