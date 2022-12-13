package builder

import (
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

// TargetTypeBottlerocket identifies the Bottlerocket target.
const TargetTypeBottlerocket Type = "bottlerocket"

func init() {
	BuilderByTarget[TargetTypeBottlerocket] = &bottlerocket{
		vanilla{},
	}
}

type bottlerocket struct {
	vanilla
}

func (b *bottlerocket) Name() string {
	return TargetTypeBottlerocket.String()
}

func (b *bottlerocket) TemplateData(c Config, kr kernelrelease.KernelRelease, urls []string) interface{} {
	return vanillaTemplateData{
		commonTemplateData: c.toTemplateData(b, kr),
		KernelDownloadURL:  urls[0],
		KernelLocalVersion: kr.FullExtraversion,
	}
}
