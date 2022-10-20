package builder

import (
	"github.com/blang/semver"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

// TargetTypeMinikube identifies the Minikube target.
const TargetTypeMinikube Type = "minikube"

func init() {
	BuilderByTarget[TargetTypeMinikube] = &minikube{
		vanilla{},
	}
}

type minikube struct {
	vanilla
}

func (m *minikube) Name() string {
	return TargetTypeMinikube.String()
}

func (m *minikube) TemplateData(c Config, kr kernelrelease.KernelRelease, urls []string) interface{} {
	return vanillaTemplateData{
		commonTemplateData: c.toTemplateData(m, kr),
		KernelDownloadURL:  urls[0],
		KernelLocalVersion: kr.FullExtraversion,
	}
}

func (m *minikube) GCCVersion(kr kernelrelease.KernelRelease) semver.Version {
	// The supported versions of minikube use kernels > 4.19.
	switch kr.Major {
	case 5:
		return semver.Version{Major: 10}
	case 4:
		return semver.Version{Major: 8}
	default:
		return semver.Version{Major: 12}
	}
}
