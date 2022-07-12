package builder

import (
	_ "embed"
	"fmt"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

//go:embed templates/archlinux.sh
var archlinuxTemplate string

// TargetTypeArchlinux identifies the Archlinux target.
const TargetTypeArchlinux Type = "archlinux"

func init() {
	BuilderByTarget[TargetTypeArchlinux] = &archlinux{}
}

// archlinux is a driverkit target.
type archlinux struct {
}

type archlinuxTemplateData struct {
	commonTemplateData
	KernelDownloadURL string
	GCCVersion        string
}

func (c archlinux) Name() string {
	return TargetTypeArchlinux.String()
}

func (c archlinux) TemplateScript() string {
	return archlinuxTemplate
}

func (c archlinux) URLs(cfg Config, kr kernelrelease.KernelRelease) ([]string, error) {
	urls := []string{}

	if kr.Architecture == "amd64" {
		urls = append(urls, fmt.Sprintf(
			"https://archive.archlinux.org/packages/l/linux-headers/linux-headers-%s.%s-%s-%s.pkg.tar.xz",
			kr.Fullversion,
			kr.Extraversion,
			cfg.KernelVersion,
			kr.Architecture.ToNonDeb()))
	} else {
		urls = append(urls, fmt.Sprintf(
			"http://tardis.tiny-vps.com/aarm/packages/l/linux-%s-headers/linux-%s-headers-%s-%s-%s.pkg.tar.xz",
			kr.Architecture.ToNonDeb(),
			kr.Architecture.ToNonDeb(),
			kr.Fullversion,
			cfg.KernelVersion,
			kr.Architecture.ToNonDeb()))
	}
	return urls, nil
}

func (c archlinux) TemplateData(cfg Config, kr kernelrelease.KernelRelease, urls []string) interface{} {
	return archlinuxTemplateData{
		commonTemplateData: cfg.toTemplateData(),
		KernelDownloadURL:  urls[0],
		GCCVersion:         archlinuxGccVersionFromKernelRelease(kr),
	}
}

func archlinuxGccVersionFromKernelRelease(kr kernelrelease.KernelRelease) string {
	switch kr.Version {
	case 3:
		return "5"
	case 2:
		return "4.8"
	}
	return "8"
}
