package builder

import (
	_ "embed"
	"fmt"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

//go:embed templates/almalinux.sh
var almaTemplate string

// TargetTypeAlma identifies the AlmaLinux target.
const TargetTypeAlma Type = "almalinux"

func init() {
	BuilderByTarget[TargetTypeAlma] = &alma{}
}

type almaTemplateData struct {
	commonTemplateData
	KernelDownloadURL string
}

// alma is a driverkit target.
type alma struct {
}

func (c *alma) Name() string {
	return TargetTypeAlma.String()
}

func (c *alma) TemplateScript() string {
	return almaTemplate
}

func (c *alma) URLs(kr kernelrelease.KernelRelease) ([]string, error) {
	return fetchAlmaKernelURLS(kr), nil
}

func (c *alma) TemplateData(cfg Config, kr kernelrelease.KernelRelease, urls []string) interface{} {
	return almaTemplateData{
		commonTemplateData: cfg.toTemplateData(c, kr),
		KernelDownloadURL:  urls[0],
	}
}

func fetchAlmaKernelURLS(kr kernelrelease.KernelRelease) []string {
	almaReleases := []string{
		"8",
		"8.6",
		"9",
		"9.0",
	}

	urls := []string{}
	for _, r := range almaReleases {
		if r >= "9" {
			urls = append(urls, fmt.Sprintf(
				"https://repo.almalinux.org/almalinux/%s/AppStream/%s/os/Packages/kernel-devel-%s%s.rpm",
				r,
				kr.Architecture.ToNonDeb(),
				kr.Fullversion,
				kr.FullExtraversion,
			))
		} else {
			urls = append(urls, fmt.Sprintf(
				"https://repo.almalinux.org/almalinux/%s/BaseOS/%s/os/Packages/kernel-devel-%s%s.rpm",
				r,
				kr.Architecture.ToNonDeb(),
				kr.Fullversion,
				kr.FullExtraversion,
			))
		}
	}
	return urls
}
