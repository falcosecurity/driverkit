package builder

import (
	_ "embed"
	"fmt"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

//go:embed templates/alinux.sh
var alinuxTemplate string

// TargetTypeAlinux identifies the AliyunLinux 2 and 3 target.
const TargetTypeAlinux Type = "alinux"



func init() {
	BuilderByTarget[TargetTypeAlinux] = &alinux{}
}

type alinuxTemplateData struct {
	commonTemplateData
	KernelDownloadURL string
}

type alinux struct {
}

func (c *alinux) Name() string {
	return TargetTypeAlinux.String()
}

func (c *alinux) TemplateScript() string {
	return alinuxTemplate
}

func (c *alinux) URLs(_ Config, kr kernelrelease.KernelRelease) ([]string, error) {
	return fetchAlinuxKernelURLS(kr), nil
}

func (c *alinux) TemplateData(cfg Config, kr kernelrelease.KernelRelease, urls []string) interface{} {
	return alinuxTemplateData{
		commonTemplateData: cfg.toTemplateData(c, kr),
		KernelDownloadURL:  urls[0],
	}
}

func fetchAlinuxKernelURLS(kr kernelrelease.KernelRelease) []string {
	alinuxReleases := []string{
		"2",
		"2.1903",
		"3",
	}

	urls := []string{}
	for _, r := range alinuxReleases {
		urls = append(urls, fmt.Sprintf(
			"http://mirrors.aliyun.com/alinux/%s/os/%s/Packages/kernel-devel-%s%s.rpm",
			r,
			kr.Architecture.ToNonDeb(),
			kr.Fullversion,
			kr.FullExtraversion,
		))
	}
	return urls
}
