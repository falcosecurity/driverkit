package builder

import (
	_ "embed"
	"fmt"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

//go:embed templates/aliyunlinux.sh
var aliyunlinuxTemplate string

// TargetTypeAlma identifies the AliyunLinux2 target.
const TargetTypeAliyunLinux2 Type = "aliyunlinux2"

// TargetTypeAlma identifies the AliyunLinux3 target.
const TargetTypeAliyunLinux3 Type = "aliyunlinux3"

func init() {
	BuilderByTarget[TargetTypeAliyunLinux2] = &aliyunlinux2{}
	BuilderByTarget[TargetTypeAliyunLinux3] = &aliyunlinux3{}
}

type aliyunlinuxTemplateData struct {
	commonTemplateData
	KernelDownloadURL string
}

type aliyunlinux2 struct {
	aliyunlinux2
}

type aliyunlinux3 struct {
	aliyunlinux3
}

func (c *aliyunlinux2) Name() string {
	return TargetTypeAliyunLinux2.String()
}

func (c *aliyunlinux2) TemplateScript() string {
	return aliyunlinuxTemplate
}

func (c *aliyunlinux2) URLs(_ Config, kr kernelrelease.KernelRelease) ([]string, error) {
	return fetchAliyunLinux2KernelURLS(kr), nil
}

func (c *aliyunlinux2) TemplateData(cfg Config, kr kernelrelease.KernelRelease, urls []string) interface{} {
	return aliyunlinux2TemplateData{
		commonTemplateData: cfg.toTemplateData(c, kr),
		KernelDownloadURL:  urls[0],
	}
}

func fetchAliyunLinux2KernelURLS(kr kernelrelease.KernelRelease) []string {
	aliyunlinux2Releases := []string{
		"2",
		"2.1903",
	}

	urls := []string{}
	for _, r := range aliyunlinux2Releases {
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

func (c *aliyunlinux3) Name() string {
	return TargetTypeAliyunLinux3.String()
}

func (c *aliyunlinux3) TemplateScript() string {
	return aliyunlinuxTemplate
}

func (c *aliyunlinux3) URLs(_ Config, kr kernelrelease.KernelRelease) ([]string, error) {
	return fetchAliyunLinux3KernelURLS(kr), nil
}

func (c *aliyunlinux3) TemplateData(cfg Config, kr kernelrelease.KernelRelease, urls []string) interface{} {
	return aliyunlinux3TemplateData{
		commonTemplateData: cfg.toTemplateData(c, kr),
		KernelDownloadURL:  urls[0],
	}
}

func fetchAliyunLinux3KernelURLS(kr kernelrelease.KernelRelease) []string {
	aliyunlinux3Releases := []string{
		"3",
	}

	urls := []string{}
	for _, r := range aliyunlinux3Releases {
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
