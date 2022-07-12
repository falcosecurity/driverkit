package builder

import (
	_ "embed"
	"fmt"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

//go:embed templates/rocky.sh
var rockyTemplate string

// TargetTypeRocky identifies the Rocky target.
const TargetTypeRocky Type = "rocky"

func init() {
	BuilderByTarget[TargetTypeRocky] = &rocky{}
}

type rockyTemplateData struct {
	commonTemplateData
	KernelDownloadURL string
	GCCVersion        string
}

// rocky is a driverkit target.
type rocky struct {
}

func (c rocky) Name() string {
	return TargetTypeRocky.String()
}

func (c rocky) TemplateScript() string {
	return rockyTemplate
}

func (c rocky) URLs(_ Config, kr kernelrelease.KernelRelease) ([]string, error) {
	return fetchRockyKernelURLS(kr), nil
}

func (c rocky) TemplateData(cfg Config, kr kernelrelease.KernelRelease, urls []string) interface{} {
	return rockyTemplateData{
		commonTemplateData: cfg.toTemplateData(),
		KernelDownloadURL:  urls[0],
		GCCVersion:         rockyGccVersionFromKernelRelease(kr),
	}
}

func fetchRockyKernelURLS(kr kernelrelease.KernelRelease) []string {
	rockyReleases := []string{
		"8",
		"8.5",
	}

	urls := []string{}
	for _, r := range rockyReleases {
		urls = append(urls, fmt.Sprintf(
			"https://download.rockylinux.org/pub/rocky/%s/BaseOS/%s/os/Packages/k/kernel-devel-%s%s.rpm",
			r,
			kr.Architecture.ToNonDeb(),
			kr.Fullversion,
			kr.FullExtraversion,
		))
	}
	return urls
}

func rockyGccVersionFromKernelRelease(kr kernelrelease.KernelRelease) string {
	switch kr.Version {
	case 3:
		return "5"
	case 2:
		return "4.8"
	}
	return "8"
}
