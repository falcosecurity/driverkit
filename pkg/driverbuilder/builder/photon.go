package builder

import (
	_ "embed"
	"fmt"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

// TargetTypePhoton identifies the Photon target.
const TargetTypePhoton Type = "photon"

//go:embed templates/photonos.sh
var photonTemplate string

func init() {
	BuilderByTarget[TargetTypePhoton] = &photon{}
}

// photon is a driverkit target.
type photon struct {
}

type photonTemplateData struct {
	commonTemplateData
	KernelDownloadURL string
}

func (p *photon) Name() string {
	return TargetTypePhoton.String()
}

func (p *photon) TemplateScript() string {
	return photonTemplate
}

func (p *photon) URLs(kr kernelrelease.KernelRelease) ([]string, error) {
	return fetchPhotonKernelURLS(kr), nil
}

func (p *photon) TemplateData(cfg Config, kr kernelrelease.KernelRelease, urls []string) interface{} {
	return photonTemplateData{
		commonTemplateData: cfg.toTemplateData(p, kr),
		KernelDownloadURL:  urls[0],
	}
}

func fetchPhotonKernelURLS(kr kernelrelease.KernelRelease) []string {
	photonReleases := []string{
		"3.0",
		"4.0",
	}

	urls := []string{}
	for _, r := range photonReleases {
		switch r {
		case "3.0":
			urls = append(urls, fmt.Sprintf(
				"https://packages.vmware.com/photon/%s/photon_updates_%s_x86_64/x86_64/linux-devel-%s%s.x86_64.rpm",
				r,
				r,
				kr.Fullversion,
				kr.FullExtraversion,
			))
			urls = append(urls, fmt.Sprintf(
				"https://packages.vmware.com/photon/%s/photon_release_%s_x86_64/x86_64/linux-devel-%s%s.x86_64.rpm",
				r,
				r,
				kr.Fullversion,
				kr.FullExtraversion,
			))

		case "4.0":
			urls = append(urls, fmt.Sprintf(
				"https://packages.vmware.com/photon/%s/photon_%s_x86_64/x86_64/linux-devel-%s%s.x86_64.rpm",
				r,
				r,
				kr.Fullversion,
				kr.FullExtraversion,
			))
			urls = append(urls, fmt.Sprintf(
				"https://packages.vmware.com/photon/%s/photon_release_%s_x86_64/x86_64/linux-devel-%s%s.x86_64.rpm",
				r,
				r,
				kr.Fullversion,
				kr.FullExtraversion,
			))
		}
	}
	return urls
}
