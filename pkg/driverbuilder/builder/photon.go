package builder

import (
	"bytes"
	_ "embed"
	"fmt"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"text/template"
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

// Script compiles the script to build the kernel module and/or the eBPF probe.
func (c photon) Script(cfg Config, kr kernelrelease.KernelRelease) (string, error) {
	t := template.New(string(TargetTypePhoton))
	parsed, err := t.Parse(photonTemplate)
	if err != nil {
		return "", err
	}
	
	// Check (and filter) existing kernels before continuing
	urls, err := getResolvingURLs(fetchPhotonKernelURLS(kr))
	if err != nil {
		return "", err
	}

	td := photonTemplateData{
		DriverBuildDir:    DriverDirectory,
		ModuleDownloadURL: moduleDownloadURL(cfg),
		KernelDownloadURL: urls[0],
		GCCVersion:        photonGccVersionFromKernelRelease(kr),
		ModuleDriverName:  cfg.DriverName,
		ModuleFullPath:    ModuleFullPath,
		BuildModule:       len(cfg.Build.ModuleFilePath) > 0,
		BuildProbe:        len(cfg.Build.ProbeFilePath) > 0,
	}

	buf := bytes.NewBuffer(nil)
	err = parsed.Execute(buf, td)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
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

type photonTemplateData struct {
	DriverBuildDir    string
	ModuleDownloadURL string
	KernelDownloadURL string
	GCCVersion        string
	ModuleDriverName  string
	ModuleFullPath    string
	BuildModule       bool
	BuildProbe        bool
}

func photonGccVersionFromKernelRelease(kr kernelrelease.KernelRelease) string {
	switch kr.Version {
	default:
		return "8"
	}
}
