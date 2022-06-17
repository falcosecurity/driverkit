package builder

import (
	"bytes"
	_ "embed"
	"fmt"
	"text/template"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

//go:embed templates/rocky.sh
var rockyTemplate string

// TargetTypeRocky identifies the Rocky target.
const TargetTypeRocky Type = "rocky"

func init() {
	BuilderByTarget[TargetTypeRocky] = &rocky{}
}

// rocky is a driverkit target.
type rocky struct {
}

// Script compiles the script to build the kernel module and/or the eBPF probe.
func (c rocky) Script(cfg Config, kr kernelrelease.KernelRelease) (string, error) {
	t := template.New(string(TargetTypeRocky))
	parsed, err := t.Parse(rockyTemplate)
	if err != nil {
		return "", err
	}

	var urls []string
	if cfg.KernelUrls == nil {
		// Check (and filter) existing kernels before continuing
		urls, err = getResolvingURLs(fetchRockyKernelURLS(kr))
	} else {
		urls, err = getResolvingURLs(cfg.KernelUrls)
	}
	if err != nil {
		return "", err
	}

	td := rockyTemplateData{
		DriverBuildDir:    DriverDirectory,
		ModuleDownloadURL: moduleDownloadURL(cfg),
		KernelDownloadURL: urls[0],
		GCCVersion:        rockyGccVersionFromKernelRelease(kr),
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

type rockyTemplateData struct {
	DriverBuildDir    string
	ModuleDownloadURL string
	KernelDownloadURL string
	GCCVersion        string
	ModuleDriverName  string
	ModuleFullPath    string
	BuildModule       bool
	BuildProbe        bool
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
