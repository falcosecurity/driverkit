package builder

import (
	"bytes"
	_ "embed"
	"fmt"
	"text/template"

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

// Script compiles the script to build the kernel module and/or the eBPF probe.
func (c archlinux) Script(cfg Config, kr kernelrelease.KernelRelease) (string, error) {
	t := template.New(string(TargetTypeArchlinux))
	parsed, err := t.Parse(archlinuxTemplate)
	if err != nil {
		return "", err
	}

	var urls []string
	if cfg.KernelUrls == nil {
		// Check (and filter) existing kernels before continuing
		urls, err = getResolvingURLs(fetchArchlinuxKernelURLS(kr, cfg.KernelVersion))
	} else {
		urls, err = getResolvingURLs(cfg.KernelUrls)
	}
	if err != nil {
		return "", err
	}

	td := archlinuxTemplateData{
		DriverBuildDir:    DriverDirectory,
		ModuleDownloadURL: moduleDownloadURL(cfg),
		KernelDownloadURL: urls[0],
		GCCVersion:        archlinuxGccVersionFromKernelRelease(kr),
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

func fetchArchlinuxKernelURLS(kr kernelrelease.KernelRelease, kv uint16) []string {
	urls := []string{}

	if kr.Architecture == "amd64" {
		urls = append(urls, fmt.Sprintf(
			"https://archive.archlinux.org/packages/l/linux-headers/linux-headers-%s.%s-%d-%s.pkg.tar.xz",
			kr.Fullversion,
			kr.Extraversion,
			kv,
			kr.Architecture.ToNonDeb()))
	} else {
		urls = append(urls, fmt.Sprintf(
			"http://tardis.tiny-vps.com/aarm/packages/l/linux-%s-headers/linux-%s-headers-%s-%d-%s.pkg.tar.xz",
			kr.Architecture.ToNonDeb(),
			kr.Architecture.ToNonDeb(),
			kr.Fullversion,
			kv,
			kr.Architecture.ToNonDeb()))
	}
	return urls
}

type archlinuxTemplateData struct {
	DriverBuildDir    string
	ModuleDownloadURL string
	KernelDownloadURL string
	GCCVersion        string
	ModuleDriverName  string
	ModuleFullPath    string
	BuildModule       bool
	BuildProbe        bool
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
