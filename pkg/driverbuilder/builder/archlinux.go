package builder

import (
	_ "embed"
	"fmt"
	"strings"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

//go:embed templates/archlinux.sh
var archlinuxTemplate string

// TargetTypeArchlinux identifies the Archlinux target.
const TargetTypeArchlinux Type = "arch"

func init() {
	BuilderByTarget[TargetTypeArchlinux] = &archlinux{}
}

// archlinux is a driverkit target.
type archlinux struct {
}

type archlinuxTemplateData struct {
	commonTemplateData
	KernelDownloadURL string
}

func (c *archlinux) Name() string {
	return TargetTypeArchlinux.String()
}

func (c *archlinux) TemplateScript() string {
	return archlinuxTemplate
}

func (c *archlinux) URLs(cfg Config, kr kernelrelease.KernelRelease) ([]string, error) {
	urls := []string{}

	if kr.Architecture == kernelrelease.ArchitectureAmd64 {
		// Archlinux officially support 4 kernel versions: stable, lts, hardened and zen
		// see: https://wiki.archlinux.org/title/Kernel#Officially_supported_kernels
		var archKernelVersion string
		var customVersion string
		var baseurl string
		switch {
		case strings.Contains(kr.Extraversion, "-lts"):
			archKernelVersion = "-lts"
			customVersion = strings.ReplaceAll(kr.Extraversion, archKernelVersion, "")
			baseurl = fmt.Sprintf("https://archive.archlinux.org/packages/l/linux%s-headers/linux%s-headers-%s-%s-%s.pkg.tar",
				archKernelVersion,
				archKernelVersion,
				kr.Fullversion,
				customVersion,
				kr.Architecture.ToNonDeb())
		case strings.Contains(kr.Extraversion, "-hardened"):
			archKernelVersion = "-hardened"
			customVersion = strings.ReplaceAll(kr.Extraversion, archKernelVersion, "")
			baseurl = fmt.Sprintf("https://archive.archlinux.org/packages/l/linux%s-headers/linux%s-headers-%s.%s-%s.pkg.tar",
				archKernelVersion,
				archKernelVersion,
				kr.Fullversion,
				customVersion,
				kr.Architecture.ToNonDeb())
		case strings.Contains(kr.Extraversion, "-zen"):
			archKernelVersion = "-zen"
			customVersion = strings.ReplaceAll(kr.Extraversion, archKernelVersion, "")
			baseurl = fmt.Sprintf("https://archive.archlinux.org/packages/l/linux%s-headers/linux%s-headers-%s.%s-%s.pkg.tar",
				archKernelVersion,
				archKernelVersion,
				kr.Fullversion,
				customVersion,
				kr.Architecture.ToNonDeb())
		default:
			baseurl = fmt.Sprintf("https://archive.archlinux.org/packages/l/linux-headers/linux-headers-%s.%s-%s.pkg.tar",
				kr.Fullversion,
				kr.Extraversion,
				kr.Architecture.ToNonDeb())
		}
		urls = append(urls, fmt.Sprintf("%s%s", baseurl, ".xz"))
		urls = append(urls, fmt.Sprintf("%s%s", baseurl, ".zst"))
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

func (c *archlinux) TemplateData(cfg Config, kr kernelrelease.KernelRelease, urls []string) interface{} {
	return archlinuxTemplateData{
		commonTemplateData: cfg.toTemplateData(c, kr),
		KernelDownloadURL:  urls[0],
	}
}
