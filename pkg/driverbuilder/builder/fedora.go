package builder

import (
	_ "embed"
	"fmt"
	"strings"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

//go:embed templates/fedora.sh
var fedoraTemplate string

// TargetTypeFedora identifies the Fedora target.
const TargetTypeFedora Type = "fedora"

func init() {
	BuilderByTarget[TargetTypeFedora] = &fedora{}
}

// fedora is a driverkit target.
type fedora struct {
}

type fedoraTemplateData struct {
	commonTemplateData
	KernelDownloadURL string
}

func (c *fedora) Name() string {
	return TargetTypeFedora.String()
}

func (c *fedora) TemplateScript() string {
	return fedoraTemplate
}

func (c *fedora) URLs(_ Config, kr kernelrelease.KernelRelease) ([]string, error) {

	// fedora FullExtraversion looks like "-200.fc36.x86_64"
	// need to get the "fc36" out of the middle
	fedoraVersion := strings.Split(kr.FullExtraversion, ".")[1]

	// trim off the "fc" from fedoraVersion
	version := strings.Trim(fedoraVersion, "fc")

	// template the kernel info into all possible URL strings
	urls := []string{
		fmt.Sprintf( // updates
			"https://mirrors.kernel.org/fedora/updates/%s/Everything/%s/Packages/k/kernel-devel-%s%s.rpm",
			version,
			kr.Architecture.ToNonDeb(),
			kr.Fullversion,
			kr.FullExtraversion,
		),
		fmt.Sprintf( // releases
			"https://mirrors.kernel.org/fedora/releases/%s/Everything/%s/os/Packages/k/kernel-devel-%s%s.rpm",
			version,
			kr.Architecture.ToNonDeb(),
			kr.Fullversion,
			kr.FullExtraversion,
		),
	}

	// return out all possible urls
	return urls, nil
}

func (c *fedora) TemplateData(cfg Config, kr kernelrelease.KernelRelease, urls []string) interface{} {
	return fedoraTemplateData{
		commonTemplateData: cfg.toTemplateData(c, kr),
		KernelDownloadURL:  urls[0],
	}
}
