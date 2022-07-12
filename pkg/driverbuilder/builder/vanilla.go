package builder

import (
	_ "embed"
	"fmt"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

//go:embed templates/vanilla.sh
var vanillaTemplate string

// vanilla is a driverkit target.
type vanilla struct {
}

// TargetTypeVanilla identifies the Vanilla target.
const TargetTypeVanilla Type = "vanilla"

func init() {
	BuilderByTarget[TargetTypeVanilla] = &vanilla{}
}

type vanillaTemplateData struct {
	commonTemplateData
	KernelDownloadURL  string
	KernelLocalVersion string
}

func (v vanilla) Name() string {
	return TargetTypeVanilla.String()
}

func (v vanilla) TemplateScript() string {
	return vanillaTemplate
}

func (v vanilla) URLs(_ Config, kr kernelrelease.KernelRelease) ([]string, error) {
	return []string{fetchVanillaKernelURLFromKernelVersion(kr)}, nil
}

func (v vanilla) TemplateData(c Config, kr kernelrelease.KernelRelease, urls []string) interface{} {
	return vanillaTemplateData{
		commonTemplateData: c.toTemplateData(),
		KernelDownloadURL:  urls[0],
		KernelLocalVersion: kr.FullExtraversion,
	}
}

func fetchVanillaKernelURLFromKernelVersion(kv kernelrelease.KernelRelease) string {
	return fmt.Sprintf("https://cdn.kernel.org/pub/linux/kernel/v%d.x/linux-%s.tar.xz", kv.Version, kv.Fullversion)
}
