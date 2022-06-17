package builder

import (
	"bytes"
	_ "embed"
	"fmt"
	"text/template"

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
	DriverBuildDir     string
	ModuleDownloadURL  string
	KernelDownloadURL  string
	KernelLocalVersion string
	ModuleDriverName   string
	ModuleFullPath     string
	BuildModule        bool
	BuildProbe         bool
}

// Script compiles the script to build the kernel module and/or the eBPF probe.
func (v vanilla) Script(c Config, kv kernelrelease.KernelRelease) (string, error) {
	t := template.New(string(TargetTypeVanilla))
	parsed, err := t.Parse(vanillaTemplate)
	if err != nil {
		return "", err
	}

	var urls []string
	if c.KernelUrls == nil {
		// Check (and filter) existing kernels before continuing
		urls, err = getResolvingURLs([]string{fetchVanillaKernelURLFromKernelVersion(kv)})
	} else {
		urls, err = getResolvingURLs(c.KernelUrls)
	}
	if err != nil {
		return "", err
	}

	td := vanillaTemplateData{
		DriverBuildDir:     DriverDirectory,
		ModuleDownloadURL:  moduleDownloadURL(c),
		KernelDownloadURL:  urls[0],
		KernelLocalVersion: kv.FullExtraversion,
		ModuleDriverName:   c.DriverName,
		ModuleFullPath:     ModuleFullPath,
		BuildModule:        len(c.Build.ModuleFilePath) > 0,
		BuildProbe:         len(c.Build.ProbeFilePath) > 0,
	}

	buf := bytes.NewBuffer(nil)
	err = parsed.Execute(buf, td)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func fetchVanillaKernelURLFromKernelVersion(kv kernelrelease.KernelRelease) string {
	return fmt.Sprintf("https://cdn.kernel.org/pub/linux/kernel/v%d.x/linux-%s.tar.xz", kv.Version, kv.Fullversion)
}
