package builder

import (
	"bytes"
	"fmt"
	"text/template"
)

type Vanilla struct {
}

const BuildTypeVanilla BuildType = "vanilla"

func init() {
	EnabledBuildTypes[BuildTypeVanilla] = true
}

const vanillaTemplate = `
#!/bin/bash
set -euo pipefail

rm -Rf {{ .ModuleBuildDir }}
mkdir {{ .ModuleBuildDir }}
rm -Rf /tmp/module-download
mkdir -p /tmp/module-download

curl -SL {{ .ModuleDownloadURL }} | tar -xzf - -C /tmp/module-download
mv /tmp/module-download/*/driver/* {{ .ModuleBuildDir }}

cp /module-builder/module-Makefile {{ .ModuleBuildDir }}/Makefile
cp /module-builder/module-driver-config.h {{ .ModuleBuildDir }}/driver_config.h

# Fetch the kernel
cd /tmp
mkdir /tmp/kernel-download
curl -SL {{ .KernelDownloadURL }} | tar -Jxf - -C /tmp/kernel-download
rm -Rf {{ .KernelBuildDir }}
mkdir -p {{ .KernelBuildDir }}
mv /tmp/kernel-download/*/* {{ .KernelBuildDir }}

# Prepare the kernel

cd {{ .KernelBuildDir }}
cp /module-builder/kernel.config /tmp/kernel.config
make KCONFIG_CONFIG=/tmp/kernel.config oldconfig
make KCONFIG_CONFIG=/tmp/kernel.config prepare
make KCONFIG_CONFIG=/tmp/kernel.config modules_prepare

# Build the module
cd {{ .ModuleBuildDir }}
make
# print results
ls -la
`

type vanillaTemplateData struct {
	KernelBuildDir    string
	ModuleBuildDir    string
	ModuleDownloadURL string
	KernelDownloadURL string
}

func (v Vanilla) Script(bc BuilderConfig) (string, error) {
	t := template.New("vanilla")
	parsed, err := t.Parse(vanillaTemplate)
	if err != nil {
		return "", err
	}

	td := vanillaTemplateData{
		KernelBuildDir:    KernelDirectory,
		ModuleBuildDir:    ModuleDirectory,
		ModuleDownloadURL: fmt.Sprintf("%s/%s.tar.gz", bc.ModuleConfig.DownloadBaseURL, bc.ModuleConfig.ModuleVersion),
		KernelDownloadURL: fetchVanillaKernelURLFromKernelVersion(bc.KernelVersion),
	}

	buf := bytes.NewBuffer(nil)
	err = parsed.Execute(buf, td)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func fetchVanillaKernelURLFromKernelVersion(kernelVersion string) string {
	// TODO: change base url 5.x based on kernel version
	return fmt.Sprintf("https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-%s.tar.xz", kernelVersion)
}
