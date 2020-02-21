package builder

import (
	"bytes"
	"fmt"
	"github.com/falcosecurity/build-service/pkg/modulebuilder/buildtype"
	"text/template"

	"github.com/falcosecurity/build-service/pkg/kernelrelease"
)

type Vanilla struct {
}

const BuildTypeVanilla buildtype.BuildType = "vanilla"

func init() {
	buildtype.EnabledBuildTypes[BuildTypeVanilla] = true
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

{{ if .KernelLocalVersion}}
sed -i 's/^CONFIG_LOCALVERSION=.*$/CONFIG_LOCALVERSION="{{ .KernelLocalVersion }}"/' /tmp/kernel.config
{{ end }}

make KCONFIG_CONFIG=/tmp/kernel.config oldconfig
make KCONFIG_CONFIG=/tmp/kernel.config prepare
make KCONFIG_CONFIG=/tmp/kernel.config modules_prepare

# Build the module
cd {{ .ModuleBuildDir }}
make
# print results
ls -la

modinfo falco.ko
`

type vanillaTemplateData struct {
	KernelBuildDir     string
	ModuleBuildDir     string
	ModuleDownloadURL  string
	KernelDownloadURL  string
	KernelLocalVersion string
}

func (v Vanilla) Script(bc BuilderConfig) (string, error) {
	t := template.New(string(BuildTypeVanilla))
	parsed, err := t.Parse(vanillaTemplate)
	if err != nil {
		return "", err
	}

	kv := kernelrelease.FromString(bc.Build.KernelRelease)

	td := vanillaTemplateData{
		KernelBuildDir:     KernelDirectory,
		ModuleBuildDir:     ModuleDirectory,
		ModuleDownloadURL:  moduleDownloadURL(bc),
		KernelDownloadURL:  fetchVanillaKernelURLFromKernelVersion(kv),
		KernelLocalVersion: kv.FullExtraversion,
	}

	buf := bytes.NewBuffer(nil)
	err = parsed.Execute(buf, td)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func fetchVanillaKernelURLFromKernelVersion(kv kernelrelease.KernelRelease) string {
	return fmt.Sprintf("https://cdn.kernel.org/pub/linux/kernel/v%s.x/linux-%s.tar.xz", kv.Version, kv.Fullversion)
}
