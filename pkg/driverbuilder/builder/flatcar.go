package builder

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"text/template"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

// TargetTypeFlatcar identifies the Flatcar target.
const TargetTypeFlatcar Type = "flatcar"

func init() {
	BuilderByTarget[TargetTypeFlatcar] = &flatcar{}
}

// flatcar is a driverkit target.
type flatcar struct {
}

// Script compiles the script to build the kernel module and/or the eBPF probe.
func (c flatcar) Script(cfg Config) (string, error) {
	t := template.New(string(TargetTypeFlatcar))
	parsed, err := t.Parse(flatcarTemplate)
	if err != nil {
		return "", err
	}

	kr :=  kernelReleaseFromBuildConfig(cfg.Build)
	if kr.Extraversion != "" {
		return "", fmt.Errorf("unexpected extraversion: %s", kr.Extraversion)
	}

	// convert string to int
	version, err := strconv.Atoi(kr.Version)
	if err != nil {
		return "", err
	}
	if version < 1500 {
		return "", fmt.Errorf("not a valid flatcar release version: %s", kr.Version)
	}
	flatcarVersion := kr.Fullversion
	flatcarInfo, err := fetchFlatcarMetadata(kr)
	if err != nil {
		return "", err
	}

	kconfUrls, err := getResolvingURLs(fetchFlatcarKernelConfigURL(kr.Architecture, flatcarInfo.Channel, kr.Fullversion))
	if err != nil {
		return "", err
	}

	var urls []string
    if cfg.KernelUrls == nil {
        // Check (and filter) existing kernels before continuing
        urls, err = getResolvingURLs(fetchFlatcarKernelURLS(flatcarInfo.KernelVersion))
    } else {
        urls, err = getResolvingURLs(cfg.KernelUrls)
    }
    if err != nil {
        return "", err
    }

	td := flatcarTemplateData{
		DriverBuildDir:    DriverDirectory,
		ModuleDownloadURL: moduleDownloadURL(cfg),
		KernelDownloadURL: urls[0],
		GCCVersion:        flatcarGccVersion(flatcarInfo.GCCVersion),
		FlatcarVersion:    flatcarVersion,
		FlatcarChannel:    flatcarInfo.Channel,
		KernelConfigURL:   kconfUrls[0],
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

func fetchFlatcarMetadata(kr kernelrelease.KernelRelease) (*flatcarReleaseInfo, error) {
	flatcarInfo := flatcarReleaseInfo{}
	flatcarVersion := kr.Fullversion
	packageIndexUrl, err := getResolvingURLs(fetchFlatcarPackageListURL(kr.Architecture, flatcarVersion))
	if err != nil {
		return nil, err
	}
	// first part of the URL is the channel
	flatcarInfo.Channel = strings.Split(packageIndexUrl[0], ".")[0][len("https://"):]
	resp, err := http.Get(packageIndexUrl[0])
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	packageListBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	packageList := string(packageListBytes)
	if len(packageListBytes) == 0 {
		return nil, fmt.Errorf("missing package list for %s", flatcarVersion)
	}

	gccVersion := ""
	kernelVersion := ""
	// structure of a package line is: category/name-version(-revision)::repository
	for _, pkg := range strings.Split(string(packageList), "\n") {
		if strings.HasPrefix(pkg, "sys-devel/gcc") {
			gccVersion = pkg[len("sys-devel/gcc-"):]
			gccVersion = strings.Split(gccVersion, "::")[0]
			gccVersion = strings.Split(gccVersion, "-")[0]
		}
		if strings.HasPrefix(pkg, "sys-kernel/coreos-kernel") {
			kernelVersion = pkg[len("sys-kernel/coreos-kernel-"):]
			kernelVersion = strings.Split(kernelVersion, "::")[0]
			kernelVersion = strings.Split(kernelVersion, "-")[0]
		}
	}
	flatcarInfo.GCCVersion = gccVersion
	flatcarInfo.KernelVersion = kernelVersion

	return &flatcarInfo, nil
}

func fetchFlatcarPackageListURL(architecture kernelrelease.Architecture, flatcarVersion string) []string {
	pattern := "https://%s.release.flatcar-linux.net/%s-usr/%s/flatcar_production_image_packages.txt"
	channels := []string{
		"stable",
		"beta",
		"alpha",
	}
	urls := []string{}
	for _, channel := range channels {
		urls = append(urls, fmt.Sprintf(pattern, channel, architecture.String(), flatcarVersion))
	}
	return urls
}

func fetchFlatcarKernelConfigURL(architecture kernelrelease.Architecture, flatcarChannel, flatcarVersion string) []string {
	return []string{fmt.Sprintf("https://%s.release.flatcar-linux.net/%s-usr/%s/flatcar_production_image_kernel_config.txt", flatcarChannel, architecture.String(), flatcarVersion)}
}

func fetchFlatcarKernelURLS(kernelVersion string) []string {
	kv := kernelrelease.FromString(kernelVersion)
	return []string{fmt.Sprintf("https://cdn.kernel.org/pub/linux/kernel/v%s.x/linux-%s.tar.xz", kv.Version, kv.Fullversion)}
}

type flatcarReleaseInfo struct {
	Channel       string
	GCCVersion    string
	KernelVersion string
}

type flatcarTemplateData struct {
	DriverBuildDir    string
	ModuleDownloadURL string
	KernelDownloadURL string
	GCCVersion        string
	FlatcarVersion    string
	FlatcarChannel    string
	KernelConfigURL   string
	ModuleDriverName  string
	ModuleFullPath    string
	BuildModule       bool
	BuildProbe        bool
}

const flatcarTemplate = `
#!/bin/bash
set -xeuo pipefail

rm -Rf {{ .DriverBuildDir }}
mkdir {{ .DriverBuildDir }}
rm -Rf /tmp/module-download
mkdir -p /tmp/module-download

curl --silent -SL {{ .ModuleDownloadURL }} | tar -xzf - -C /tmp/module-download
mv /tmp/module-download/*/driver/* {{ .DriverBuildDir }}

cp /driverkit/module-Makefile {{ .DriverBuildDir }}/Makefile
bash /driverkit/fill-driver-config.sh {{ .DriverBuildDir }}

# Fetch the kernel
mkdir /tmp/kernel-download
cd /tmp/kernel-download
curl --silent -SL {{ .KernelDownloadURL }} | tar -Jxf - -C /tmp/kernel-download
rm -Rf /tmp/kernel
mkdir -p /tmp/kernel
mv /tmp/kernel-download/*/* /tmp/kernel

# Change current gcc
ln -sf /usr/bin/gcc-{{ .GCCVersion }} /usr/bin/gcc

curl --silent -o /tmp/kernel.config -SL {{ .KernelConfigURL }}

cd /tmp/kernel
sed -i -e 's|^\(EXTRAVERSION =\).*|\1 -flatcar|' Makefile
make KCONFIG_CONFIG=/tmp/kernel.config oldconfig
make KCONFIG_CONFIG=/tmp/kernel.config modules_prepare

{{ if .BuildModule }}
# Build the module
cd {{ .DriverBuildDir }}
make KERNELDIR=/tmp/kernel
mv {{ .ModuleDriverName }}.ko {{ .ModuleFullPath }}
strip -g {{ .ModuleFullPath }}
# Print results
modinfo {{ .ModuleFullPath }}
{{ end }}

{{ if .BuildProbe }}
# Build the eBPF probe
cd {{ .DriverBuildDir }}/bpf
make LLC=/usr/bin/llc-12 CLANG=/usr/bin/clang-12 CC=/usr/bin/gcc KERNELDIR=/tmp/kernel
ls -l probe.o
{{ end }}
`

func flatcarGccVersion(gccVersion string) string {
	// reuse kernelrelease version parsing for gcc
	gv := kernelrelease.FromString(gccVersion)
	switch gv.Version {
	case "7":
		return "6"
	default:
		// builder doesn't support anything newer than 8 right now
		return "8"
	}
}
