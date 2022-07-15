package builder

import (
	"bytes"
	_ "embed"
	"fmt"
	"strings"
	"text/template"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

// TargetTypeUbuntu identifies the Ubuntu target.
const TargetTypeUbuntu Type = "ubuntu"

// backwards compatibility
const TargetTypeUbuntuGeneric Type = "ubuntu-generic"
const TargetTypeUbuntuAWS Type = "ubuntu-aws"

func init() {
	BuilderByTarget[TargetTypeUbuntu] = &ubuntu{}

	// backwards compatibility
	BuilderByTarget[TargetTypeUbuntuGeneric] = &ubuntu{}
	BuilderByTarget[TargetTypeUbuntuAWS] = &ubuntu{}
}

// ubuntu is a driverkit target.
type ubuntu struct{}

// ubuntuTemplateData stores information to be templated into the shell script
type ubuntuTemplateData struct {
	DriverBuildDir       string
	ModuleDownloadURL    string
	KernelDownloadURLS   []string
	KernelLocalVersion   string
	KernelHeadersPattern string
	ModuleDriverName     string
	ModuleFullPath       string
	BuildProbe           bool
	BuildModule          bool
	GCCVersion           string
}

// Script compiles the script to build the kernel module and/or the eBPF probe.
func (v ubuntu) Script(c Config, kr kernelrelease.KernelRelease) (string, error) {

	t := template.New(string(TargetTypeUbuntu))

	parsed, err := t.Parse(ubuntuTemplate)
	if err != nil {
		return "", err
	}

	var urls []string
	if c.KernelUrls == nil {
		urls, err = ubuntuHeadersURLFromRelease(kr, c.Build.KernelVersion)
	} else {
		urls, err = getResolvingURLs(c.KernelUrls)
	}
	// if there was an error
	if err != nil {
		return "", err
	}
	// if no results
	if len(urls) == 0 {
		return "", fmt.Errorf("specific kernel headers not found")
	}

	td := ubuntuTemplateData{
		DriverBuildDir:       DriverDirectory,
		ModuleDownloadURL:    moduleDownloadURL(c),
		KernelDownloadURLS:   urls,
		KernelLocalVersion:   kr.FullExtraversion,
		KernelHeadersPattern: "linux*headers*",
		ModuleDriverName:     c.Build.ModuleDriverName,
		ModuleFullPath:       ModuleFullPath,
		BuildModule:          len(c.Build.ModuleFilePath) > 0,
		BuildProbe:           len(c.Build.ProbeFilePath) > 0,
		GCCVersion:           ubuntuGCCVersionFromKernelRelease(kr),
	}

	buf := bytes.NewBuffer(nil)
	err = parsed.Execute(buf, td)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func ubuntuHeadersURLFromRelease(kr kernelrelease.KernelRelease, kv string) ([]string, error) {

	// decide which mirrors to use based on the architecture passed in
	fmt.Println(kr.Architecture.String())
	baseURLs := []string{}
	if kr.Architecture.String() == "amd64" {
		baseURLs = []string{
			"https://mirrors.edge.kernel.org/ubuntu/pool/main/l",
			"http://security.ubuntu.com/ubuntu/pool/main/l",
		}
	} else {
		baseURLs = []string{
			"http://ports.ubuntu.com/ubuntu-ports/pool/main/l",
		}
	}

	for _, url := range baseURLs {
		// get all possible URLs
		possibleURLs, err := fetchUbuntuKernelURL(url, kr, kv)
		if err != nil {
			return nil, err
		}
		// try resolving the URLs
		urls, err := getResolvingURLs(possibleURLs)
		fmt.Println(urls)
		// there should be 2 urls returned - the _all package and the arch-specific package
		if err == nil && len(urls) == 2 {
			return urls, err
		}
	}

	// packages weren't found, return error out
	return nil, fmt.Errorf("kernel headers not found")
}

func fetchUbuntuKernelURL(baseURL string, kr kernelrelease.KernelRelease, kernelVersion string) ([]string, error) {
	firstExtra := extractExtraNumber(kr.Extraversion)
	ubuntuFlavor := extractUbuntuFlavor(kr.Extraversion)

	// piece together possible subdirs on Ubuntu URLs for a given flavor
	// these include the base (such as 'linux-azure') and the base + version/path ('linux-azure-5.15')
	possibleSubDirs := []string{
		"linux",                               // default subdir, where generic, lowlatency, etc. are store
		fmt.Sprintf("linux-%s", ubuntuFlavor), // ex: linux-aws
		fmt.Sprintf("linux-%s-%d.%d", ubuntuFlavor, kr.Version, kr.PatchLevel), // ex: linux-azure-5.15
	}

	// build all possible full URLs with the flavor subdirs
	possibleFullURLs := []string{}
	for _, subdir := range possibleSubDirs {
		possibleFullURLs = append(
			possibleFullURLs,
			fmt.Sprintf("%s/%s", baseURL, subdir),
		)
	}

	// piece together all possible naming patterns for packages
	// in general, there should be 2: an arch-specific package and an _all package
	packageNamePatterns := []string{
		fmt.Sprintf(
			"linux-headers-%s%s_%s-%s.%s_%s_all.deb",
			kr.Fullversion,
			kr.FullExtraversion,
			kr.Fullversion,
			firstExtra,
			kernelVersion,
			kr.Architecture.String(),
		),
		fmt.Sprintf(
			"linux-headers-%s-%s-%s_%s-%s.%s_%s.deb",
			kr.Fullversion,
			firstExtra,
			ubuntuFlavor,
			kr.Fullversion,
			firstExtra,
			kernelVersion,
			kr.Architecture.String(),
		),
		fmt.Sprintf(
			"linux-%s-headers-%s-%s_%s-%s.%s_all.deb",
			ubuntuFlavor,
			kr.Fullversion,
			firstExtra,
			kr.Fullversion,
			firstExtra,
			kernelVersion,
		),
	}

	// combine it all together now
	packageFullURLs := []string{}
	for _, url := range possibleFullURLs {
		for _, packageName := range packageNamePatterns {
			packageFullURLs = append(
				packageFullURLs,
				fmt.Sprintf("%s/%s", url, packageName),
			)
		}
	}

	// testing
	fmt.Println(packageFullURLs)
	// os.Exit(1)

	return packageFullURLs, nil

}

func extractExtraNumber(extraversion string) string {
	firstExtraSplit := strings.Split(extraversion, "-")
	if len(firstExtraSplit) > 0 {
		return firstExtraSplit[0]
	}
	return ""
}

func extractUbuntuFlavor(extraversion string) string {
	firstExtraSplit := strings.Split(extraversion, "-")
	if len(firstExtraSplit) > 0 {
		flavor := firstExtraSplit[1]
		return flavor
	}
	return ""
}

func ubuntuGCCVersionFromKernelRelease(kr kernelrelease.KernelRelease) string {
	switch kr.Version {
	case 3:
		if kr.PatchLevel == 13 || kr.PatchLevel == 2 {
			return "4.8"
		}
		return "6"
	case 5:
		if kr.PatchLevel >= 19 {
			return "11"
		} else if kr.PatchLevel >= 11 {
			return "10"
		}
	}
	return "8"
}

const ubuntuTemplate = `
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
{{range $url := .KernelDownloadURLS}}
curl --silent -o kernel.deb -SL {{ $url }}
ar x kernel.deb
tar -xvf data.tar.*
{{end}}
ls -la /tmp/kernel-download

cd /tmp/kernel-download/usr/src/
sourcedir=$(find . -type d -name "{{ .KernelHeadersPattern }}" | head -n 1 | xargs readlink -f)

ls -la $sourcedir

# Change current gcc
ln -sf /usr/bin/gcc-{{ .GCCVersion }} /usr/bin/gcc

{{ if .BuildModule }}
# Build the module
cd {{ .DriverBuildDir }}
make KERNELDIR=$sourcedir
mv {{ .ModuleDriverName }}.ko {{ .ModuleFullPath }}
strip -g {{ .ModuleFullPath }}
# Print results
modinfo {{ .ModuleFullPath }}
{{ end }}

{{ if .BuildProbe }}
# Build the eBPF probe
cd {{ .DriverBuildDir }}/bpf
if [[ -x /usr/bin/llc ]]; then
	LLC_BIN=/usr/bin/llc
else
	LLC_BIN=/usr/bin/llc-7
fi

if [[ -x /usr/bin/clang ]]; then
	CLANG_BIN=/usr/bin/clang
else
	CLANG_BIN=/usr/bin/clang-7
fi

make LLC=$LLC_BIN CLANG=$CLANG_BIN CC=/usr/bin/gcc-8 KERNELDIR=$sourcedir
ls -l probe.o
{{ end }}
`
