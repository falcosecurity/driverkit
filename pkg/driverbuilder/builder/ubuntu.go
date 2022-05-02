package builder

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"text/template"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

// TargetTypeUbuntuGeneric identifies the UbuntuGeneric target.
const TargetTypeUbuntuGeneric Type = "ubuntu-generic"

// TargetTypeUbuntuAWS identifies the UbuntuAWS target.
const TargetTypeUbuntuAWS Type = "ubuntu-aws"

func init() {
	BuilderByTarget[TargetTypeUbuntuGeneric] = &ubuntuGeneric{}
	BuilderByTarget[TargetTypeUbuntuAWS] = &ubuntuAWS{}
}

// ubuntuGeneric is a driverkit target.
type ubuntuGeneric struct {
}

// Script compiles the script to build the kernel module and/or the eBPF probe.
func (v ubuntuGeneric) Script(c Config) (string, error) {
	t := template.New(string(TargetTypeUbuntuGeneric))
	parsed, err := t.Parse(ubuntuTemplate)
	if err != nil {
		return "", err
	}

	kr := kernelReleaseFromBuildConfig(c.Build)

	var urls []string
	if c.KernelUrls == nil {
		urls, err = ubuntuGenericHeadersURLFromRelease(kr, c.Build.KernelVersion)
	} else {
		urls, err = getResolvingURLs(c.KernelUrls)
	}
	if len(urls) != 2 {
		return "", fmt.Errorf("specific kernel headers not found")
	}

	td := ubuntuTemplateData{
		DriverBuildDir:       DriverDirectory,
		ModuleDownloadURL:    fmt.Sprintf("%s/%s.tar.gz", c.DownloadBaseURL, c.Build.DriverVersion),
		KernelDownloadURLS:   urls,
		KernelLocalVersion:   kr.FullExtraversion,
		KernelHeadersPattern: "linux-headers*generic",
		ModuleDriverName:     c.Build.ModuleDriverName,
		ModuleFullPath:       ModuleFullPath,
		BuildModule:          len(c.Build.ModuleFilePath) > 0,
		BuildProbe:           len(c.Build.ProbeFilePath) > 0,
		GCCVersion:           ubuntuGCCVersionFromKernelRelease(kr),
	}

	if kr.IsGKE() {
		td.KernelHeadersPattern = "linux-headers*gke"
	}

	buf := bytes.NewBuffer(nil)
	err = parsed.Execute(buf, td)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

// ubuntuAWS is a driverkit target.
type ubuntuAWS struct {
}

// Script compiles the script to build the kernel module and/or the eBPF probe.
func (v ubuntuAWS) Script(c Config) (string, error) {
	t := template.New(string(TargetTypeUbuntuGeneric))
	parsed, err := t.Parse(ubuntuTemplate)
	if err != nil {
		return "", err
	}

	kr := kernelReleaseFromBuildConfig(c.Build)

	var urls []string
	if c.KernelUrls == nil {
		urls, err = ubuntuAWSHeadersURLFromRelease(kr, c.Build.KernelVersion)
	} else {
		urls, err = getResolvingURLs(c.KernelUrls)
	}
	if err != nil {
		return "", err
	}
	if len(urls) != 2 {
		return "", fmt.Errorf("specific kernel headers not found")
	}

	td := ubuntuTemplateData{
		DriverBuildDir:       DriverDirectory,
		ModuleDownloadURL:    moduleDownloadURL(c),
		KernelDownloadURLS:   urls,
		KernelLocalVersion:   kr.FullExtraversion,
		KernelHeadersPattern: "linux-headers*",
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

func ubuntuAWSHeadersURLFromRelease(kr kernelrelease.KernelRelease, kv uint16) ([]string, error) {
	baseURL := []string{
		"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-aws",
		"http://security.ubuntu.com/ubuntu/pool/main/l/linux-aws",
		"http://ports.ubuntu.com/ubuntu-ports/pool/main/l/linux-aws",
	}

	for _, u := range baseURL {
		urls, err := getResolvingURLs(fetchUbuntuAWSKernelURLS(u, kr, kv))
		if err == nil && len(urls) == 2 {
			return urls, err
		}
	}

	// If we can't find the AWS files in the main folders,
	// try to proactively parse the subfolders to find what we need
	for _, u := range baseURL {
		url := fmt.Sprintf("%s-%s.%s", u, kr.Version, kr.PatchLevel)
		urls, err := parseUbuntuAWSKernelURLS(url, kr, kv)
		if err != nil {
			continue
		}
		urls, err = getResolvingURLs(urls)
		if err == nil {
			return urls, err
		}

	}

	return nil, fmt.Errorf("kernel headers not found")
}

func ubuntuGenericHeadersURLFromRelease(kr kernelrelease.KernelRelease, kv uint16) ([]string, error) {
	baseURL := []string{
		"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux",
		"http://security.ubuntu.com/ubuntu/pool/main/l/linux",
		"http://ports.ubuntu.com/ubuntu-ports/pool/main/l/linux",
		"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-gke-5.4",
		"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-gke-4.15",
	}

	for _, u := range baseURL {
		urls, err := getResolvingURLs(fetchUbuntuGenericKernelURL(u, kr, kv))
		// We expect both a common "_all" package,
		// and an arch dependent package.
		if err == nil && len(urls) == 2 {
			return urls, err
		}
	}

	return nil, fmt.Errorf("kernel headers not found")
}

func fetchUbuntuGenericKernelURL(baseURL string, kr kernelrelease.KernelRelease, kernelVersion uint16) []string {
	firstExtra := extractExtraNumber(kr.Extraversion)

	if kr.IsGKE() {
		return []string{
			// For 4.15 GKE kernels
			fmt.Sprintf(
				"%s/linux-gke-%s.%s-headers-%s-%s_%s-%s.%d_%s.deb",
				baseURL,
				kr.Version,
				kr.PatchLevel,
				kr.Fullversion,
				firstExtra,
				kr.Fullversion,
				firstExtra,
				kernelVersion,
				kr.Architecture.String(),
			),
			fmt.Sprintf(
				"%s/linux-headers-%s%s_%s-%s.%d_%s.deb",
				baseURL,
				kr.Fullversion,
				kr.FullExtraversion,
				kr.Fullversion,
				firstExtra,
				kernelVersion,
				kr.Architecture.String(),
			),
			// For 5.4 GKE kernels
			fmt.Sprintf(
				"%s/linux-gke-%s.%s-headers-%s-%s_%s-%s.%d~18.04.1_%s.deb",
				baseURL,
				kr.Version,
				kr.PatchLevel,
				kr.Fullversion,
				firstExtra,
				kr.Fullversion,
				firstExtra,
				kernelVersion,
				kr.Architecture.String(),
			),
			fmt.Sprintf(
				"%s/linux-headers-%s%s_%s-%s.%d~18.04.1_%s.deb",
				baseURL,
				kr.Fullversion,
				kr.FullExtraversion,
				kr.Fullversion,
				firstExtra,
				kernelVersion,
				kr.Architecture.String(),
			),
		}
	}

	return []string{
		fmt.Sprintf(
			"%s/linux-headers-%s-%s_%s-%s.%d_all.deb",
			baseURL,
			kr.Fullversion,
			firstExtra,
			kr.Fullversion,
			firstExtra,
			kernelVersion,
		),
		fmt.Sprintf(
			"%s/linux-headers-%s%s_%s-%s.%d_%s.deb",
			baseURL,
			kr.Fullversion,
			kr.FullExtraversion,
			kr.Fullversion,
			firstExtra,
			kernelVersion,
			kr.Architecture.String(),
		),
		fmt.Sprintf(
			"%s/linux-headers-%s%s-generic_%s-%s.%d_%s.deb",
			baseURL,
			kr.Fullversion,
			kr.FullExtraversion,
			kr.Fullversion,
			firstExtra,
			kernelVersion,
			kr.Architecture.String(),
		),
	}
}

func fetchUbuntuAWSKernelURLS(baseURL string, kr kernelrelease.KernelRelease, kernelVersion uint16) []string {
	firstExtra := extractExtraNumber(kr.Extraversion)
	return []string{
		fmt.Sprintf(
			"%s/linux-aws-headers-%s-%s_%s-%s.%d_all.deb",
			baseURL,
			kr.Fullversion,
			firstExtra,
			kr.Fullversion,
			firstExtra,
			kernelVersion,
		),
		fmt.Sprintf(
			"%s/linux-headers-%s%s_%s-%s.%d_%s.deb",
			baseURL,
			kr.Fullversion,
			kr.FullExtraversion,
			kr.Fullversion,
			firstExtra,
			kernelVersion,
			kr.Architecture.String(),
		),
		fmt.Sprintf(
			"%s/linux-headers-%s%s-aws_%s-%s.%d_%s.deb",
			baseURL,
			kr.Fullversion,
			kr.FullExtraversion,
			kr.Fullversion,
			firstExtra,
			kernelVersion,
			kr.Architecture.String(),
		),
	}
}

func parseUbuntuAWSKernelURLS(baseURL string, kr kernelrelease.KernelRelease, kernelVersion uint16) ([]string, error) {
	resp, err := http.Get(baseURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	firstExtra := extractExtraNumber(kr.Extraversion)
	rmatch := `href="(linux(?:-aws-%s.%s)?-headers-%s-%s(?:-aws)?_%s-%s\.%d.*(?:%s|all)\.deb)"`
	fullRegex := fmt.Sprintf(rmatch, kr.Version, kr.PatchLevel,
		kr.Fullversion, firstExtra, kr.Fullversion,
		firstExtra, kernelVersion, kr.Architecture.String())
	pattern := regexp.MustCompile(fullRegex)
	matches := pattern.FindAllStringSubmatch(string(body), 2)
	if len(matches) != 2 {
		return nil, fmt.Errorf("kernel headers and kernel headers common not found")
	}

	foundURLs := []string{fmt.Sprintf("%s/%s", baseURL, matches[0][1])}
	foundURLs = append(foundURLs, fmt.Sprintf("%s/%s", baseURL, matches[1][1]))
	return foundURLs, nil
}

func extractExtraNumber(extraversion string) string {
	firstExtraSplit := strings.Split(extraversion, "-")
	if len(firstExtraSplit) > 0 {
		return firstExtraSplit[0]
	}
	return ""
}

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

func ubuntuGCCVersionFromKernelRelease(kr kernelrelease.KernelRelease) string {
	switch kr.Version {
	case "3":
		if kr.PatchLevel == "13" || kr.PatchLevel == "2" {
			return "4.8"
		}
		return "6"
	}
	return "8"
}
