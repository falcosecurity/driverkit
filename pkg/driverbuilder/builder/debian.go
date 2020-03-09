package builder

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"text/template"

	"github.com/falcosecurity/driverkit/pkg/driverbuilder/buildtype"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

const BuildTypeDebian buildtype.BuildType = "debian"

func init() {
	buildtype.EnabledBuildTypes[BuildTypeDebian] = true
}

// Debian ...
type Debian struct {
}

// Script ...
func (v Debian) Script(bc BuilderConfig) (string, error) {
	t := template.New(string(BuildTypeDebian))
	parsed, err := t.Parse(debianTemplate)
	if err != nil {
		return "", err
	}

	kr := kernelrelease.FromString(bc.Build.KernelRelease)

	kurls, err := fetchDebianKernelURLs(kr, bc.Build.KernelVersion)
	if err != nil {
		return "", err
	}

	urls, err := getResolvingURLs(kurls)
	if err != nil {
		return "", err
	}
	if len(urls) < 2 {
		return "", fmt.Errorf("specific kernel headers not found")
	}

	td := debianTemplateData{
		ModuleBuildDir:     ModuleDirectory,
		ModuleDownloadURL:  fmt.Sprintf("%s/%s.tar.gz", bc.ModuleConfig.DownloadBaseURL, bc.Build.ModuleVersion),
		KernelDownloadURLS: urls,
		KernelLocalVersion: kr.FullExtraversion,
	}

	buf := bytes.NewBuffer(nil)
	err = parsed.Execute(buf, td)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func fetchDebianKernelURLs(kr kernelrelease.KernelRelease, kernelVersion uint16) ([]string, error) {
	kbuildURL, err := debianKbuildURLFromRelease(kr)
	if err != nil {
		return nil, err
	}

	urls, err := debianHeadersURLFromRelease(kr)
	if err != nil {
		return nil, err
	}
	urls = append(urls, kbuildURL)

	return urls, nil
}

type debianTemplateData struct {
	ModuleBuildDir     string
	ModuleDownloadURL  string
	KernelDownloadURLS []string
	KernelLocalVersion string
}

const debianTemplate = `
#!/bin/bash
set -xeuo pipefail

rm -Rf {{ .ModuleBuildDir }}
mkdir {{ .ModuleBuildDir }}
rm -Rf /tmp/module-download
mkdir -p /tmp/module-download

curl --silent -SL {{ .ModuleDownloadURL }} | tar -xzf - -C /tmp/module-download
mv /tmp/module-download/*/driver/* {{ .ModuleBuildDir }}

cp /module-builder/module-Makefile {{ .ModuleBuildDir }}/Makefile
cp /module-builder/module-driver-config.h {{ .ModuleBuildDir }}/driver_config.h

# Fetch the kernel
mkdir /tmp/kernel-download
cd /tmp/kernel-download
{{range $url := .KernelDownloadURLS}}
curl --silent -o kernel.deb -SL {{ $url }}
ar x kernel.deb
tar -xvf data.tar.xz
{{end}}
ls -la /tmp/kernel-download

cd /tmp/kernel-download/

cp -r usr/* /usr
cp -r lib/* /lib

cd /usr/src
sourcedir=$(find . -type d -name "linux-headers-*amd64" | head -n 1 | xargs readlink -f)

ls -la $sourcedir

# Build the module
cd $sourcedir
cd {{ .ModuleBuildDir }}
make CC=/usr/bin/gcc-8 KERNELDIR=$sourcedir
# Print results
ls -la

modinfo falco.ko

cd bpf
make LLC=/usr/bin/llc-7 CLANG=/usr/bin/clang-7 CC=/usr/bin/gcc-8 KERNELDIR=$sourcedir
ls -la
`

func debianHeadersURLFromRelease(kr kernelrelease.KernelRelease) ([]string, error) {
	baseURLS := []string{
		"http://security-cdn.debian.org/pool/main/l/linux/",
		"http://security-cdn.debian.org/pool/updates/main/l/linux/",
		"https://mirrors.edge.kernel.org/debian/pool/main/l/linux/",
	}

	for _, u := range baseURLS {
		urls, err := fetchDebianHeadersURLFromRelease(u, kr)

		if err == nil {
			return urls, err
		}
	}

	return nil, fmt.Errorf("kernel headers not found")
}

func fetchDebianHeadersURLFromRelease(baseURL string, kr kernelrelease.KernelRelease) ([]string, error) {
	extraVersionPartial := strings.TrimSuffix(kr.FullExtraversion, "-amd64")
	rmatch := `href="(linux-headers-%s\.%s\.%s%s-(amd64|common)_.*(amd64|all)\.deb)"`
	fullregex := fmt.Sprintf(rmatch, kr.Version, kr.PatchLevel, kr.Sublevel, extraVersionPartial)
	pattern := regexp.MustCompile(fullregex)
	resp, err := http.Get(baseURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	matches := pattern.FindAllStringSubmatch(string(body), 2)

	if len(matches) != 2 {
		return nil, fmt.Errorf("kernel headers and kernel headers common not found")
	}

	foundURLs := []string{fmt.Sprintf("%s%s", baseURL, matches[0][1])}

	foundURLs = append(foundURLs, fmt.Sprintf("%s%s", baseURL, matches[1][1]))

	return foundURLs, nil
}

func debianKbuildURLFromRelease(kr kernelrelease.KernelRelease) (string, error) {
	rmatch := `href="(linux-kbuild-%s\.%s.*amd64\.deb)"`
	kbuildPattern := regexp.MustCompile(fmt.Sprintf(rmatch, kr.Version, kr.PatchLevel))
	baseUrl := "http://mirrors.kernel.org/debian/pool/main/l/linux/"
	if kr.Version == "3" {
		baseUrl = "http://mirrors.kernel.org/debian/pool/main/l/linux-tools/"
	}

	resp, err := http.Get(baseUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	match := kbuildPattern.FindStringSubmatch(string(body))

	if len(match) != 2 {
		return "", fmt.Errorf("kbuild not found")
	}

	return fmt.Sprintf("%s%s", baseUrl, match[1]), nil
}