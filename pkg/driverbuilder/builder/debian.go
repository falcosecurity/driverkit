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

// TargetTypeDebian identifies the Debian target.
const TargetTypeDebian Type = "debian"

func init() {
	BuilderByTarget[TargetTypeDebian] = &debian{}
}

// debian is a driverkit target.
type debian struct {
}

// Script compiles the script to build the kernel module and/or the eBPF probe.
func (v debian) Script(c Config) (string, error) {
	t := template.New(string(TargetTypeDebian))
	parsed, err := t.Parse(debianTemplate)
	if err != nil {
		return "", err
	}

	kr := kernelrelease.FromString(c.Build.KernelRelease)

	kurls, err := fetchDebianKernelURLs(kr, c.Build.KernelVersion)
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
		DriverBuildDir:     DriverDirectory,
		ModuleDownloadURL:  fmt.Sprintf("%s/%s.tar.gz", c.DownloadBaseURL, c.Build.DriverVersion),
		KernelDownloadURLS: urls,
		KernelLocalVersion: kr.FullExtraversion,
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
	DriverBuildDir     string
	ModuleDownloadURL  string
	KernelDownloadURLS []string
	KernelLocalVersion string
	BuildModule        bool
	BuildProbe         bool
}

const debianTemplate = `
#!/bin/bash
set -xeuo pipefail

rm -Rf {{ .DriverBuildDir }}
mkdir {{ .DriverBuildDir }}
rm -Rf /tmp/module-download
mkdir -p /tmp/module-download

curl --silent -SL {{ .ModuleDownloadURL }} | tar -xzf - -C /tmp/module-download
mv /tmp/module-download/*/driver/* {{ .DriverBuildDir }}

cp /driverkit/module-Makefile {{ .DriverBuildDir }}/Makefile
cp /driverkit/module-driver-config.h {{ .DriverBuildDir }}/driver_config.h

# Fetch the kernel
mkdir /tmp/kernel-download
cd /tmp/kernel-download
{{ range $url := .KernelDownloadURLS }}
curl --silent -o kernel.deb -SL {{ $url }}
ar x kernel.deb
tar -xvf data.tar.xz
{{ end }}
ls -la /tmp/kernel-download

cd /tmp/kernel-download/

cp -r usr/* /usr
cp -r lib/* /lib

cd /usr/src
sourcedir=$(find . -type d -name "linux-headers-*amd64" | head -n 1 | xargs readlink -f)

ls -la $sourcedir

{{ if .BuildModule }}
# Build the module
cd {{ .DriverBuildDir }}
make CC=/usr/bin/gcc-8 KERNELDIR=$sourcedir
strip -g falco.ko
# Print results
modinfo falco.ko
{{ end }}

{{ if .BuildProbe }}
# Build the eBPF probe
cd {{ .DriverBuildDir }}/bpf
make LLC=/usr/bin/llc-7 CLANG=/usr/bin/clang-7 KERNELDIR=$sourcedir
ls -l probe.o
{{ end }}
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
	rmatch := `href="(linux-headers-%s\.%s\.%s%s-(%s)_.*(amd64|all)\.deb)"`

	// match for kernel versions like 4.19.0-6-amd64
	extraVersionPartial := strings.TrimSuffix(kr.FullExtraversion, "-amd64")
	matchExtraGroup := "amd64"
	matchExtraGroupCommon := "common"

	// match for kernel versions like 4.19.0-6-cloud-amd64
	if strings.Contains(kr.FullExtraversion, "-cloud") {
		extraVersionPartial = strings.TrimSuffix(extraVersionPartial, "-cloud")
		matchExtraGroup = "cloud-amd64"
	}

	// download index
	resp, err := http.Get(baseURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	bodyStr := string(body)

	// look for kernel headers
	fullregex := fmt.Sprintf(rmatch, kr.Version, kr.PatchLevel, kr.Sublevel, extraVersionPartial, matchExtraGroup)
	pattern := regexp.MustCompile(fullregex)
	matches := pattern.FindStringSubmatch(bodyStr)
	if len(matches) < 1 {
		return nil, fmt.Errorf("kernel headers not found")
	}

	// look for kernel headers common
	fullregexCommon := fmt.Sprintf(rmatch, kr.Version, kr.PatchLevel, kr.Sublevel, extraVersionPartial, matchExtraGroupCommon)
	patternCommon := regexp.MustCompile(fullregexCommon)
	matchesCommon := patternCommon.FindStringSubmatch(bodyStr)
	if len(matchesCommon) < 1 {
		return nil, fmt.Errorf("kernel headers common not found")
	}

	foundURLs := []string{fmt.Sprintf("%s%s", baseURL, matches[1])}
	foundURLs = append(foundURLs, fmt.Sprintf("%s%s", baseURL, matchesCommon[1]))

	return foundURLs, nil
}

func debianKbuildURLFromRelease(kr kernelrelease.KernelRelease) (string, error) {
	rmatch := `href="(linux-kbuild-%s\.%s.*amd64\.deb)"`
	kbuildPattern := regexp.MustCompile(fmt.Sprintf(rmatch, kr.Version, kr.PatchLevel))
	baseURL := "http://mirrors.kernel.org/debian/pool/main/l/linux/"
	if kr.Version == "3" {
		baseURL = "http://mirrors.kernel.org/debian/pool/main/l/linux-tools/"
	}

	resp, err := http.Get(baseURL)
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

	return fmt.Sprintf("%s%s", baseURL, match[1]), nil
}
