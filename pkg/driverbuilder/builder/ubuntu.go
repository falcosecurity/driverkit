package builder

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"text/template"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

// TargetTypeUbuntuGeneric identifies the Ubuntu target.
const TargetTypeUbuntu Type = "ubuntu"

func init() {
	BuilderByTarget[TargetTypeUbuntu] = &ubuntu{}
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
func (v ubuntu) Script(c Config) (string, error) {

	t := template.New(string(TargetTypeUbuntu))

	parsed, err := t.Parse(ubuntuTemplate)
	if err != nil {
		return "", err
	}
	fmt.Printf("%+v\n", parsed)

	// read in the build config
	kr := kernelReleaseFromBuildConfig(c.Build)
	fmt.Printf("%+v\n", kr)

	var urls []string
	if c.KernelUrls == nil {
		urls, err = ubuntuHeadersURLFromRelease(kr, c.Build.KernelVersion)
	} else {
		urls, err = getResolvingURLs(c.KernelUrls)
	}
	if err != nil {
		return "", err
	}
	if len(urls) < 2 {
		return "", fmt.Errorf("specific kernel headers not found")
	}
	fmt.Printf("%+v\n", urls)

	td := ubuntuTemplateData{
		DriverBuildDir:       DriverDirectory,
		ModuleDownloadURL:    fmt.Sprintf("%s/%s.tar.gz", c.DownloadBaseURL, c.Build.DriverVersion),
		KernelDownloadURLS:   urls,
		KernelLocalVersion:   kr.FullExtraversion,
		KernelHeadersPattern: determineKernelHeadersPattern(kr),
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

func determineKernelHeadersPattern(kr kernelrelease.KernelRelease) string {
	if kr.IsGKE() {
		return "linux-gke-headers"
	} else if kr.IsAWS() {
		return "linux-aws-headers"
	} else {
		return "linux-generic-headers"
	}
}

func ubuntuHeadersURLFromRelease(kr kernelrelease.KernelRelease, kv uint16) ([]string, error) {
	baseURLs := []string{
		"http://archive.ubuntu.com/ubuntu/pool/main/l",
		"http://ports.ubuntu.com/pool/main/l",

		// "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux",
		// "http://security.ubuntu.com/ubuntu/pool/main/l/linux",
		// "http://ports.ubuntu.com/ubuntu-ports/pool/main/l/linux",
		// "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-gke-5.4",
		// "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-gke-4.15",
		// "https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-aws",
		// "http://security.ubuntu.com/ubuntu/pool/main/l/linux-aws",
		// "http://ports.ubuntu.com/ubuntu-ports/pool/main/l/linux-aws",
	}

	for _, url := range baseURLs {
		// get all possible URLs
		possibleURLs, err := fetchUbuntuKernelURL(url, kr, kv)
		if err != nil {
			return nil, err
		}
		// try resolving the URLs
		urls, err := getResolvingURLs(possibleURLs)
		// We expect both a common "_all" package,
		// and an arch dependent package.
		if err == nil && len(urls) == 2 {
			return urls, err
		}
	}

	return nil, fmt.Errorf("kernel headers not found")
}

func fetchUbuntuKernelURL(baseURL string, kr kernelrelease.KernelRelease, kernelVersion uint16) ([]string, error) {
	firstExtra := extractExtraNumber(kr.Extraversion)
	ubuntuFlavor := extractUbuntuFlavor(kr.Extraversion)

	// discover all possible subdirs on Ubuntu URLs for a given flavor
	subdirs, err := fetchAllFlavorSubdirs(baseURL, ubuntuFlavor)
	if err != nil {
		return nil, err
	}

	// build all possible full URLs with the flavor subdirs
	possibleFullURLs := []string{}
	for _, subdir := range subdirs {
		possibleFullURLs = append(
			possibleFullURLs,
			fmt.Sprintf("%s/%s", baseURL, subdir),
		)
	}

	// swap back from hwe to generic --
	// the subdir on the archive is linux-hwe-*,
	// but the actual package is linux-headers-*-generic-*
	if ubuntuFlavor == "hwe" {
		ubuntuFlavor = "generic"
	}

	// piece together all possible naming patterns for packages
	// in general, there should be 2: an arch-specific package and an _all package
	packageNamePatterns := []string{
		fmt.Sprintf(
			"linux-headers-%s-%s-%s_%s-%s.%d_%s.deb",
			kr.Fullversion,
			firstExtra,
			ubuntuFlavor,
			kr.Fullversion,
			firstExtra,
			kernelVersion,
			kr.Architecture.String(),
		),
		fmt.Sprintf(
			"linux-headers-%s-%s-%s_%s-%s.%d_all.deb",
			kr.Fullversion,
			firstExtra,
			ubuntuFlavor,
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
	os.Exit(1)

	return packageFullURLs, nil

}

// given a base URL and an Ubuntu flavor, query the URL and find all possible subdirs with that flavor
// example for "generic": [linux-hwe-5.0 linux-hwe-5.4 linux-hwe-5.8 linux-hwe-5.11 linux-hwe-5.13 linux-hwe-5.15 linux-hwe-edge linux-hwe]
func fetchAllFlavorSubdirs(baseURL string, flavor string) ([]string, error) {
	// query base URL
	res, err := http.Get(baseURL)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	// convert body to string
	strBody := string(body)

	// regex for grep'ing out the flavor
	// capture group to get just the subdir name from the HTML
	r := regexp.MustCompile(`.*(linux-` + flavor + `.*)/</a>.*`)
	matches := r.FindAllStringSubmatch(strBody, -1)
	if matches == nil { // present error to user if no matches
		return nil, fmt.Errorf("No URLs found for specific Ubuntu flavor: %s", flavor)
	}

	// loop over the matches, append to return
	// capture groups are stored at 2nd index
	flavorSubdirs := []string{}
	for _, match := range matches {
		flavorSubdirs = append(flavorSubdirs, match[1])
	}
	fmt.Printf("%+v\n", flavorSubdirs)
	return flavorSubdirs, nil
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
		// generic is stored as "hwe" on ubuntu archive
		if flavor == "generic" {
			flavor = "hwe"
		}
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
