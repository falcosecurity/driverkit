package builder

import (
	"bytes"
	_ "embed"
	"fmt"
	"strings"
	"text/template"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

//go:embed templates/ubuntu.sh
var ubuntuTemplate string

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
	if len(urls) < 2 {
		return "", fmt.Errorf("specific kernel headers not found")
	}

	// parse the flavor out of the kernelrelease extraversion
	_, flavor := parseUbuntuExtraVersion(kr.Extraversion)

	// handle hwe kernels, which resolve to "generic" urls under /linux-hwe
	// Example: http://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-hwe/linux-headers-4.18.0-24-generic_4.18.0-24.25~18.04.1_amd64.deb
	headersPattern := ""
	if flavor == "hwe" {
		headersPattern = "linux-headers*generic"
	} else {
		headersPattern = fmt.Sprintf("linux-headers*%s", flavor)
	}

	td := ubuntuTemplateData{
		DriverBuildDir:       DriverDirectory,
		ModuleDownloadURL:    moduleDownloadURL(c),
		KernelDownloadURLS:   urls,
		KernelLocalVersion:   kr.FullExtraversion,
		KernelHeadersPattern: headersPattern,
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
	baseURLs := []string{}
	if kr.Architecture.String() == "amd64" {
		baseURLs = []string{
			"https://mirrors.edge.kernel.org/ubuntu/pool/main/l",
			"http://security.ubuntu.com/ubuntu/pool/main/l",
		}
	} else {
		baseURLs = []string{
			// arm64 and others are hosted on ports.ubuntu.com
			// but they will resolve for amd64 without this if logic
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
		// there should be 2 urls returned - the _all.deb package and the _{arch}.deb package
		if err == nil && len(urls) == 2 {
			return urls, err
		}
	}

	// packages weren't found, return error out
	return nil, fmt.Errorf("kernel headers not found")
}

func fetchUbuntuKernelURL(baseURL string, kr kernelrelease.KernelRelease, kernelVersion string) ([]string, error) {

	// parse the extra number and flavor for the kernelrelease extraversion
	firstExtra, ubuntuFlavor := parseUbuntuExtraVersion(kr.Extraversion)

	// piece together possible subdirs on Ubuntu base URLs for a given flavor
	// these include the base (such as 'linux-azure') and the base + version/patch ('linux-azure-5.15')
	// examples:
	// 		https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux
	// 		https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-aws
	// 		https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-azure-5.15
	possibleSubDirs := []string{
		"linux",                               // default subdir, where generic etc. are stored
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
	// 2 urls should resolve: an _{arch}.deb package and an _all.deb package
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
		fmt.Sprintf(
			"linux-headers-%s%s_%s-%s.%s_%s.deb",
			kr.Fullversion,
			kr.FullExtraversion,
			kr.Fullversion,
			firstExtra,
			kernelVersion,
			kr.Architecture.String(),
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

	// return out the deduplicated url list
	return deduplicateURLs(packageFullURLs), nil
}

// deduplicate the array of URLs to ensure we are
// only get unique resolving URLs for packages
func deduplicateURLs(urls []string) []string {
	keys := make(map[string]bool)
	dedupURLs := []string{}

	// loop over the URL list
	// set a flag for new URLs in list, add to dedup list
	// do nothing if URL is duplicate
	for _, url := range urls {
		if _, value := keys[url]; !value {
			keys[url] = true
			dedupURLs = append(dedupURLs, url)
		}
	}
	return dedupURLs
}

// parse the extraversion from the kernelrelease to retrieve the extraNumber and flavor
// assume the flavor is "generic" if unable to parse the flavor
// Example: Input -> "188-generic", Output -> "188", "generic"
// NOTE: make sure the kernelrelease passed in appears *exactly* as `uname -r` output
func parseUbuntuExtraVersion(extraversion string) (string, string) {
	if strings.Contains(extraversion, "-") {
		split := strings.Split(extraversion, "-")
		extraNumber := split[0]
		flavor := split[1]
		return extraNumber, flavor
	}

	// if unable to parse a flavor assume "generic" and return back the extraversion passed in
	return extraversion, "generic"
}

func ubuntuGCCVersionFromKernelRelease(kr kernelrelease.KernelRelease) string {
	switch kr.Version {
	case 3:
		switch {
		case kr.PatchLevel == 13 || kr.PatchLevel == 2:
			return "4.8"
		default:
			return "6"
		}
	case 5:
		switch {
		case kr.PatchLevel >= 18:
			return "11"
		case kr.PatchLevel >= 11:
			return "10"
		}
	}
	return "8"
}
