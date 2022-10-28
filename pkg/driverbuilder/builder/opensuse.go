package builder

import (
	_ "embed"
	"fmt"
	"strings"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

//go:embed templates/opensuse.sh
var opensuseTemplate string

// TargetTypeOpenSUSE identifies the OpenSUSE target.
const TargetTypeOpenSUSE Type = "opensuse"

// base URLs
var baseURLs []string = []string{
	// general releases, leap releases
	"https://mirrors.edge.kernel.org/opensuse/distribution",
	"http://download.opensuse.org/distribution",
	"https://download.opensuse.org/repositories/Kernel:",
	// some releases are stored at the top level specifically
	"http://download.opensuse.org",
}

var releases []string = []string{
	// openSUSE leap
	"43.2",
	"15.0",
	"15.1",
	"15.2",
	"15.3",
	// other releases
	"HEAD",
	"stable",
	"tumbleweed",
}

func init() {
	BuilderByTarget[TargetTypeOpenSUSE] = &opensuse{}
}

// opensuse is a driverkit target.
type opensuse struct {
}

type opensuseTemplateData struct {
	commonTemplateData
	KernelDownloadURLs []string
}

func (o *opensuse) Name() string {
	return TargetTypeOpenSUSE.String()
}

func (o *opensuse) TemplateScript() string {
	return opensuseTemplate
}

func (o *opensuse) URLs(_ Config, kr kernelrelease.KernelRelease) ([]string, error) {

	// SUSE requires 2 urls: a kernel-default-devel*{arch}.rpm and a kernel-devel*noarch.rpm
	kernelDefaultDevelPattern := fmt.Sprintf("kernel-default-devel-%s%s.rpm", kr.Fullversion, kr.FullExtraversion)
	kernelDevelNoArchPattern := strings.ReplaceAll( // need to replace architecture string with "noarch"
		fmt.Sprintf("kernel-devel-%s%s.rpm", kr.Fullversion, kr.FullExtraversion),
		kr.Architecture.ToNonDeb(),
		"noarch",
	)

	// get all possible URLs
	possibleURLs := buildURLs(kr, kernelDefaultDevelPattern, kernelDevelNoArchPattern)

	// try to resolve the URLs
	urls, err := getResolvingURLs(possibleURLs)
	if err != nil {
		return nil, err
	}

	// ensure there is at least one URL of each required package type
	if validateURLs(urls, kernelDefaultDevelPattern, kernelDevelNoArchPattern) {
		return urls, nil
	} else {
		return nil, fmt.Errorf(
			"missing one of the required package types: [ kernel-default-devel, kernel-devel*noarch ]: %v",
			urls,
		)
	}
}

// build all possible url combinations from base URLs and releases
func buildURLs(kr kernelrelease.KernelRelease, kernelDefaultDevelPattern string, kernelDevelNoArchPattern string) []string {

	possibleURLs := []string{}
	for _, release := range releases {
		for _, baseURL := range baseURLs {

			possibleURLs = append(
				possibleURLs,
				// leap urls
				fmt.Sprintf(
					"%s/leap/%s/repo/oss/%s/%s",
					baseURL,
					release,
					kr.Architecture.ToNonDeb(),
					kernelDefaultDevelPattern,
				),
				fmt.Sprintf( // noarch
					"%s/leap/%s/repo/oss/noarch/%s",
					baseURL,
					release,
					kernelDevelNoArchPattern,
				),
				// other urls
				fmt.Sprintf(
					"%s/%s/repo/oss/%s/%s",
					baseURL,
					release,
					kr.Architecture.ToNonDeb(),
					kernelDefaultDevelPattern,
				),
				fmt.Sprintf( // noarch
					"%s/%s/repo/oss/noarch/%s",
					baseURL,
					release,
					kernelDevelNoArchPattern,
				),
				// weird opensuse site urls
				fmt.Sprintf(
					"%s/openSUSE-%s/Submit/standard/%s/%s",
					baseURL,
					release,
					kr.Architecture.ToNonDeb(),
					kernelDefaultDevelPattern,
				),
				fmt.Sprintf(
					"%s/openSUSE-%s/standard/%s/%s",
					baseURL,
					release,
					kr.Architecture.ToNonDeb(),
					kernelDefaultDevelPattern,
				),
				fmt.Sprintf(
					"%s/openSUSE-%s:/Submit/standard/%s/%s",
					baseURL,
					release,
					kr.Architecture.ToNonDeb(),
					kernelDefaultDevelPattern,
				),
				fmt.Sprintf(
					"%s/openSUSE-%s:/standard/%s/%s",
					baseURL,
					release,
					kr.Architecture.ToNonDeb(),
					kernelDefaultDevelPattern,
				),
				fmt.Sprintf(
					"%s/%s/Submit/standard/%s/%s",
					baseURL,
					release,
					kr.Architecture.ToNonDeb(),
					kernelDefaultDevelPattern,
				),
				fmt.Sprintf(
					"%s/%s/standard/%s/%s",
					baseURL,
					release,
					kr.Architecture.ToNonDeb(),
					kernelDefaultDevelPattern,
				),
				// weird opensuse site urls - kernel-devel*noarch edition
				fmt.Sprintf(
					"%s/openSUSE-%s/Submit/standard/noarch/%s",
					baseURL,
					release,
					kernelDevelNoArchPattern,
				),
				fmt.Sprintf(
					"%s/openSUSE-%s/standard/noarch/%s",
					baseURL,
					release,
					kernelDevelNoArchPattern,
				),
				fmt.Sprintf(
					"%s/openSUSE-%s:/Submit/standard/noarch/%s",
					baseURL,
					release,
					kernelDevelNoArchPattern,
				),
				fmt.Sprintf(
					"%s/openSUSE-%s:/standard/noarch/%s",
					baseURL,
					release,
					kernelDevelNoArchPattern,
				),
				fmt.Sprintf(
					"%s/%s/Submit/standard/noarch/%s",
					baseURL,
					release,
					kernelDevelNoArchPattern,
				),
				fmt.Sprintf(
					"%s/%s/standard/noarch/%s",
					baseURL,
					release,
					kernelDevelNoArchPattern,
				),
			)
		}
	}

	return possibleURLs
}

// check to ensure there is at least one URL of each package type
func validateURLs(urls []string, kernelDefaultDevelPattern string, kernelDevelNoArchPattern string) bool {

	// setup some flags
	kernelDefaultDevelFlag := false
	kernelDevelNoArchFlag := false

	for _, url := range urls {
		if strings.Contains(url, kernelDefaultDevelPattern) {
			kernelDefaultDevelFlag = true
		}
		if strings.Contains(url, kernelDevelNoArchPattern) {
			kernelDevelNoArchFlag = true
		}
	}

	return kernelDefaultDevelFlag && kernelDevelNoArchFlag

}

func (o *opensuse) TemplateData(cfg Config, kr kernelrelease.KernelRelease, urls []string) interface{} {
	return opensuseTemplateData{
		commonTemplateData: cfg.toTemplateData(o, kr),
		KernelDownloadURLs: urls,
	}
}
