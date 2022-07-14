package builder

import (
	_ "embed"
	"fmt"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
)

//go:embed templates/debian.sh
var debianTemplate string

// TargetTypeDebian identifies the Debian target.
const TargetTypeDebian Type = "debian"

// We need:
// kernel devel
// kernel devel common
// kbuild package
const debianRequiredURLs = 3

func init() {
	BuilderByTarget[TargetTypeDebian] = &debian{}
}

type debianTemplateData struct {
	commonTemplateData
	KernelDownloadURLS []string
	KernelLocalVersion string
	KernelArch         string
}

// debian is a driverkit target.
type debian struct {
}

func (v debian) Name() string {
	return TargetTypeDebian.String()
}

func (v debian) TemplateScript() string {
	return debianTemplate
}

func (v debian) URLs(_ Config, kr kernelrelease.KernelRelease) ([]string, error) {
	return fetchDebianKernelURLs(kr)
}

func (v debian) TemplateData(c Config, kr kernelrelease.KernelRelease, urls []string) interface{} {
	return debianTemplateData{
		commonTemplateData: c.toTemplateData(),
		KernelDownloadURLS: urls,
		KernelLocalVersion: kr.FullExtraversion,
		KernelArch:         kr.Architecture.String(),
	}
}

func (v debian) MinimumURLs() int {
	return debianRequiredURLs
}

func fetchDebianKernelURLs(kr kernelrelease.KernelRelease) ([]string, error) {
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

	return nil, HeadersNotFoundErr
}

func fetchDebianHeadersURLFromRelease(baseURL string, kr kernelrelease.KernelRelease) ([]string, error) {
	extraVersionPartial := strings.TrimSuffix(kr.FullExtraversion, "-"+kr.Architecture.String())
	matchExtraGroup := kr.Architecture.String()
	rmatch := `href="(linux-headers-%d\.%d\.%d%s-(%s)_.*(%s|all)\.deb)"`

	// For urls like: http://security.debian.org/pool/updates/main/l/linux/linux-headers-5.10.0-12-amd64_5.10.103-1_amd64.deb
	// when 5.10.103-1 is passed as kernel version
	rmatchNew := `href="(linux-headers-[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-(%s)_%d\.%d\.%d%s_(%s|all)\.deb)"`

	matchExtraGroupCommon := "common"

	// match for kernel versions like 4.19.0-6-cloud-amd64
	if strings.Contains(kr.FullExtraversion, "-cloud") {
		extraVersionPartial = strings.TrimSuffix(extraVersionPartial, "-cloud")
		matchExtraGroup = "cloud-" + matchExtraGroup
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
	fullregex := fmt.Sprintf(rmatch, kr.Version, kr.PatchLevel, kr.Sublevel,
		extraVersionPartial, matchExtraGroup, kr.Architecture.String())
	pattern := regexp.MustCompile(fullregex)
	matches := pattern.FindStringSubmatch(bodyStr)
	if len(matches) < 1 {
		fullregex = fmt.Sprintf(rmatchNew, matchExtraGroup, kr.Version, kr.PatchLevel, kr.Sublevel,
			extraVersionPartial, kr.Architecture.String())
		pattern = regexp.MustCompile(fullregex)
		matches = pattern.FindStringSubmatch(bodyStr)
		if len(matches) < 1 {
			return nil, fmt.Errorf("kernel headers not found")
		}
	}

	// look for kernel headers common
	fullregexCommon := fmt.Sprintf(rmatch, kr.Version, kr.PatchLevel, kr.Sublevel,
		extraVersionPartial, matchExtraGroupCommon, kr.Architecture.String())
	patternCommon := regexp.MustCompile(fullregexCommon)
	matchesCommon := patternCommon.FindStringSubmatch(bodyStr)
	if len(matchesCommon) < 1 {
		fullregexCommon = fmt.Sprintf(rmatchNew, matchExtraGroupCommon, kr.Version, kr.PatchLevel, kr.Sublevel,
			extraVersionPartial, kr.Architecture.String())
		patternCommon = regexp.MustCompile(fullregexCommon)
		matchesCommon = patternCommon.FindStringSubmatch(bodyStr)
		if len(matchesCommon) < 1 {
			return nil, fmt.Errorf("kernel headers common not found")
		}
	}

	foundURLs := []string{fmt.Sprintf("%s%s", baseURL, matches[1])}
	foundURLs = append(foundURLs, fmt.Sprintf("%s%s", baseURL, matchesCommon[1]))

	return foundURLs, nil
}

func debianKbuildURLFromRelease(kr kernelrelease.KernelRelease) (string, error) {
	rmatch := `href="(linux-kbuild-%d\.%d.*%s\.deb)"`

	kbuildPattern := regexp.MustCompile(fmt.Sprintf(rmatch, kr.Version, kr.PatchLevel, kr.Architecture.String()))
	baseURL := "http://mirrors.kernel.org/debian/pool/main/l/linux/"
	if kr.Version == 3 {
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
