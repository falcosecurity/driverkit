package builder

import (
	_ "embed"
	"fmt"
	"github.com/blang/semver"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"io/ioutil"
	"net/http"
	"strings"
)

//go:embed templates/flatcar.sh
var flatcarTemplate string

// TargetTypeFlatcar identifies the Flatcar target.
const TargetTypeFlatcar Type = "flatcar"

func init() {
	BuilderByTarget[TargetTypeFlatcar] = &flatcar{}
}

type flatcarTemplateData struct {
	commonTemplateData
	KernelDownloadURL string
}

// flatcar is a driverkit target.
type flatcar struct {
	info *flatcarReleaseInfo
}

func (f *flatcar) Name() string {
	return TargetTypeFlatcar.String()
}

func (f *flatcar) TemplateScript() string {
	return flatcarTemplate
}

func (f *flatcar) URLs(_ Config, kr kernelrelease.KernelRelease) ([]string, error) {
	if err := f.fillFlatcarInfos(kr); err != nil {
		return nil, err
	}
	return fetchFlatcarKernelURLS(f.info.KernelVersion), nil
}

func (f *flatcar) TemplateData(c Config, kr kernelrelease.KernelRelease, urls []string) interface{} {
	// This happens when `kernelurls` option is passed,
	// therefore URLs() method is not called.
	if f.info == nil {
		if err := f.fillFlatcarInfos(kr); err != nil {
			return err
		}
	}

	return flatcarTemplateData{
		commonTemplateData: c.toTemplateData(f, kr),
		KernelDownloadURL:  urls[0],
	}
}

func (f *flatcar) GCCVersion(_ kernelrelease.KernelRelease) semver.Version {
	return f.info.GCCVersion
}

func (f *flatcar) fillFlatcarInfos(kr kernelrelease.KernelRelease) error {
	if kr.Extraversion != "" {
		return fmt.Errorf("unexpected extraversion: %s", kr.Extraversion)
	}

	// convert string to int
	if kr.Major < 1500 {
		return fmt.Errorf("not a valid flatcar release version: %d", kr.Major)
	}

	var err error
	f.info, err = fetchFlatcarMetadata(kr)
	return err
}

func fetchFlatcarKernelURLS(kernelVersion string) []string {
	kv := kernelrelease.FromString(kernelVersion)
	return []string{fetchVanillaKernelURLFromKernelVersion(kv)}
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
	flatcarInfo.GCCVersion = semver.MustParse(gccVersion)
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

type flatcarReleaseInfo struct {
	Channel       string
	GCCVersion    semver.Version
	KernelVersion string
}
