package builder

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/blang/semver"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"log"
	"net/http"
	"net/url"
	"path"
	"strings"
	"text/template"

	logger "github.com/sirupsen/logrus"
)

var BaseImage = "placeholder" // This is overwritten when using the Makefile to build

// DriverDirectory is the directory the processor uses to store the driver.
const DriverDirectory = "/tmp/driver"

// ModuleFileName is the standard file name for the kernel module.
const ModuleFileName = "module.ko"

// ProbeFileName is the standard file name for the eBPF probe.
const ProbeFileName = "probe.o"

// ModuleFullPath is the standard path for the kernel module. Builders must place the compiled module at this location.
var ModuleFullPath = path.Join(DriverDirectory, ModuleFileName)

// ProbeFullPath is the standard path for the eBPF probe. Builders must place the compiled probe at this location.
var ProbeFullPath = path.Join(DriverDirectory, "bpf", ProbeFileName)

var HeadersNotFoundErr = errors.New("kernel headers not found")

// Config contains all the configurations needed to build the kernel module or the eBPF probe.
type Config struct {
	DriverName      string
	DeviceName      string
	DownloadBaseURL string
	*Build
}

type commonTemplateData struct {
	DriverBuildDir    string
	ModuleDownloadURL string
	ModuleDriverName  string
	ModuleFullPath    string
	BuildModule       bool
	BuildProbe        bool
	GCCVersion        string
}

// Builder represents a builder capable of generating a script for a driverkit target.
type Builder interface {
	Name() string
	TemplateScript() string
	URLs(c Config, kr kernelrelease.KernelRelease) ([]string, error)
	TemplateData(c Config, kr kernelrelease.KernelRelease, urls []string) interface{} // error return type is managed
}

// MinimumURLsBuilder is an optional interface
// to specify minimum number of requested headers urls
type MinimumURLsBuilder interface {
	MinimumURLs() int
}

func Script(b Builder, c Config, kr kernelrelease.KernelRelease) (string, error) {
	t := template.New(b.Name())
	parsed, err := t.Parse(b.TemplateScript())
	if err != nil {
		return "", err
	}

	minimumURLs := 1
	if bb, ok := b.(MinimumURLsBuilder); ok {
		minimumURLs = bb.MinimumURLs()
	}

	var urls []string
	if c.KernelUrls == nil {
		urls, err = b.URLs(c, kr)
		if err != nil {
			return "", err
		}
		// Only if returned urls array is not empty
		// Otherwise, it is up to the builder to return an error
		if len(urls) > 0 {
			// Check (and filter) existing kernels before continuing
			urls, err = getResolvingURLs(urls)
		}
	} else {
		urls, err = getResolvingURLs(c.KernelUrls)
	}
	if err != nil {
		return "", err
	}

	if len(urls) < minimumURLs {
		return "", fmt.Errorf("not enough headers packages found; expected %d, found %d", minimumURLs, len(urls))
	}

	td := b.TemplateData(c, kr, urls)
	if tdErr, ok := td.(error); ok {
		return "", tdErr
	}

	buf := bytes.NewBuffer(nil)
	err = parsed.Execute(buf, td)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

type GCCVersionRequestor interface {
	GCCVersion(kr kernelrelease.KernelRelease) semver.Version
}

type Image struct {
	GCCVersion map[kernelrelease.Architecture][]string
}

// We cannot use semver.Version here, because we need to know the
// actual gcc-$version string that will be used by template scripts,
// like: make CC=/usr/bin/gcc-{{ .GCCVersion }}
// When using semver.Version, gcc like semver.Version { Major: 5 }.String() -> "5.0.0"
// and that would break our scripts, because the real name is just "5"
var images = map[string]Image{
	"buster": {
		GCCVersion: map[kernelrelease.Architecture][]string{
			kernelrelease.ArchitectureAmd64: {"4.8", "4.9", "5", "6", "8"},
			kernelrelease.ArchitectureArm64: {"4.8", "5", "6", "8"}, // 4.9 is not present on arm64
		},
	},
	"bullseye": {
		GCCVersion: map[kernelrelease.Architecture][]string{
			kernelrelease.ArchitectureAmd64: {"9", "10"},
			kernelrelease.ArchitectureArm64: {"9", "10"},
		},
	},
	"bookworm": {
		GCCVersion: map[kernelrelease.Architecture][]string{
			kernelrelease.ArchitectureAmd64: {"11", "12"},
			kernelrelease.ArchitectureArm64: {"11", "12"},
		},
	},
}

func defaultGCC(kr kernelrelease.KernelRelease) semver.Version {
	switch kr.Major {
	case 5:
		if kr.Minor >= 18 {
			return semver.Version{Major: 12}
		}
		return semver.Version{Major: 11}
	case 4:
		return semver.Version{Major: 8}
	case 3:
		if kr.Minor >= 18 {
			return semver.Version{Major: 5}
		}
		return semver.Version{Major: 4, Minor: 9}
	case 2:
		return semver.Version{Major: 4, Minor: 8}
	default:
		return semver.Version{Major: 12}
	}
}

func mustParseTolerant(gccStr string) semver.Version {
	g, err := semver.ParseTolerant(gccStr)
	if err != nil {
		panic(err)
	}
	return g
}

// Simple algorithm:
// sort versions passed as first params,
// then, find the higher gcc version which is also lower than target.
// Moreover, try harder to keep same major gcc version.
func findNearestGCCVersion(gccs []semver.Version, target semver.Version) semver.Version {
	semver.Sort(gccs)
	foundGCC := gccs[0]
	for _, gcc := range gccs {
		if gcc.GT(target) {
			// Be smarter trying to find the proper gcc version
			if gcc.Major == target.Major && foundGCC.Major < target.Major {
				foundGCC = gcc
			}
			break
		}
		foundGCC = gcc
	}
	return foundGCC
}

// Given an image, returns the list of semvers for its supported gccs
func buildGCCSemvers(img Image, arch kernelrelease.Architecture) []semver.Version {
	gccs := make([]semver.Version, 0)
	for _, gccStr := range img.GCCVersion[arch] {
		gccs = append(gccs, mustParseTolerant(gccStr))
	}
	return gccs
}

func (b *Build) setGCCVersion(builder Builder, kr kernelrelease.KernelRelease) {
	if len(b.GCCVersion) > 0 {
		// If set from user, go on
		return
	}

	b.GCCVersion = "8" // default value

	// if builder implements "GCCVersionRequestor" interface -> use it
	// Else, fetch the best builder available from the kernelrelease version
	// using the deadly simple defaultGCC() algorithm
	// Always returns the nearest one
	var targetGCC semver.Version
	if bb, ok := builder.(GCCVersionRequestor); ok {
		targetGCC = bb.GCCVersion(kr)
	} else {
		targetGCC = defaultGCC(kr)
	}

	// Build the list of "proposed" GCC versions,
	// that is, the nearest-to-target GCC version
	// for each builder image.
	proposedGCCs := make([]semver.Version, 0)
	for name, img := range images {
		gccs := buildGCCSemvers(img, kr.Architecture)
		foundGCC := findNearestGCCVersion(gccs, targetGCC)
		proposedGCCs = append(proposedGCCs, foundGCC)
		logger.WithField("image", name).
			WithField("targetGCC", targetGCC.String()).
			Debug("proposedGCC=", foundGCC.String())
	}

	// Now, find the nearest-to-target GCC version
	// from the proposed GCCs from the builder images.
	foundGCC := findNearestGCCVersion(proposedGCCs, targetGCC)

	// Finally, discover the right gcc version string
	// for the final GCC that will be used by scripts.
	for _, img := range images {
		for _, gccStr := range img.GCCVersion[kr.Architecture] {
			gccSemVer := mustParseTolerant(gccStr)
			if gccSemVer.EQ(foundGCC) {
				b.GCCVersion = gccStr
			}
		}
	}

	logger.WithField("targetGCC", targetGCC.String()).
		Debug("foundGCC=", b.GCCVersion)
}

func (b *Build) GetBuilderImage() string {
	var imageTag string

	fmt.Println("len(b.CustomBuilderImage)=", len(b.CustomBuilderImage))

	// One can pass "auto:tag/latest" to choose the automatic
	// image selection but forcing an imagetag
	if len(b.CustomBuilderImage) > 0 {
		customNames := strings.Split(b.CustomBuilderImage, ":")
		if customNames[0] != "auto" {
			// CustomBuilderImage MUST have requested GCC installed inside
			return b.CustomBuilderImage
		}

		// Updated image tag if "auto:tag" is passed
		if len(customNames) > 1 {
			imageTag = customNames[1]
		} else {
			imageTag = "latest"
		}
	}

	// A bit complicated because we must check that
	// "auto:tag" custom builder image was not passed
	builderImage := BaseImage
	names := strings.Split(builderImage, ":")
	// Updated image tag if no "auto" custom builder image was passed
	if imageTag == "" {
		if len(names) > 1 {
			imageTag = names[1]
		} else {
			imageTag = "latest"
		}
	}

	for name, img := range images {
		for _, gccStr := range img.GCCVersion[kernelrelease.Architecture(b.Architecture)] {
			if gccStr == b.GCCVersion {
				return names[0] + "_" + name + ":" + imageTag
			}
		}
	}
	return builderImage
}

// Factory returns a builder for the given target.
func Factory(target Type) (Builder, error) {
	b, ok := BuilderByTarget[target]
	if !ok {
		return nil, fmt.Errorf("no builder found for target: %s", target)
	}
	return b, nil
}

func (c Config) toTemplateData(b Builder, kr kernelrelease.KernelRelease) commonTemplateData {
	c.setGCCVersion(b, kr)
	return commonTemplateData{
		DriverBuildDir:    DriverDirectory,
		ModuleDownloadURL: fmt.Sprintf("%s/%s.tar.gz", c.DownloadBaseURL, c.DriverVersion),
		ModuleDriverName:  c.DriverName,
		ModuleFullPath:    ModuleFullPath,
		BuildModule:       len(c.ModuleFilePath) > 0,
		BuildProbe:        len(c.ProbeFilePath) > 0,
		GCCVersion:        c.GCCVersion,
	}
}

func resolveURLReference(u string) string {
	uu, err := url.Parse(u)
	if err != nil {
		log.Fatal(err)
	}
	base, err := url.Parse(uu.Host)
	if err != nil {
		log.Fatal(err)
	}
	return base.ResolveReference(uu).String()
}

func getResolvingURLs(urls []string) ([]string, error) {
	var results []string
	for _, u := range urls {
		// in case url has some relative paths
		// (kernel-crawler does not resolve them for us,
		// neither it is expected, because they are effectively valid urls),
		// resolve the absolute one.
		// HEAD would fail otherwise.
		u = resolveURLReference(u)
		res, err := http.Head(u)
		if err != nil {
			continue
		}
		if res.StatusCode == http.StatusOK {
			results = append(results, u)
			logger.WithField("url", u).Debug("kernel header url found")
		}
	}
	if len(results) == 0 {
		return nil, HeadersNotFoundErr
	}
	return results, nil
}
