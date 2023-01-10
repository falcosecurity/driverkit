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
	}
	if targetGCC.EQ(semver.Version{}) {
		targetGCC = defaultGCC(kr)
	}

	b.LoadImages()

	// If we are able to either find a specific-target image,
	// or "any" target image that provide desired gcc,
	// we are over.
	image, ok := b.Images.findImage(b.TargetType, targetGCC)
	if ok {
		b.GCCVersion = image.GCCVersion.String()
	}

	// List all images to find nearest gcc

	// Step 1:
	// Build the list of "proposed" GCC versions,
	// that is, the list of available gccs from images
	// for each builder image
	// whose target is the requested one
	// or the "any" one.
	proposedGCCs := make([]semver.Version, 0)
	for _, img := range b.Images {
		if img.Target == b.TargetType || img.Target.String() == "any" {
			proposedGCCs = append(proposedGCCs, img.GCCVersion)
			logger.WithField("image", img.Name).
				WithField("targetGCC", targetGCC.String()).
				Debug("proposedGCC=", img.GCCVersion.String())
		}
	}

	// Now, sort versions and fetch
	// the nearest gcc, that is also < targetGCC
	semver.Sort(proposedGCCs)
	lastGCC := proposedGCCs[0]
	for _, gcc := range proposedGCCs {
		if gcc.GT(targetGCC) {
			break
		}
		lastGCC = gcc
	}
	b.GCCVersion = lastGCC.String()
	logger.WithField("targetGCC", targetGCC.String()).
		Debug("foundGCC=", b.GCCVersion)
}

func (b *Build) GetBuilderImage() string {
	imageTag := "latest"
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

	// NOTE: here below we are already sure that we are going
	// to find an image, because setGCCVersion()
	// has already set an existent gcc version
	// (ie: one provided by an image) for us
	image, _ := b.Images.findImage(b.TargetType, mustParseTolerant(b.GCCVersion))
	return image.Name + ":" + imageTag
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
