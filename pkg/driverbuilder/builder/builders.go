package builder

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/blang/semver"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"log"
	"net/http"
	"net/url"
	"path"
	"regexp"
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

func loadImages() map[string]Image {
	var nameReg = regexp.MustCompile("^falcosecurity/driverkit-builder-(?P<target>[a-z0-9]+)-(?P<arch>x86_64|aarch64)(?P<gccVers>(_gcc[0-9].[0-9].[0-9])+)$")
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		log.Fatal(err)
	}
	imgs, err := cli.ImageSearch(context.Background(), "falcosecurity/driverkit-", types.ImageSearchOptions{Limit: 100})
	if err != nil {
		log.Fatal(err)
	}
	images := make(map[string]Image)
	for _, img := range imgs {
		match := nameReg.FindStringSubmatch(img.Name)
		var gccVers []string
		var target string
		var arch string
		for i, name := range nameReg.SubexpNames() {
			if i > 0 && i <= len(match) {
				switch name {
				case "target":
					target = match[i]
				case "arch":
					arch = match[i]
				case "gccVers":
					gccVers = strings.Split(match[i], "_gcc")
				}
			}
		}

		if len(target) == 0 || len(arch) == 0 || len(gccVers) == 0 {
			logger.Warn("Malformed image name: ", img.Name)
			continue
		}

		typeTarget := Type(target)
		if _, ok := BuilderByTarget[typeTarget]; !ok && target != "any" {
			logger.Warn("Skipping builder image for unsupported target: ", target)
			continue
		}

		for _, gccVer := range gccVers {
			buildImage := Image{
				Target:     typeTarget,
				Arch:       kernelrelease.Architecture(arch),
				GCCVersion: mustParseTolerant(gccVer),
				Name:       img.Name,
			}
			images[buildImage.toKey()] = buildImage
		}
	}
	return images
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

	b.Images = loadImages()

	targetImage := Image{
		Target:     b.TargetType,
		Arch:       kr.Architecture,
		GCCVersion: targetGCC,
	}

	// Try to find specific image for specific target first
	if img, ok := b.Images[targetImage.toKey()]; ok {
		b.GCCVersion = img.GCCVersion.String()
		return
	}

	// Fallback at "any" target that offers specific gcc
	targetImage.Target = "any"
	if img, ok := b.Images[targetImage.toKey()]; ok {
		b.GCCVersion = img.GCCVersion.String()
		return
	}

	// Finally: list all images to find nearest gcc

	// Step 1:
	// Build the list of "proposed" GCC versions,
	// that is, the list of available gccs from images
	// for each builder image.
	proposedGCCs := make([]semver.Version, 0)
	for _, img := range b.Images {
		if img.Arch != kr.Architecture {
			continue
		}
		proposedGCCs = append(proposedGCCs, img.GCCVersion)
		logger.WithField("image", img.Name).
			WithField("targetGCC", targetGCC.String()).
			Debug("proposedGCC=", img.GCCVersion.String())
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
	var imageTag string

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
	var builderImage string

	if len(b.CustomBuilderImageBase) != 0 {
		builderImage = b.CustomBuilderImageBase
	} else {
		builderImage = BaseImage
	}

	names := strings.Split(builderImage, ":")
	// Updated image tag if no "auto" custom builder image was passed
	if imageTag == "" {
		if len(names) > 1 {
			imageTag = names[1]
		} else {
			imageTag = "latest"
		}
	}

	// Try to find target specific given targetGCC
	targetImage := Image{
		Target:     b.TargetType,
		Arch:       kernelrelease.Architecture(b.Architecture),
		GCCVersion: mustParseTolerant(b.GCCVersion),
	}
	if image, ok := b.Images[targetImage.toKey()]; ok {
		return image.Name
	}

	// Fallback at "any"
	targetImage.Target = "any"
	return b.Images[targetImage.toKey()].Name
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
