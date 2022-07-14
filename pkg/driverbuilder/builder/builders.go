package builder

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"log"
	"math"
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
	GCCVersion        float64
}

// Builder represents a builder capable of generating a script for a driverkit target.
type Builder interface {
	Name() string
	TemplateScript() string
	URLs(c Config, kr kernelrelease.KernelRelease) ([]string, error)
	TemplateData(c Config, kr kernelrelease.KernelRelease, urls []string) interface{}
}

// MinimumURLsBuilder is an optional interface
// to specify minimum number of requested headers urls
type MinimumURLsBuilder interface {
	MinimumURLs() int
}

func Script(b Builder, c Config, kr kernelrelease.KernelRelease) (string, error) {
	c.SetGCCVersion(b, kr)

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
	buf := bytes.NewBuffer(nil)
	err = parsed.Execute(buf, td)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

type GCCVersionRequestor interface {
	GCCVersion(kr kernelrelease.KernelRelease) float64
}

type Image struct {
	GCCVersion []float64
}

var images = map[string]Image{
	"buster": {
		GCCVersion: []float64{4.8, 5.5, 6.3, 8},
	},
	"bullseye": {
		GCCVersion: []float64{9, 10},
	},
	"bookworm": {
		GCCVersion: []float64{11, 12},
	},
}

func defaultGCC(kr kernelrelease.KernelRelease) float64 {
	switch kr.Version {
	case 5:
		if kr.PatchLevel > 10 {
			return 11
		}
		if kr.PatchLevel > 18 {
			return 12
		}
		return 10
	case 4:
		return 8
	case 3:
		return 5
	case 2:
		return 4.8
	default:
		return 10
	}
}

func (b *Build) SetGCCVersion(builder Builder, kr kernelrelease.KernelRelease) {
	b.GCCVersion = 8 // default value

	distance := math.MaxFloat64

	// if builder implements "GCCVersionRequestor" interface -> use it
	// Else, fetch the best builder available from the kernelrelease version
	// using the deadly simple defaultGCC() algorithm
	// Always returns nearest one
	var targetGCC float64
	if bb, ok := builder.(GCCVersionRequestor); ok {
		targetGCC = bb.GCCVersion(kr)
	} else {
		targetGCC = defaultGCC(kr)
	}

	for _, img := range images {
		var gcc float64
		d := math.MaxFloat64
		for _, gcc = range img.GCCVersion {
			if gcc-targetGCC < d {
				// Find the nearest to targetGCC
				// for this image
				d = gcc - targetGCC
			}
		}

		if d < distance {
			b.GCCVersion = gcc
			distance = d
		}
	}
}

func (b *Build) GetBuilderImage() string {
	if len(b.CustomBuilderImage) > 0 {
		return b.CustomBuilderImage
	}
	builderImage := BaseImage
	names := strings.SplitAfter(builderImage, ":")
	// If no version
	if len(names) == 1 {
		names = append(names, "latest")
	}
	for name, img := range images {
		for _, gcc := range img.GCCVersion {
			if gcc == b.GCCVersion {
				return names[0] + "_" + name + ":" + names[1]
			}
		}
	}
	return ""
}

// Factory returns a builder for the given target.
func Factory(target Type) (Builder, error) {
	b, ok := BuilderByTarget[target]
	if !ok {
		return nil, fmt.Errorf("no builder found for target: %s", target)
	}
	return b, nil
}

func (c Config) toTemplateData() commonTemplateData {
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
