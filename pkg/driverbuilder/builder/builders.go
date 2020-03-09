package builder

import (
	"fmt"
	"net/http"
	"path"

	buildmeta "github.com/falcosecurity/driverkit/pkg/driverbuilder/build"
	"github.com/falcosecurity/driverkit/pkg/driverbuilder/buildtype"
	"github.com/sirupsen/logrus"
)

// DriverDirectory is the directory the processor uses to store the driver.
const DriverDirectory = "/tmp/module"

// ModuleFileName is the standard file name for the kernel module.
const ModuleFileName = "falco.ko"

// ProbeFileName is the standard file name for the eBPF probe.
const ProbeFileName = "probe.o"

// FalcoModuleFullPath is the standard path for the kernel module.
var FalcoModuleFullPath = path.Join(DriverDirectory, ModuleFileName)

// FalcoProbeFullPath is the standard path for the eBPF probe.
var FalcoProbeFullPath = path.Join(DriverDirectory, "bpf", ProbeFileName)

// BuilderConfig contains all the configurations needed to build the kernel module or the eBPF probe.
type BuilderConfig struct {
	ModuleConfig ModuleConfig
	Build        *buildmeta.Build
}

type ModuleConfig struct {
	ModuleName      string
	DeviceName      string
	DownloadBaseURL string
}

type Builder interface {
	Script(bc BuilderConfig) (string, error)
}

func Factory(buildType buildtype.BuildType) (Builder, error) {
	// TODO(fntlnz): avoid duplicating this information, we already know which ones are enabled
	// look at buildtype.EnabledBuildTypes
	switch buildType {
	case BuildTypeVanilla:
		return &Vanilla{}, nil
	case BuildTypeUbuntuGeneric:
		return &UbuntuGeneric{}, nil
	case BuildTypeUbuntuAWS:
		return &UbuntuAWS{}, nil
	case BuildTypeCentos:
		return &Centos{}, nil
	case BuildTypeDebian:
		return &Debian{}, nil
	}
	return nil, fmt.Errorf("build type not found: %s", buildType)
}

func moduleDownloadURL(bc BuilderConfig) string {
	return fmt.Sprintf("%s/%s.tar.gz", bc.ModuleConfig.DownloadBaseURL, bc.Build.DriverVersion)
}

func getResolvingURLs(urls []string) ([]string, error) {
	results := []string{}
	for _, u := range urls {
		res, err := http.Head(u)
		if err != nil {
			continue
		}
		if res.StatusCode == http.StatusOK {
			results = append(results, u)
			logrus.WithField("url", u).Debug("kernel header url found")
		}
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("kernel not found")
	}
	return results, nil
}
