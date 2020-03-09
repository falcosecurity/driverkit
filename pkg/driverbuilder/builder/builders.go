package builder

import (
	"fmt"
	"net/http"
	"path"

	"github.com/sirupsen/logrus"
)

// DriverDirectory is the directory the processor uses to store the driver.
const DriverDirectory = "/tmp/driver"

// ModuleFileName is the standard file name for the kernel module.
const ModuleFileName = "falco.ko"

// ProbeFileName is the standard file name for the eBPF probe.
const ProbeFileName = "probe.o"

// FalcoModuleFullPath is the standard path for the kernel module.
var FalcoModuleFullPath = path.Join(DriverDirectory, ModuleFileName)

// FalcoProbeFullPath is the standard path for the eBPF probe.
var FalcoProbeFullPath = path.Join(DriverDirectory, "bpf", ProbeFileName)

// Config contains all the configurations needed to build the kernel module or the eBPF probe.
type Config struct {
	DriverName      string
	DeviceName      string
	DownloadBaseURL string
	*Build
}

// Builder represents a builder capable of generating a script for a driverkit target.
type Builder interface {
	Script(c Config) (string, error)
}

// Factory returns a builder for the given target.
func Factory(target Type) (Builder, error) {
	b, ok := BuilderByTarget[target]
	if !ok {
		return nil, fmt.Errorf("no builder found for target: %s", target)
	}
	return b, nil
}

func moduleDownloadURL(c Config) string {
	return fmt.Sprintf("%s/%s.tar.gz", c.DownloadBaseURL, c.DriverVersion)
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
