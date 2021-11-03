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
const ModuleFileName = "module.ko"

// ProbeFileName is the standard file name for the eBPF probe.
const ProbeFileName = "probe.o"

// ModuleFullPath is the standard path for the kernel module. Builders must place the compiled module at this location.
var ModuleFullPath = path.Join(DriverDirectory, ModuleFileName)

// ProbeFullPath is the standard path for the eBPF probe. Builders must place the compiled probe at this location.
var ProbeFullPath = path.Join(DriverDirectory, "bpf", ProbeFileName)

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
