# Module Builder

This is the component that takes care of preparing the kernel sources and building the module.

TODO:
- [x] Implement a local builder
- [ ] Implement a builder in a container using the docker daemon
- [ ] Iplement a remote builder using kubernetes

## Local builder Usage example

```go
package main

import (
	"bytes"
	"compress/gzip"
	"log"
	"os"

	"github.com/falcosecurity/build-service/pkg/modulebuilder"
)

func main() {
	localCfgFile, err := os.Open("/proc/config.gz")
	if err != nil {
		log.Fatal(err)
	}
	zr, err := gzip.NewReader(localCfgFile)
	if err != nil {
		log.Fatal(err)
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(zr)
	configStr := buf.String()

	builder := modulebuilder.NewLocalBuilderFromConfig(modulebuilder.Config{
		KernelDir:        "/tmp/linux-src-5.5.2",
		KernelVersion:    "5.5.2-arch1-1",
		ModuleDir:        "/tmp/driver-src",
		ModuleName:       "falco",
		DeviceName:       "falco",
		ModuleVersion:    "0.19.0",
		KernelConfigData: configStr,
	})

	err = builder.Build()
	if err != nil {
		log.Fatal(err)
	}
}

```

## Docker builder Usage example

```go
TODO: example here
```
