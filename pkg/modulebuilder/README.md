# Module Builder

## Usage example

```go
package main

import (
	"log"

	"github.com/falcosecurity/build-service/pkg/modulebuilder"
)

func main() {
	builder := modulebuilder.NewFromConfig(modulebuilder.Config{
		KernelBuildDir: "/lib/modules/5.5.2-arch1-1/build",
		KernelVersion:  "5.5.2-arch1-1",
		ModuleDir:      "/tmp/driver-src",
		ModuleName:     "falco",
		DeviceName:     "falco",
		ModuleVersion:  "0.19.0",
	})

	err := builder.Build()
	if err != nil {
		log.Fatal(err)
	}
}
```
