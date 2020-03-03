package modulebuilder

import (
	"github.com/falcosecurity/driverkit/pkg/modulebuilder/build"
)

type BuildArchitecture string

const BuildArchitectureX86_64 BuildArchitecture = "x86_64"

func (ba BuildArchitecture) String() string {
	return string(ba)
}

var EnabledBuildArchitectures = map[BuildArchitecture]bool{}

func init() {
	EnabledBuildArchitectures[BuildArchitectureX86_64] = true
}

type BuildProcessor interface {
	Start(b *build.Build) error
	String() string
}
