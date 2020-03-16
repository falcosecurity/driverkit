package driverbuilder

import (
	"github.com/falcosecurity/driverkit/pkg/driverbuilder/builder"
)

type BuildArchitecture string

const BuildArchitectureX86_64 BuildArchitecture = "x86_64"

var builderBaseImage = "falcosecurity/driverkit-builder:latest" // This is overwritten when using the Makefile to build

func (ba BuildArchitecture) String() string {
	return string(ba)
}

var EnabledBuildArchitectures = map[BuildArchitecture]bool{}

func init() {
	EnabledBuildArchitectures[BuildArchitectureX86_64] = true
}

type BuildProcessor interface {
	Start(b *builder.Build) error
	String() string
}
