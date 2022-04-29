package driverbuilder

import (
	"github.com/falcosecurity/driverkit/pkg/driverbuilder/builder"
)

var BuilderBaseImage = "falcosecurity/driverkit-builder:latest" // This is overwritten when using the Makefile to build

type BuildProcessor interface {
	Start(b *builder.Build) error
	String() string
}
