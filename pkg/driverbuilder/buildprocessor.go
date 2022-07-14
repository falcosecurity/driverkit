package driverbuilder

import (
	"github.com/falcosecurity/driverkit/pkg/driverbuilder/builder"
)

type BuildProcessor interface {
	Start(b *builder.Build) error
	String() string
}
