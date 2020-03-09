package driverbuilder

import (
	"github.com/falcosecurity/driverkit/pkg/driverbuilder/build"
)

type NopBuildProcessor struct {
}

func NewNopBuildProcessor() *NopBuildProcessor {
	return &NopBuildProcessor{}
}

func (bp *NopBuildProcessor) String() string {
	return "no-op"
}

func (bp *NopBuildProcessor) Start(b *build.Build) error {
	return nil
}
