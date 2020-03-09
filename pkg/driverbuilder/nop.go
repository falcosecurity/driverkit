package driverbuilder

import "github.com/falcosecurity/driverkit/pkg/driverbuilder/builder"

type NopBuildProcessor struct {
}

func NewNopBuildProcessor() *NopBuildProcessor {
	return &NopBuildProcessor{}
}

func (bp *NopBuildProcessor) String() string {
	return "no-op"
}

func (bp *NopBuildProcessor) Start(b *builder.Build) error {
	return nil
}
