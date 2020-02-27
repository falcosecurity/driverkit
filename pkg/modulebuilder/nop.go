package modulebuilder

import (
	"github.com/falcosecurity/driverkit/pkg/modulebuilder/build"
	"go.uber.org/zap"
)

type NopBuildProcessor struct {
}

func NewNopBuildProcessor() *NopBuildProcessor {
	return &NopBuildProcessor{}
}

func (bp *NopBuildProcessor) WithLogger(logger *zap.Logger) {
}

func (bp *NopBuildProcessor) String() string {
	return "no-op"
}

func (bp *NopBuildProcessor) Start(b build.Build) error {
	return nil
}
