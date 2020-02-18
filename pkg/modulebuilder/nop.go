package modulebuilder

import (
	"context"

	"github.com/falcosecurity/build-service/pkg/filesystem"
	"github.com/falcosecurity/build-service/pkg/modulebuilder/build"
	"go.uber.org/zap"
)

type NopBuildProcessor struct {
	ctx           context.Context
	logger        *zap.Logger
	modulestorage *filesystem.ModuleStorage
}

func NewNopBuildProcessor() *NopBuildProcessor {
	return &NopBuildProcessor{}
}

func (bp *NopBuildProcessor) WithContext(c context.Context) {
	bp.ctx = c
}

func (bp *NopBuildProcessor) WithLogger(logger *zap.Logger) {
	bp.logger = logger
}

func (bp *NopBuildProcessor) WithModuleStorage(ms *filesystem.ModuleStorage) {
	bp.modulestorage = ms
}

func (bp *NopBuildProcessor) String() string {
	return "no-op"
}

func (bp *NopBuildProcessor) Request(b build.Build) error {
	// just ignore everything
	return nil
}

func (bp *NopBuildProcessor) Start() error {
	// I don't do anything and just sit here pretending I'm working
	// but I'm Nop so that's what I do!
	for {
		select {
		case <-bp.ctx.Done():
			return nil
		default:
			continue
		}
	}
}
