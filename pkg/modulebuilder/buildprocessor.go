package modulebuilder

import (
	"context"

	"github.com/asaskevich/govalidator"
	"github.com/falcosecurity/build-service/pkg/modulebuilder/builder"
	"go.uber.org/zap"
)

type Build struct {
	BuildType        builder.BuildType `valid:"buildtype"`
	KernelConfigData string
	KernelVersion    string
	// only architecture supported is x86_64 now, if you want to add one, just add it:
	// e.g: in(x86_64|ppcle64|armv7hf)
	Architecture string `valid:"in(x86_64)"`
}

func (b *Build) Validate() (bool, error) {
	return govalidator.ValidateStruct(b)
}

type BuildProcessor interface {
	Start() error
	Request(b Build) error
	WithContext(c context.Context)
	WithLogger(logger *zap.Logger)
	String() string
}

type NopBuildProcessor struct {
	ctx    context.Context
	logger *zap.Logger
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

func (bp *NopBuildProcessor) String() string {
	return "no-op"
}

func (bp *NopBuildProcessor) Request(b Build) error {
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
