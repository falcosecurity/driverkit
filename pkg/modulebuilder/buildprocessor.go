package modulebuilder

import (
	"context"
	"go.uber.org/zap"
)

type BuildType string
const (
	 BuildTypeVanilla BuildType = "vanilla"
	// BuildTypeCentOS BuildType = "centos" // not implemented
	// BuildTypeCoreOS BuildType = "coreos" // Not implemented
	// BuildTypeFedora BuildType = "fedora"  // Not implemented
	// BuildTypeUbuntu BuildType = "ubuntu"  // Not implemented
	// BuildTypeDebian BuildType = "debian"  // Not implemented
)

type Build struct {
	BuildType        BuildType
	KernelConfigData string
	KernelVersion    string
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
	// but I'm Nop so taht's what I do!
	for {
		select {
		case <-bp.ctx.Done():
			return nil
		default:
			continue
		}
	}
}
