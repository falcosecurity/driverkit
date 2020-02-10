package modulebuilder

import (
	"context"
	"fmt"

	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
)

const (
	BuildTypeVanilla = "vanilla"
	// BuildTypeCentOS  = "centos" // not implemented
	// BuildTypeCoreOS  = "coreos" // Not implemented
	// BuildTypeFedora = "fedora"  // Not implemented
	// BuildTypeUbuntu = "ubuntu"  // Not implemented
	// BuildTypeDebian = "debian"  // Not implemented
)

type Build struct {
	BuildType        string
	KernelConfigData string
	KernelVersion    string
}

type BuildProcessor interface {
	Start() error
	Request(b Build) error
	WithContext(c context.Context)
	WithLogger(logger *zap.Logger)
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

type KubernetesBuildProcessor struct {
	buildsch   chan Build
	ctx        context.Context
	logger     *zap.Logger
	kubeClient *kubernetes.Clientset
	bufferSize int
}

// NewKubernetesBuildProcessor constructs a KubernetesBuildProcessor
// starting from a kubernetes.Clientset. bufferSize represents the length of the
// channel we use to do the builds. A bigger bufferSize will mean that we can save more Builds
// for processing, however setting this to a big value will have impacts
func NewKubernetesBuildProcessor(kubeClient *kubernetes.Clientset, bufferSize int) *KubernetesBuildProcessor {
	buildsch := make(chan Build, bufferSize)
	return &KubernetesBuildProcessor{
		buildsch:   buildsch,
		ctx:        context.TODO(),
		logger:     zap.NewNop(),
		kubeClient: kubeClient,
		bufferSize: bufferSize,
	}
}

func (bp *KubernetesBuildProcessor) WithContext(c context.Context) {
	bp.ctx = c
}

func (bp *KubernetesBuildProcessor) WithLogger(logger *zap.Logger) {
	bp.logger = logger
}

func (bp *KubernetesBuildProcessor) Request(b Build) error {
	if len(bp.buildsch) >= bp.bufferSize {
		return fmt.Errorf("too many queued elements right now, retry later")
	}
	bp.buildsch <- b
	return nil // TODO(fntlnz): do validation and error in case
}

func (bp *KubernetesBuildProcessor) Start() error {
	for b := range bp.buildsch {
		select {
		case <-bp.ctx.Done():
			// TODO(fntlnz): log that the processor was interrupted here
			return nil
		default:
			// TODO(fntlnz): hook the the build process on kubernetes here
			bp.logger.Info("doing a build", zap.String("type", b.BuildType))
		}
	}
	return nil
}
