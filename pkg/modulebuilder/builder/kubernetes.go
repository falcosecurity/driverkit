package builder

import (
	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
)

type KubernetesBuilder struct {
	cfg           Config
	kubeClientSet *kubernetes.Clientset
	logger        *zap.Logger
}

func NewKubernetesBuilderFromConfig(cfg Config) KubernetesBuilder {
	return KubernetesBuilder{
		cfg:    cfg,
		logger: zap.NewNop(),
	}
}

func (b *KubernetesBuilder) WithLogger(logger *zap.Logger) {
	b.logger = logger
}

func (b *KubernetesBuilder) WithKubeClientSet(clientset *kubernetes.Clientset) {
	b.kubeClientSet = clientset
}

func (b KubernetesBuilder) Build() error {
	err := b.BuildKernel()
	if err != nil {
		return err
	}
	return b.BuildModule()
}

func (b KubernetesBuilder) BuildKernel() error {

	panic("TODO")
}

func (b KubernetesBuilder) BuildModule() error {
	panic("TODO")
}
