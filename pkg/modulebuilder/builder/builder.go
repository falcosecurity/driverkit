package builder

const moduleExtension = "ko"
const KubernetesBuilderName = "kubernetes"
const LocalBuilderName = "local"

type Builder interface {
	Build() error
}

type ModuleBuilder interface {
	BuildModule() error
}

type KernelBuilder interface {
	BuildKernel() error
}

type Config struct {
	KernelVersion    string
	KernelDir        string
	ModuleDir        string
	ModuleVersion    string
	ModuleName       string
	DeviceName       string
	KernelConfigData string
}
