package modulebuilder

type DockerBuilder struct {
	cfg Config
}

func NewDockerBuilderFromConfig(cfg Config) DockerBuilder {
	return DockerBuilder{
		cfg: cfg,
	}
}

func (b DockerBuilder) Build() error {
	err := b.BuildKernel()
	if err != nil {
		return err
	}
	return b.BuildModule()
}

func (b DockerBuilder) BuildKernel() error {
	panic("TODO")
}

func (b DockerBuilder) BuildModule() error {
	panic("TODO")
}
