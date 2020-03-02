package modulebuilder

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	buildmeta "github.com/falcosecurity/driverkit/pkg/modulebuilder/build"
	"go.uber.org/zap"
)

const DockerBuildProcessorName = "docker"

type DockerBuildProcessor struct {
	logger *zap.Logger
}

// NewDockerBuildProcessor ...
func NewDockerBuildProcessor() *DockerBuildProcessor {
	return &DockerBuildProcessor{
		logger: zap.NewNop(),
	}
}

func (bp *DockerBuildProcessor) String() string {
	return DockerBuildProcessorName
}

func (bp *DockerBuildProcessor) WithLogger(logger *zap.Logger) {
	bp.logger = logger
	bp.logger.With(zap.String("processor", bp.String()))
}

func (bp *DockerBuildProcessor) Start(b buildmeta.Build) error {
	buildlogger := bp.logger.With(
		zap.String("Architecture", b.Architecture),
		zap.String("BuildType", string(b.BuildType)),
		zap.String("KernelRelease", b.KernelVersion),
		zap.String("ModuleVersion", b.ModuleVersion),
	)
	sha, err := b.SHA256()
	if err != nil {
		buildlogger.Error("build sha256 error", zap.Error(err))
		return err
	}
	buildlogger = buildlogger.With(zap.String("SHA256", sha))
	buildlogger.Info("doing a new build")
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return err
	}
	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		return err
	}
	for _, container := range containers {
		fmt.Printf("%s %s\n", container.ID[:10], container.Image)
	}
	return nil
}
