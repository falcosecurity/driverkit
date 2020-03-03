package modulebuilder

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	buildmeta "github.com/falcosecurity/driverkit/pkg/modulebuilder/build"
	"github.com/falcosecurity/driverkit/pkg/modulebuilder/builder"
	"github.com/falcosecurity/driverkit/pkg/signals"
	"k8s.io/apimachinery/pkg/util/uuid"
	logger "github.com/sirupsen/logrus"
	"io"
	"os"
)

const DockerBuildProcessorName = "docker"

type DockerBuildProcessor struct {
}

// NewDockerBuildProcessor ...
func NewDockerBuildProcessor() *DockerBuildProcessor {
	return &DockerBuildProcessor{
	}
}

func (bp *DockerBuildProcessor) String() string {
	return DockerBuildProcessorName
}

func (bp *DockerBuildProcessor) Start(b *buildmeta.Build) error {
	logger.Debug("doing a new docker build")
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return err
	}

	// create a builder based on the choosen build type
	v, err := builder.Factory(b.BuildType)
	if err != nil {
		return err
	}
	bc := builder.BuilderConfig{
		ModuleConfig: builder.ModuleConfig{
			ModuleName:      "falco",                                    // TODO: make this configurable
			DeviceName:      "falco",                                    // TODO: make this configurable
			DownloadBaseURL: "https://github.com/draios/sysdig/archive", // TODO: make this configurable
		},
		Build: b,
	}

	// generate the build script from the builder
	res, err := v.Script(bc)
	if err != nil {
		return err
	}

	res = fmt.Sprintf("%s\n%s", res, tarModuleScript)

	// Prepare driver config template
	bufDriverConfig := bytes.NewBuffer(nil)
	err = renderDriverConfig(bufDriverConfig, driverConfigData{ModuleVersion: bc.Build.ModuleVersion, ModuleName: bc.ModuleConfig.ModuleName, DeviceName: bc.ModuleConfig.DeviceName})
	if err != nil {
		return err
	}

	// Prepare makefile template
	bufMakefile := bytes.NewBuffer(nil)
	err = renderMakefile(bufMakefile, makefileData{ModuleName: bc.ModuleConfig.ModuleName, ModuleBuildDir: builder.ModuleDirectory})
	if err != nil {
		return err
	}

	configDecoded, err := base64.StdEncoding.DecodeString(b.KernelConfigData)
	if err != nil {
		return err
	}

	// Create the container
	ctx := context.Background()
	ctx = signals.WithStandardSignals(ctx)
	containerCfg := &container.Config{
		Hostname:        "",
		Domainname:      "",
		User:            "",
		AttachStdin:     false,
		AttachStdout:    false,
		AttachStderr:    false,
		ExposedPorts:    nil,
		Tty:             true,
		OpenStdin:       false,
		StdinOnce:       false,
		Env:             nil,
		Cmd:             []string{"/bin/cat"},
		Healthcheck:     nil,
		ArgsEscaped:     false,
		Image:           builderBaseImage,
		Volumes:         nil,
		WorkingDir:      "",
		Entrypoint:      nil,
		NetworkDisabled: false,
		MacAddress:      "",
		OnBuild:         nil,
		Labels:          nil,
		StopSignal:      "",
		StopTimeout:     nil,
		Shell:           nil,
	}
	hostCfg := &container.HostConfig{
		Binds:           nil,
		ContainerIDFile: "",
		LogConfig:       container.LogConfig{},
		NetworkMode:     "",
		PortBindings:    nil,
		RestartPolicy:   container.RestartPolicy{},
		AutoRemove:      false,
		VolumeDriver:    "",
		VolumesFrom:     nil,
		CapAdd:          nil,
		CapDrop:         nil,
		Capabilities:    nil,
		DNS:             nil,
		DNSOptions:      nil,
		DNSSearch:       nil,
		ExtraHosts:      nil,
		GroupAdd:        nil,
		IpcMode:         "",
		Cgroup:          "",
		Links:           nil,
		OomScoreAdj:     0,
		PidMode:         "",
		Privileged:      false,
		PublishAllPorts: false,
		ReadonlyRootfs:  false,
		SecurityOpt:     nil,
		StorageOpt:      nil,
		Tmpfs:           nil,
		UTSMode:         "",
		UsernsMode:      "",
		ShmSize:         0,
		Sysctls:         nil,
		Runtime:         "",
		ConsoleSize:     [2]uint{},
		Isolation:       "",
		Resources:       container.Resources{},
		Mounts:          nil,
		MaskedPaths:     nil,
		ReadonlyPaths:   nil,
		Init:            nil,
	}
	networkCfg := &network.NetworkingConfig{}
	uid := uuid.NewUUID()
	name := fmt.Sprintf("driverkit-%s", string(uid))
	cdata, err := cli.ContainerCreate(ctx, containerCfg, hostCfg, networkCfg, name)
	if err != nil {
		return err
	}

	err = cli.ContainerStart(ctx, cdata.ID, types.ContainerStartOptions{})
	if err != nil {
		return err
	}

	files := []dockerCopyFile{
		{"/module-builder/module-builder.sh", res},
		{"/module-builder/kernel.config", string(configDecoded)},
		{"/module-builder/module-Makefile", bufMakefile.String()},
		{"/module-builder/module-driver-config.h", bufDriverConfig.String()},
	}

	var buf bytes.Buffer
	err = tarWriterFiles(&buf, files)
	if err != nil {
		return err
	}

	// Copy the needed files to the container
	err = cli.CopyToContainer(ctx, cdata.ID, "/", &buf, types.CopyToContainerOptions{})
	if err != nil {
		return err
	}

	edata, err := cli.ContainerExecCreate(ctx, cdata.ID, types.ExecConfig{
		User:         "",
		Privileged:   false,
		Tty:          false,
		AttachStdin:  false,
		AttachStderr: true,
		AttachStdout: true,
		Detach:       false,
		DetachKeys:   "",
		Env:          nil,
		WorkingDir:   "",
		Cmd: []string{
			"/bin/bash",
			"/module-builder/module-builder.sh",
		},
	})
	if err != nil {
		return err
	}

	hr, err := cli.ContainerExecAttach(ctx, edata.ID, types.ExecStartCheck{})
	if err != nil {
		return err
	}

	forwardLogs(hr.Reader)

	rc, _, err := cli.CopyFromContainer(ctx, cdata.ID, "/tmp/module.tar")
	if err != nil {
		return err
	}
	defer rc.Close()

	out, err := os.Create(b.OutputFilePath)

	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, rc)
	if err != nil {
		return err
	}

	return nil
}

type dockerCopyFile struct {
	Name string
	Body string
}

func tarWriterFiles(buf io.Writer, files []dockerCopyFile) error {
	tw := tar.NewWriter(buf)
	defer tw.Close()
	for _, file := range files {
		hdr := &tar.Header{
			Name: file.Name,
			Mode: 0600,
			Size: int64(len(file.Body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write([]byte(file.Body)); err != nil {
			return err
		}
	}
	return nil
}

func forwardLogs(logPipe io.Reader) {
	lineReader := bufio.NewReader(logPipe)
	for {
		line, err := lineReader.ReadBytes('\n')
		if len(line) > 0 {
			logger.Debugf("%s", line)
		}
		if err == io.EOF {
			logger.WithError(err).Debug("log pipe close")
			return
		}
		if err != nil {
			logger.WithError(err).Error("log pipe error")
		}
	}
}
