package driverbuilder

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/falcosecurity/driverkit/pkg/driverbuilder/builder"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"github.com/falcosecurity/driverkit/pkg/signals"
	"github.com/sirupsen/logrus"
	logger "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/uuid"
)

const DockerBuildProcessorName = "docker"

type DockerBuildProcessor struct {
	clean   bool
	timeout int
}

// NewDockerBuildProcessor ...
func NewDockerBuildProcessor(timeout int) *DockerBuildProcessor {
	return &DockerBuildProcessor{
		timeout: timeout,
	}
}

func (bp *DockerBuildProcessor) String() string {
	return DockerBuildProcessorName
}

// Start ...
func (bp *DockerBuildProcessor) Start(b *builder.Build) error {
	logger.Debug("doing a new docker build")
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return err
	}

	// create a builder based on the choosen build type
	v, err := builder.Factory(b.TargetType)
	if err != nil {
		return err
	}

	c := builder.Config{
		DriverName:      "falco",
		DeviceName:      "falco",
		DownloadBaseURL: "https://github.com/draios/sysdig/archive",
		Build:           b,
	}

	// Generate the build script from the builder
	res, err := v.Script(c)
	if err != nil {
		return err
	}

	// Prepare driver config template
	bufDriverConfig := bytes.NewBuffer(nil)
	err = renderDriverConfig(bufDriverConfig, driverConfigData{DriverVersion: c.DriverVersion, DriverName: c.DriverName, DeviceName: c.DeviceName})
	if err != nil {
		return err
	}

	// Prepare makefile template
	bufMakefile := bytes.NewBuffer(nil)
	err = renderMakefile(bufMakefile, makefileData{ModuleName: c.DriverName, ModuleBuildDir: builder.DriverDirectory})
	if err != nil {
		return err
	}

	configDecoded, err := base64.StdEncoding.DecodeString(b.KernelConfigData)
	if err != nil {
		return err
	}

	ctx := context.Background()
	ctx = signals.WithStandardSignals(ctx)

	_, err = cli.ImagePull(ctx, builderBaseImage, types.ImagePullOptions{All: true})
	if err != nil {
		return err
	}

	// Build the builder image
	if b.TargetType == builder.TargetTypeLinuxKit {
		kr := kernelrelease.FromString(c.KernelRelease)
		opts := types.ImageBuildOptions{
			SuppressOutput: false,
			// Remove:         true,
			// ForceRemove:    true,
			PullParent: true,
			// todo > update the URL
			RemoteContext: "https://gist.githubusercontent.com/leodido/e78666ba8a7ad5ec1b97acf4ade098d6/raw/328dc2452163762e6824995da2f8a29888680381/lktest.Dockerfile",
			BuildArgs: map[string]*string{
				"KERNEL_VERSION": &kr.Fullversion,
			},
			Tags: []string{
				fmt.Sprintf("driverkit-builder:%s", c.KernelRelease),
			},
		}
		buildRes, err := cli.ImageBuild(ctx, nil, opts)
		if err != nil {
			return err
		}
		defer buildRes.Body.Close()
		forwardLogs(buildRes.Body)
		// todo > use docker logging API with our logrus logger?
		// termFd, isTerm := term.GetFdInfo(os.Stdout)
		// jsonmessage.DisplayJSONMessagesStream(buildRes.Body, nil, termFd, isTerm)
	}

	// Create the container
	containerCfg := &container.Config{
		Tty:   true,
		Cmd:   []string{"/bin/sleep", strconv.Itoa(bp.timeout)},
		Image: builderBaseImage,
	}

	if b.TargetType == builder.TargetTypeLinuxKit {
		containerCfg.Image = fmt.Sprintf("driverkit-builder:%s", c.KernelRelease)
	}

	hostCfg := &container.HostConfig{
		AutoRemove: true,
	}
	// if b.TargetType == builder.TargetTypeLinuxKit {
	// 	hostCfg.Mounts = []mount.Mount{
	// 		{
	// 			Type:   mount.TypeBind,
	// 			Source: "/var/run/docker.sock",
	// 			Target: "/var/run/docker.sock",
	// 		},
	// 	}
	// }

	networkCfg := &network.NetworkingConfig{}
	uid := uuid.NewUUID()
	name := fmt.Sprintf("driverkit-%s", string(uid))
	cdata, err := cli.ContainerCreate(ctx, containerCfg, hostCfg, networkCfg, name)
	if err != nil {
		return err
	}

	defer bp.cleanup(ctx, cli, cdata.ID)
	go func() {
		for {
			select {
			case <-ctx.Done():
				bp.cleanup(ctx, cli, cdata.ID)
				return
			}
		}
	}()

	err = cli.ContainerStart(ctx, cdata.ID, types.ContainerStartOptions{})
	if err != nil {
		return err
	}

	files := []dockerCopyFile{
		{"/driverkit/driverkit.sh", res},
		{"/driverkit/kernel.config", string(configDecoded)},
		{"/driverkit/module-Makefile", bufMakefile.String()},
		{"/driverkit/module-driver-config.h", bufDriverConfig.String()},
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
		Privileged:   false,
		Tty:          false,
		AttachStdin:  false,
		AttachStderr: true,
		AttachStdout: true,
		Detach:       false,
		Cmd: []string{
			"/bin/bash",
			"/driverkit/driverkit.sh",
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

	if len(b.ModuleFilePath) > 0 {
		if err := copyFromContainer(ctx, cli, cdata.ID, builder.FalcoModuleFullPath, b.ModuleFilePath); err != nil {
			return err
		}
		logrus.WithField("path", b.ModuleFilePath).Info("kernel module available")
	}

	if len(b.ProbeFilePath) > 0 {
		if err := copyFromContainer(ctx, cli, cdata.ID, builder.FalcoProbeFullPath, b.ProbeFilePath); err != nil {
			return err
		}
		logrus.WithField("path", b.ProbeFilePath).Info("eBPF probe available")
	}

	return nil
}

func copyFromContainer(ctx context.Context, cli *client.Client, ID, from, to string) error {
	rc, _, err := cli.CopyFromContainer(ctx, ID, from)
	if err != nil {
		return err
	}
	defer rc.Close()

	tr := tar.NewReader(rc)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			logger.WithError(err).Error("error expanding tar")
		}

		if hdr.Name == filepath.Base(from) {
			out, err := os.Create(to)

			if err != nil {
				return err
			}
			defer out.Close()

			_, err = io.Copy(out, tr)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (bp *DockerBuildProcessor) cleanup(ctx context.Context, cli *client.Client, ID string) {
	if !bp.clean {
		bp.clean = true
		logger.Debug("context canceled")
		duration := time.Duration(time.Second)
		if err := cli.ContainerStop(context.Background(), ID, &duration); err != nil {
			logger.WithError(err).WithField("container_id", ID).Error("error stopping container")
		}
	}
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
