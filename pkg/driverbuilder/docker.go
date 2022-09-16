package driverbuilder

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"github.com/docker/docker/pkg/archive"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"io"
	"io/ioutil"
	"log"
	"runtime"
	"strconv"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/falcosecurity/driverkit/pkg/driverbuilder/builder"
	"github.com/falcosecurity/driverkit/pkg/signals"
	logger "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/uuid"
)

// DockerBuildProcessorName is a constant containing the docker name.
const DockerBuildProcessorName = "docker"

type DockerBuildProcessor struct {
	clean   bool
	timeout int
	proxy   string
}

// NewDockerBuildProcessor ...
func NewDockerBuildProcessor(timeout int, proxy string) *DockerBuildProcessor {
	return &DockerBuildProcessor{
		timeout: timeout,
		proxy:   proxy,
	}
}

func (bp *DockerBuildProcessor) String() string {
	return DockerBuildProcessorName
}

func mustCheckArchUseQemu(ctx context.Context, b *builder.Build, cli *client.Client) {
	var err error
	if b.Architecture == runtime.GOARCH {
		// Nothing to do
		return
	}

	if runtime.GOARCH != "amd64" {
		log.Fatal("qemu-user-static image is only available for x86_64 hosts: https://github.com/multiarch/qemu-user-static#supported-host-architectures")
	}

	logger.Debug("using qemu for cross build")
	if _, _, err = cli.ImageInspectWithRaw(ctx, "multiarch/qemu-user-static"); client.IsErrNotFound(err) {
		logger.WithField("image", "multiarch/qemu-user-static").Debug("pulling qemu static image")
		pullRes, err := cli.ImagePull(ctx, "multiarch/qemu-user-static", types.ImagePullOptions{})
		if err != nil {
			log.Fatal(err)
		}
		defer pullRes.Close()
		_, err = io.Copy(ioutil.Discard, pullRes)
		if err != nil {
			log.Fatal(err)
		}
	}
	qemuImage, err := cli.ContainerCreate(ctx,
		&container.Config{
			Cmd:   []string{"--reset", "-p", "yes"},
			Image: "multiarch/qemu-user-static",
		},
		&container.HostConfig{
			AutoRemove: true,
			Privileged: true,
		}, nil, nil, "")
	if err != nil {
		log.Fatal(err)
	}

	if err = cli.ContainerStart(ctx, qemuImage.ID, types.ContainerStartOptions{}); err != nil {
		panic(err)
	}

	statusCh, errCh := cli.ContainerWait(ctx, qemuImage.ID, container.WaitConditionNotRunning)
	select {
	case err = <-errCh:
		if err != nil {
			panic(err)
		}
	case <-statusCh:
	}

	err = cli.ContainerStop(ctx, qemuImage.ID, nil)
	if err != nil && !client.IsErrNotFound(err) {
		log.Fatal(err)
	}
}

// Start the docker processor
func (bp *DockerBuildProcessor) Start(b *builder.Build) error {
	logger.Debug("doing a new docker build")
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return err
	}

	kr := b.KernelReleaseFromBuildConfig()

	// create a builder based on the choosen build type
	v, err := builder.Factory(b.TargetType)
	if err != nil {
		return err
	}
	c := builder.Config{
		DriverName:      b.ModuleDriverName,
		DeviceName:      b.ModuleDeviceName,
		DownloadBaseURL: "https://github.com/falcosecurity/libs/archive", // TODO: make this configurable
		Build:           b,
	}

	// Generate the build script from the builder
	driverkitScript, err := builder.Script(v, c, kr)
	if err != nil {
		return err
	}

	// Prepare driver config template
	bufFillDriverConfig := bytes.NewBuffer(nil)
	err = renderFillDriverConfig(bufFillDriverConfig, driverConfigData{DriverVersion: c.DriverVersion, DriverName: c.DriverName, DeviceName: c.DeviceName})
	if err != nil {
		return err
	}

	// Prepare makefile template
	objList, err := LoadMakefileObjList(c)
	if err != nil {
		return err
	}
	bufMakefile := bytes.NewBuffer(nil)
	err = renderMakefile(bufMakefile, makefileData{ModuleName: c.DriverName, ModuleBuildDir: builder.DriverDirectory, MakeObjList: objList})
	if err != nil {
		return err
	}

	configDecoded, err := base64.StdEncoding.DecodeString(b.KernelConfigData)
	if err != nil {
		return err
	}

	builderImage := b.GetBuilderImage()

	// Create the container
	ctx := context.Background()
	ctx = signals.WithStandardSignals(ctx)

	mustCheckArchUseQemu(ctx, b, cli)

	var inspect types.ImageInspect
	if inspect, _, err = cli.ImageInspectWithRaw(ctx, builderImage); client.IsErrNotFound(err) ||
		inspect.Architecture != b.Architecture {

		logger.
			WithField("image", builderImage).
			WithField("arch", b.Architecture).
			Debug("pulling builder image")

		pullRes, err := cli.ImagePull(ctx, builderImage, types.ImagePullOptions{Platform: b.Architecture})
		if err != nil {
			return err
		}
		defer pullRes.Close()
		_, err = io.Copy(ioutil.Discard, pullRes)
		if err != nil {
			return err
		}
	}

	logger.
		WithField("image", builderImage).
		Debug("starting container")

	containerCfg := &container.Config{
		Tty:   true,
		Cmd:   []string{"/bin/sleep", strconv.Itoa(bp.timeout)},
		Image: builderImage,
	}

	hostCfg := &container.HostConfig{
		AutoRemove: true,
	}
	uid := uuid.NewUUID()
	name := fmt.Sprintf("driverkit-%s", string(uid))

	cdata, err := cli.ContainerCreate(ctx, containerCfg, hostCfg, nil, &v1.Platform{Architecture: b.Architecture, OS: "linux"}, name)
	if err != nil {
		return err
	}

	defer bp.cleanup(cli, cdata.ID)
	go func() {
		for {
			select {
			case <-ctx.Done():
				bp.cleanup(cli, cdata.ID)
				return
			}
		}
	}()

	err = cli.ContainerStart(ctx, cdata.ID, types.ContainerStartOptions{})
	if err != nil {
		return err
	}

	files := []dockerCopyFile{
		{"/driverkit/driverkit.sh", driverkitScript},
		{"/driverkit/kernel.config", string(configDecoded)},
		{"/driverkit/module-Makefile", bufMakefile.String()},
		{"/driverkit/fill-driver-config.sh", bufFillDriverConfig.String()},
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

	// Construct environment variable array of string
	var envs []string
	// Add http_proxy and https_proxy environment variable
	if bp.proxy != "" {
		envs = append(envs,
			fmt.Sprintf("http_proxy=%s", bp.proxy),
			fmt.Sprintf("https_proxy=%s", bp.proxy),
		)
	}

	edata, err := cli.ContainerExecCreate(ctx, cdata.ID, types.ExecConfig{
		Privileged:   false,
		Tty:          false,
		AttachStdin:  false,
		AttachStderr: true,
		AttachStdout: true,
		Detach:       true,
		Env:          envs,
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
	defer hr.Close()

	forwardLogs(hr.Reader)

	if len(b.ModuleFilePath) > 0 {
		if err := copyFromContainer(ctx, cli, cdata.ID, builder.ModuleFullPath, b.ModuleFilePath); err != nil {
			return err
		}
		logger.WithField("path", b.ModuleFilePath).Info("kernel module available")
	}

	if len(b.ProbeFilePath) > 0 {
		if err := copyFromContainer(ctx, cli, cdata.ID, builder.ProbeFullPath, b.ProbeFilePath); err != nil {
			return err
		}
		logger.WithField("path", b.ProbeFilePath).Info("eBPF probe available")
	}

	return nil
}

func copyFromContainer(ctx context.Context, cli *client.Client, ID, from, to string) error {
	content, stat, err := cli.CopyFromContainer(ctx, ID, from)
	if err != nil {
		return err
	}
	defer content.Close()

	srcInfo := archive.CopyInfo{
		Path:   from,
		Exists: true,
		IsDir:  stat.Mode.IsDir(),
	}
	preArchive := content
	return archive.CopyTo(preArchive, srcInfo, to)
}

func (bp *DockerBuildProcessor) cleanup(cli *client.Client, ID string) {
	if !bp.clean {
		bp.clean = true
		logger.Debug("context canceled")
		duration := time.Second
		if err := cli.ContainerStop(context.Background(), ID, &duration); err != nil && !client.IsErrNotFound(err) {
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
