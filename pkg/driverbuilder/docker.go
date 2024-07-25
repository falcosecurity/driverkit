// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package driverbuilder

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/docker/docker/api/types/image"
	"github.com/falcosecurity/falcoctl/pkg/output"
	"io"
	"log"
	"runtime"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/archive"
	"github.com/falcosecurity/driverkit/pkg/driverbuilder/builder"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"github.com/falcosecurity/driverkit/pkg/signals"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
)

// DockerBuildProcessorName is a constant containing the docker name.
const DockerBuildProcessorName = "docker"

type DockerBuildProcessor struct {
	clean   bool
	timeout int
	proxy   string
	*output.Printer
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

func (bp *DockerBuildProcessor) mustCheckArchUseQemu(ctx context.Context, b *builder.Build, cli *client.Client) {
	var err error
	if b.Architecture == runtime.GOARCH {
		// Nothing to do
		return
	}

	if runtime.GOARCH != kernelrelease.ArchitectureAmd64 {
		bp.Logger.Fatal("qemu-user-static image is only available for x86_64 hosts: https://github.com/multiarch/qemu-user-static#supported-host-architectures")
	}

	bp.Logger.Debug("using qemu for cross build")
	if _, _, err = cli.ImageInspectWithRaw(ctx, "multiarch/qemu-user-static"); client.IsErrNotFound(err) {
		bp.Logger.Debug("pulling qemu static image",
			bp.Logger.Args("image", "multiarch/qemu-user-static"))
		pullRes, err := cli.ImagePull(ctx, "multiarch/qemu-user-static", image.PullOptions{})
		if err != nil {
			log.Fatal(err)
		}
		defer pullRes.Close()
		_, err = io.Copy(io.Discard, pullRes)
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
		bp.Logger.Fatal("failed to create qemu container",
			bp.Logger.Args("err", err.Error()))
	}

	if err = cli.ContainerStart(ctx, qemuImage.ID, container.StartOptions{}); err != nil {
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

	err = cli.ContainerStop(ctx, qemuImage.ID, container.StopOptions{})
	if err != nil && !client.IsErrNotFound(err) {
		bp.Logger.Fatal("failed to stop qemu container",
			bp.Logger.Args("err", err.Error()))
	}
}

// Start the docker processor
func (bp *DockerBuildProcessor) Start(b *builder.Build) error {
	bp.Printer = b.Printer

	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return err
	}
	cli.NegotiateAPIVersion(context.Background())

	kr := b.KernelReleaseFromBuildConfig()

	// create a builder based on the choosen build type
	v, err := builder.Factory(b.TargetType)
	if err != nil {
		return err
	}
	c := b.ToConfig()

	libsDownloadScript, err := builder.LibsDownloadScript(c)
	if err != nil {
		return err
	}

	kernelDownloadScript, err := builder.KernelDownloadScript(v, c.KernelUrls, kr, b.Printer)
	if err != nil {
		return err
	}

	// Generate the build script from the builder
	driverkitScript, err := builder.Script(v, c, kr)
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

	bp.mustCheckArchUseQemu(ctx, b, cli)

	var inspect types.ImageInspect
	if inspect, _, err = cli.ImageInspectWithRaw(ctx, builderImage); client.IsErrNotFound(err) ||
		inspect.Architecture != b.Architecture {

		bp.Logger.Debug("pulling builder image",
			bp.Logger.Args("image", builderImage, "arch", b.Architecture))

		pullRes, err := cli.ImagePull(ctx, builderImage, image.PullOptions{Platform: b.Architecture})
		if err != nil {
			return err
		}
		defer pullRes.Close()
		_, err = io.Copy(io.Discard, pullRes)
		if err != nil {
			return err
		}
	}

	bp.Logger.Debug("starting container", bp.Logger.Args("image", builderImage))

	containerCfg := &container.Config{
		Tty:   true,
		Cmd:   []string{"/bin/sleep", strconv.Itoa(bp.timeout)},
		Image: builderImage,
	}

	// check for any overridden builder image network modes by the builder
	var builderImageNetMode = container.NetworkMode("default")
	if vv, ok := v.(builder.BuilderImageNetworkMode); ok {
		builderImageNetMode = container.NetworkMode(vv.BuilderImageNetMode())
	}

	hostCfg := &container.HostConfig{
		AutoRemove:  true,
		NetworkMode: builderImageNetMode,
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

	err = cli.ContainerStart(ctx, cdata.ID, container.StartOptions{})
	if err != nil {
		return err
	}

	// We make all 3 scripts executables,
	// then:
	// * download libs at required version
	// * download and extract headers
	//   * each download-headers script will export KERNELDIR variable internally
	//   * we source download-headers.sh so that KERNELDIR is then visible to driverkit.sh
	// * we finally make the actual build of the drivers
	runCmd :=
		`
#!/bin/bash

chmod +x /driverkit/download-libs.sh
chmod +x /driverkit/download-headers.sh
chmod +x /driverkit/driverkit.sh

/driverkit/download-libs.sh
. /driverkit/download-headers.sh
/driverkit/driverkit.sh
`

	files := []dockerCopyFile{
		{"/driverkit/download-libs.sh", libsDownloadScript},
		{"/driverkit/download-headers.sh", kernelDownloadScript},
		{"/driverkit/driverkit.sh", driverkitScript},
		{"/driverkit/cmd.sh", runCmd},
		{"/driverkit/kernel.config", string(configDecoded)},
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
			"-l",
			"/driverkit/cmd.sh",
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

	isMultiplexed := false
	if val, ok := hr.MediaType(); ok {
		isMultiplexed = val == "application/vnd.docker.multiplexed-stream"
	}
	if isMultiplexed {
		bp.multiplexedForwardLogs(hr.Reader)
	} else {
		bp.forwardLogs(hr.Reader)
	}

	if len(b.ModuleFilePath) > 0 {
		if err := copyFromContainer(ctx, cli, cdata.ID, c.ToDriverFullPath(), b.ModuleFilePath); err != nil {
			return err
		}
		bp.Logger.Info("kernel module available", bp.Logger.Args("path", b.ModuleFilePath))
	}

	if len(b.ProbeFilePath) > 0 {
		if err := copyFromContainer(ctx, cli, cdata.ID, c.ToProbeFullPath(), b.ProbeFilePath); err != nil {
			return err
		}
		bp.Logger.Info("eBPF probe available", bp.Logger.Args("path", b.ProbeFilePath))
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
		bp.Logger.Debug("context canceled")
		duration := 1
		if err := cli.ContainerStop(context.Background(), ID, container.StopOptions{Timeout: &duration}); err != nil && !client.IsErrNotFound(err) {
			bp.Logger.Error("error stopping container",
				bp.Logger.Args("err", err.Error()))
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

func (bp *DockerBuildProcessor) forwardLogs(logPipe io.Reader) {
	lineReader := bufio.NewReader(logPipe)
	for {
		line, err := lineReader.ReadBytes('\n')
		if len(line) > 0 {
			bp.Logger.Debug(string(line))
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			bp.Logger.Error("log pipe error", bp.Logger.Args("err", err.Error()))
		}
	}
	bp.Logger.Debug("log pipe close")
}

// When docker container attach is called on a non-tty terminal,
// docker SDK uses a custom multiplexing protocol allowing STDOUT and STDERR string to be sent to a single stream.
// Protocol:
// > The format of the multiplexed stream is as follows:
// > [8]byte{STREAM_TYPE, 0, 0, 0, SIZE1, SIZE2, SIZE3, SIZE4}[]byte{OUTPUT}
// see cli.ContainerAttach() method for more info.
func (bp *DockerBuildProcessor) multiplexedForwardLogs(logPipe io.Reader) {
	hdr := make([]byte, 8)
	for {
		// Load size of message
		_, err := logPipe.Read(hdr)
		if err == io.EOF {
			break
		}
		if err != nil {
			bp.Logger.Error("log pipe error", bp.Logger.Args("err", err.Error()))
			return
		}
		count := binary.BigEndian.Uint32(hdr[4:])

		// Read message
		dat := make([]byte, count)
		var readCnt int
		for uint32(readCnt) < count {
			readBytes, err := logPipe.Read(dat[readCnt:])
			readCnt += readBytes
			if err == io.EOF {
				if uint32(readCnt) == count {
					break
				}
				bp.Logger.Error("log pipe error", bp.Logger.Args("err", io.EOF.Error()))
				return
			}
			if err != nil {
				bp.Logger.Error("log pipe error", bp.Logger.Args("err", err.Error()))
				return
			}
		}

		// Print message line by line
		lines := strings.Split(string(dat), "\n")
		for _, line := range lines {
			if line != "" {
				bp.Logger.Debug(line)
			}
		}
	}
	bp.Logger.Debug("log pipe close")
}
