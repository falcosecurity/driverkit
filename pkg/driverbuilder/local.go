package driverbuilder

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"github.com/falcosecurity/driverkit/pkg/driverbuilder/builder"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"time"
)

const (
	LocalBuildProcessorName = "local"
	kernelDirEnv            = "KERNELDIR"
)

type LocalBuildProcessor struct {
	timeout         int
	useDKMS         bool
	downloadHeaders bool
	srcDir          string
	envMap          map[string]string
}

func NewLocalBuildProcessor(timeout int, useDKMS, downloadHeaders bool, srcDir string, envMap map[string]string) *LocalBuildProcessor {
	return &LocalBuildProcessor{
		timeout:         timeout,
		useDKMS:         useDKMS,
		srcDir:          srcDir,
		envMap:          envMap,
		downloadHeaders: downloadHeaders,
	}
}

func (lbp *LocalBuildProcessor) String() string {
	return LocalBuildProcessorName
}

func (lbp *LocalBuildProcessor) Start(b *builder.Build) error {
	slog.Debug("doing a new local build")

	if lbp.useDKMS {
		currentUser, err := user.Current()
		if err != nil {
			return err
		}
		if currentUser.Username != "root" {
			return errors.New("must be run as root for DKMS build")
		}
	}

	// We don't want to download headers
	kr := b.KernelReleaseFromBuildConfig()

	if lbp.downloadHeaders {
		// Download headers for current distro
		realBuilder, err := builder.Factory(b.TargetType)
		// Since this can be used by external projects, it is not an issue
		// if an unsupported target is passed.
		// Go on skipping automatic kernel headers download.
		if err == nil {
			slog.Info("Trying automatic kernel headers download")
			kernelDownloadScript, err := builder.KernelDownloadScript(realBuilder, nil, kr)
			// Patch kernel download script to echo KERNELDIR.
			// We need to capture KERNELDIR to later pass it as env variable to the build.
			kernelDownloadScript += "\necho $KERNELDIR"
			if err == nil {
				out, err := exec.Command("bash", "-c", kernelDownloadScript).Output()
				if err == nil {
					// Scan all stdout line by line and
					// store last line as KERNELDIR path.
					reader := bytes.NewReader(out)
					scanner := bufio.NewScanner(reader)
					var path string
					for scanner.Scan() {
						path = scanner.Text()
					}
					slog.Info("Setting KERNELDIR env var", "path", path)
					// add the kerneldir path to env
					lbp.envMap[kernelDirEnv] = path
					defer func() {
						_ = os.RemoveAll("/tmp/kernel-download")
						_ = os.RemoveAll(path)
					}()
				} else {
					slog.Warn("Failed to download headers", "err", err)
				}
			}
		} else {
			slog.Info("Skipping kernel headers automatic download", "err", err)
		}
	}

	// From now on, we use the local builder
	b.TargetType = LocalBuildProcessorName

	// create a builder based on the choosen build type
	v, err := builder.Factory(b.TargetType)
	if err != nil {
		return err
	}
	c := b.ToConfig()

	defer os.RemoveAll(builder.DriverDirectory)

	// Load gcc versions from system
	var gccs []string
	if len(b.ModuleFilePath) > 0 {
		out, err := exec.Command("which", "gcc").Output()
		if err != nil {
			return err
		}
		gccDir := filepath.Dir(string(out))
		proposedGCCs, err := filepath.Glob(gccDir + "/gcc*")
		if err != nil {
			return err
		}
		for _, proposedGCC := range proposedGCCs {
			// Filter away gcc-{ar,nm,...}
			// Only gcc compiler has `-print-search-dirs` option.
			gccSearchArgs := fmt.Sprintf(`%s -print-search-dirs 2>&1 | grep "install:"`, proposedGCC)
			_, err = exec.Command("bash", "-c", gccSearchArgs).Output() //nolint:gosec // false positive
			if err != nil {
				continue
			}
			gccs = append(gccs, proposedGCC)
		}
	} else {
		// We won't use it!
		gccs = []string{"UNUSED"}
	}

	// Cannot fail
	vv, _ := v.(*builder.LocalBuilder)
	vv.SrcDir = lbp.srcDir
	vv.UseDKMS = lbp.useDKMS

	// Fetch paths were kmod and probe will be built
	srcModulePath := vv.GetModuleFullPath(c, kr)
	srcProbePath := vv.GetProbeFullPath(c)

	if len(lbp.srcDir) == 0 {
		slog.Info("Downloading driver sources")
		// Download src!
		libsDownloadScript, err := builder.LibsDownloadScript(c)
		if err != nil {
			return err
		}
		_, err = exec.Command("/bin/bash", "-c", libsDownloadScript).CombinedOutput()
		if err != nil {
			return err
		}
	}

	for _, gcc := range gccs {
		vv.GccPath = gcc

		// Generate the build script from the builder
		driverkitScript, err := builder.Script(v, c, kr)
		if err != nil {
			return err
		}
		ctx, cancelFunc := context.WithTimeout(context.Background(), time.Duration(lbp.timeout)*time.Second)
		defer cancelFunc()
		cmd := exec.CommandContext(ctx, "/bin/bash", "-c", driverkitScript)
		cmd.Env = os.Environ()
		// Append requested env variables to the command env
		for key, val := range lbp.envMap {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, val))
		}

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			slog.Warn("Failed to pipe stdout", "err", err)
			_, err = cmd.CombinedOutput()
		} else {
			cmd.Stderr = cmd.Stdout // redirect stderr to stdout so that we catch it
			defer stdout.Close()
			err = cmd.Start()
			if err != nil {
				slog.Warn("Failed to execute command", "err", err)
			} else {
				// print the output of the subprocess line by line
				scanner := bufio.NewScanner(stdout)
				for scanner.Scan() {
					m := scanner.Text()
					fmt.Println(m)
				}
				err = cmd.Wait()
			}
		}

		// If we built the probe, disable its build for subsequent attempts (with other available gccs)
		if c.ProbeFilePath != "" {
			if _, err = os.Stat(srcProbePath); !os.IsNotExist(err) {
				if err = copyDataToLocalPath(srcProbePath, b.ProbeFilePath); err != nil {
					return err
				}
				slog.With("path", b.ProbeFilePath).Info("eBPF probe available")
				c.ProbeFilePath = ""
			}
		}

		// If we received an error, perhaps we just need to try another build for the kmod.
		// Check if we were able to build anything.
		koFiles, err := filepath.Glob(srcModulePath)
		if err == nil && len(koFiles) > 0 {
			// Since only kmod might need to get rebuilt
			// with another gcc, break here if we actually built the kmod.
			break
		}
	}

	if len(b.ModuleFilePath) > 0 {
		// If we received an error, perhaps we must just rebuilt the kmod.
		// Check if we were able to build anything.
		koFiles, err := filepath.Glob(srcModulePath)
		if err != nil || len(koFiles) == 0 {
			return fmt.Errorf("failed to find kernel module .ko file: %s", srcModulePath)
		}
		if err = copyDataToLocalPath(koFiles[0], b.ModuleFilePath); err != nil {
			return err
		}
		slog.With("path", b.ModuleFilePath).Info("kernel module available")
	}
	return nil
}

func copyDataToLocalPath(src, dest string) error {
	in, err := os.Open(filepath.Clean(src))
	if err != nil {
		return err
	}
	defer in.Close()
	err = os.MkdirAll(filepath.Dir(dest), 0o755)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(filepath.Clean(dest), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o755)
	if err == nil {
		defer out.Close()
		_, err = io.Copy(out, in)
	}
	return err
}
