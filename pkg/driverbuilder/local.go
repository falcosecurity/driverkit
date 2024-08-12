package driverbuilder

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"github.com/falcosecurity/driverkit/pkg/driverbuilder/builder"
	"github.com/falcosecurity/falcoctl/pkg/output"
	"io"
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
	useDKMS         bool
	downloadHeaders bool
	// Whether to only print cmd output on error
	printOnError bool
	srcDir       string
	envMap       map[string]string
	timeout      int
	*output.Printer
}

func NewLocalBuildProcessor(useDKMS, downloadHeaders, printOnError bool,
	srcDir string,
	envMap map[string]string,
	timeout int,
) *LocalBuildProcessor {
	if envMap == nil {
		envMap = make(map[string]string)
	}
	return &LocalBuildProcessor{
		useDKMS:         useDKMS,
		srcDir:          srcDir,
		printOnError:    printOnError,
		envMap:          envMap,
		downloadHeaders: downloadHeaders,
		timeout:         timeout,
	}
}

func (lbp *LocalBuildProcessor) String() string {
	return LocalBuildProcessorName
}

func (lbp *LocalBuildProcessor) Start(b *builder.Build) error {
	lbp.Printer = b.Printer
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
			lbp.Logger.Info("Trying automatic kernel headers download.")
			kernelDownloadScript, err := builder.KernelDownloadScript(realBuilder, nil, kr, lbp.Printer)
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
					lbp.Logger.Info("Setting KERNELDIR env var.", lbp.Logger.Args("path", path))
					// add the kerneldir path to env
					lbp.envMap[kernelDirEnv] = path
					defer func() {
						_ = os.RemoveAll("/tmp/kernel-download")
						_ = os.RemoveAll(path)
					}()
				} else {
					lbp.Logger.Warn("Failed to download headers.", lbp.Logger.Args("err", err))
				}
			} else {
				lbp.Logger.Warn("Failed to generate script.", lbp.Logger.Args("err", err))
			}
		} else {
			lbp.Logger.Info("Skipping kernel headers automatic download.", lbp.Logger.Args("err", err))
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
	if len(c.ModuleFilePath) > 0 {
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
		lbp.Logger.Info("Downloading driver sources")
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
		if c.ModuleFilePath != "" {
			lbp.Logger.Info("Trying to dkms install module.", lbp.Logger.Args("gcc", gcc))
		}
		if c.ProbeFilePath != "" {
			lbp.Logger.Info("Trying to build eBPF probe.")
		}

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

		out, err := cmd.CombinedOutput()
		if !lbp.printOnError || err != nil {
			// Only print on error
			lbp.DefaultText.Print(string(out))
		}

		// If we built the probe, disable its build for subsequent attempts (with other available gccs)
		if c.ProbeFilePath != "" {
			if _, err = os.Stat(srcProbePath); !os.IsNotExist(err) {
				if err = copyDataToLocalPath(srcProbePath, c.ProbeFilePath); err != nil {
					return err
				}
				lbp.Logger.Info("eBPF probe available.", lbp.Logger.Args("path", c.ProbeFilePath))
				c.ProbeFilePath = ""
			}
		}

		// If we received an error, perhaps we just need to try another build for the kmod.
		// Check if we were able to build anything.
		if c.ModuleFilePath != "" {
			koFiles, err := filepath.Glob(srcModulePath)
			if err == nil && len(koFiles) > 0 {
				// Since only kmod might need to get rebuilt
				// with another gcc, break here if we actually built the kmod,
				// since we already checked ebpf build status.
				if err = copyDataToLocalPath(koFiles[0], c.ModuleFilePath); err != nil {
					return err
				}
				lbp.Logger.Info("kernel module available.", lbp.Logger.Args("path", b.ModuleFilePath))
				c.ModuleFilePath = ""
				break
			} else {
				// print dkms build log
				dkmsLogFile := fmt.Sprintf("/var/lib/dkms/%s/%s/build/make.log", c.DriverName, c.DriverVersion)
				logs, err := os.ReadFile(filepath.Clean(dkmsLogFile))
				if err != nil {
					lbp.Logger.Warn("Running dkms build failed, couldn't find dkms log.", lbp.Logger.Args("file", dkmsLogFile))
				} else {
					lbp.Logger.Warn("Running dkms build failed. Dumping dkms log.", lbp.Logger.Args("file", dkmsLogFile))
					logBuf := bytes.NewBuffer(logs)
					scanner := bufio.NewScanner(logBuf)
					for scanner.Scan() {
						m := scanner.Text()
						lbp.DefaultText.Println(m)
					}
				}
			}
		}
	}

	if c.ModuleFilePath != "" || c.ProbeFilePath != "" {
		return errors.New("failed to build all requested drivers")
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
