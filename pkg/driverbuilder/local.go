package driverbuilder

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"github.com/falcosecurity/driverkit/pkg/driverbuilder/builder"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"time"
)

const LocalBuildProcessorName = "local"

type LocalBuildProcessor struct {
	timeout int
	useDKMS bool
	srcDir  string
	envMap  map[string]string
}

func NewLocalBuildProcessor(timeout int, useDKMS bool, srcDir string, envMap map[string]string) *LocalBuildProcessor {
	return &LocalBuildProcessor{
		timeout: timeout,
		useDKMS: useDKMS,
		srcDir:  srcDir,
		envMap:  envMap,
	}
}

func (lbp *LocalBuildProcessor) String() string {
	return LocalBuildProcessorName
}

func (lbp *LocalBuildProcessor) Start(b *builder.Build) error {
	slog.Debug("doing a new local build")

	// We don't want to download headers
	kr := b.KernelReleaseFromBuildConfig()

	// create a builder based on the choosen build type
	v, err := builder.Factory(b.TargetType)
	if err != nil {
		return err
	}
	c := b.ToConfig()

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

	// Create all local files
	files := []dockerCopyFile{
		{"/tmp/module-Makefile", bufMakefile.String()},
		{"/tmp/fill-driver-config.sh", bufFillDriverConfig.String()},
	}
	for _, file := range files {
		if err = os.WriteFile(file.Name, []byte(file.Body), 0o755); err != nil {
			return err
		}
		defer os.Remove(file.Name)
	}

	defer os.Remove(builder.DriverDirectory)

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
		gccs = []string{"gcc"}
	}

	// Cannot fail
	vv, _ := v.(*builder.LocalBuilder)
	vv.SrcDir = lbp.srcDir
	vv.UseDKMS = lbp.useDKMS

	modulePath := vv.GetModuleFullPath(c, kr)
	probePath := path.Join(vv.GetDriverBuildDir(), "bpf", builder.ProbeFileName)
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
			slog.Warn("Failed to pipe output. Trying without piping.", "err", err)
			_, err = cmd.Output()
		} else {
			defer stdout.Close()
			err = cmd.Start()
			if err != nil {
				slog.Warn("Failed to execute command.", "err", err)
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
		if err == nil {
			break
		}
		// If we received an error, perhaps we must just rebuilt the kmod.
		// Check if we were able to build anything.
		koFiles, err := filepath.Glob(modulePath)
		if err == nil && len(koFiles) > 0 {
			break
		}
		if _, err = os.Stat(probePath); !os.IsNotExist(err) {
			c.ProbeFilePath = ""
		}
	}

	if len(b.ModuleFilePath) > 0 {
		// If we received an error, perhaps we must just rebuilt the kmod.
		// Check if we were able to build anything.
		koFiles, err := filepath.Glob(modulePath)
		if err != nil || len(koFiles) == 0 {
			return fmt.Errorf("failed to find kernel module .ko file: %s", modulePath)
		}
		if err = copyDataToLocalPath(koFiles[0], b.ModuleFilePath); err != nil {
			return err
		}
		slog.With("path", b.ModuleFilePath).Info("kernel module available")
	}

	if len(b.ProbeFilePath) > 0 {
		if err = copyDataToLocalPath(probePath, b.ProbeFilePath); err != nil {
			return err
		}
		slog.With("path", b.ProbeFilePath).Info("eBPF probe available")
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
