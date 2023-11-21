package driverbuilder

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"github.com/falcosecurity/driverkit/pkg/driverbuilder/builder"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const LocalBuildProcessorName = "local"

type LocalBuildProcessor struct {
	timeout int
}

func NewLocalBuildProcessor(timeout int) *LocalBuildProcessor {
	return &LocalBuildProcessor{
		timeout: timeout,
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
		if _, err = os.Stat(builder.ModuleFullPath); !os.IsNotExist(err) {
			// we built the kmod; there is no need to loop again.
			break
		}
		if _, err = os.Stat(builder.ProbeFullPath); !os.IsNotExist(err) {
			c.ProbeFilePath = ""
		}
	}

	if len(b.ModuleFilePath) > 0 {
		if err = os.Rename(builder.ModuleFullPath, b.ModuleFilePath); err != nil {
			return err
		}
		slog.With("path", b.ModuleFilePath).Info("kernel module available")
	}

	if len(b.ProbeFilePath) > 0 {
		if err = os.Rename(builder.ProbeFullPath, b.ProbeFilePath); err != nil {
			return err
		}
		slog.With("path", b.ProbeFilePath).Info("eBPF probe available")
	}

	return nil
}
