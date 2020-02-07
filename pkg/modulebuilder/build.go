package modulebuilder

import (
	"bytes"
	"fmt"
	"os/exec"
	"path"

	"github.com/falcosecurity/build-service/pkg/modinfo"
)

const moduleExtension = "ko"

type Config struct {
	KernelVersion  string
	KernelBuildDir string
	ModuleDir      string
	ModuleVersion  string
	ModuleName     string
	DeviceName     string
}

type Builder struct {
	cfg Config
}

func NewFromConfig(cfg Config) Builder {
	return Builder{
		cfg: cfg,
	}
}

func (b Builder) Build() error {
	// Create necessary makefile
	makefilePath := path.Join(b.cfg.ModuleDir, "Makefile")
	if err := createMakefile(makefilePath, "falco", b.cfg.KernelBuildDir, b.cfg.ModuleDir); err != nil {
		return fmt.Errorf("error creating the module Makefile: %v", err)
	}
	// Create the driver_config.h
	driverConfigPath := path.Join(b.cfg.ModuleDir, "driver_config.h")
	if err := createDriverConfig(driverConfigPath, b.cfg.ModuleVersion, b.cfg.ModuleName, b.cfg.DeviceName); err != nil {
		return fmt.Errorf("error creating the module Makefile: %v", err)
	}
	// Build the module against the designed kernel
	cmd := exec.Command(
		"make",
		fmt.Sprintf("M=%s", b.cfg.ModuleDir),
		"-C",
		b.cfg.KernelBuildDir,
		"modules",
	)
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("error compiling the kernel module: %s", errBuf.String())
	}

	modulePath := path.Join(b.cfg.ModuleDir, fmt.Sprintf("%s.%s", b.cfg.ModuleName, moduleExtension))
	// Strip debugging symbols
	cmd = exec.Command("strip", "-g", modulePath)
	cmd.Stderr = &errBuf
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("error stripping debbuging symbols from the kernel module: %s", errBuf.String())
	}

	// Extract modinfo to check if the module is correct
	info, err := modinfo.FromModulePath(modulePath)

	if err != nil {
		return fmt.Errorf("error checking the build module: %v", err)
	}

	if info.KernelVersion != b.cfg.KernelVersion {
		return fmt.Errorf("kernel version of the built module does not match: expected=%s, got=%s", b.cfg.KernelVersion, info.KernelVersion)
	}
	return nil
}
