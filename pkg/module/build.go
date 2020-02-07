package module

import (
	"bytes"
	"fmt"
	"os/exec"
	"path"
)

const moduleExtension = "ko"

type BuildConfig struct {
	KernelBuildDir string
	ModuleDir      string
	ModuleVersion  string
	ModuleName     string
	DeviceName     string
}

func Build(cfg BuildConfig) error {
	// Create necessary makefile
	makefilePath := path.Join(cfg.ModuleDir, "Makefile")
	if err := createMakefile(makefilePath, "falco", cfg.KernelBuildDir, cfg.ModuleDir); err != nil {
		return fmt.Errorf("error creating the module Makefile: %v", err)
	}
	// Create the driver_config.h
	driverConfigPath := path.Join(cfg.ModuleDir, "driver_config.h")
	if err := createDriverConfig(driverConfigPath, cfg.ModuleVersion, cfg.ModuleName, cfg.DeviceName); err != nil {
		return fmt.Errorf("error creating the module Makefile: %v", err)
	}
	// Build the module against the designed kernel
	cmd := exec.Command(
		"make",
		fmt.Sprintf("M=%s", cfg.ModuleDir),
		"-C",
		cfg.KernelBuildDir,
		"modules",
	)
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("error compiling the kernel module: %s", errBuf.String())
	}

	// Strip debugging symbols
	cmd = exec.Command("strip", "-g", path.Join(cfg.ModuleDir, fmt.Sprintf("%s.%s", cfg.ModuleName, moduleExtension)))
	cmd.Stderr = &errBuf
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("error stripping debbuging symbols from the kernel module: %s", errBuf.String())
	}
	return nil
}
