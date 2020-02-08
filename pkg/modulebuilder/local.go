package modulebuilder

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strings"

	"github.com/falcosecurity/build-service/pkg/modinfo"
)

type LocalBuilder struct {
	cfg Config
}

func NewLocalBuilderFromConfig(cfg Config) LocalBuilder {
	return LocalBuilder{
		cfg: cfg,
	}
}

func (b LocalBuilder) Build() error {
	err := b.BuildKernel()
	if err != nil {
		return err
	}
	return b.BuildModule()
}

func buildMakeInKernelDirCommandArguments(command, kernelDir, moduleDir, configPath string) []string {
	args := []string{}

	if command == "modules" {
		args = append(args, fmt.Sprintf("M=%s", moduleDir))
	}

	args = append(args, []string{
		fmt.Sprintf("KCONFIG_CONFIG=%s", configPath),
		"-C",
		kernelDir,
		command,
	}...)
	return args
}

func kernelConfigFile(kernelConfigContent string, kernelVersion string) (*os.File, error) {
	sp := strings.SplitN(kernelVersion, "-", 2)
	localVersion := ""
	if len(sp) == 2 {
		localVersion = sp[1]
	}

	file, err := ioutil.TempFile(os.TempDir(), "kernelconfig")
	if err != nil {
		return nil, err
	}

	configStr := fmt.Sprintf("%s\nCONFIG_LOCALVERSION=\"-%s\"\n", kernelConfigContent, localVersion)
	if _, err := file.WriteString(configStr); err != nil {
		return nil, err
	}
	return file, nil
}

func makeInKernelDir(command, kernelDir, moduleDir string, kernelConfigContent string, kernelVersion string) error {
	makeCmd, err := exec.LookPath("make")
	if err != nil {
		return fmt.Errorf("make not found in PATH")
	}
	file, err := kernelConfigFile(kernelConfigContent, kernelVersion)
	defer file.Close()
	defer os.Remove(file.Name())

	cmd := exec.Command(makeCmd, buildMakeInKernelDirCommandArguments(command, kernelDir, moduleDir, file.Name())...)
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("makeInKernelDir error: %s", errBuf.String())
	}
	return nil
}

func (b LocalBuilder) makeInKernelDir(command string) error {
	return makeInKernelDir(command, b.cfg.KernelDir, b.cfg.ModuleDir, b.cfg.KernelConfigData, b.cfg.KernelVersion)
}

func (b LocalBuilder) BuildKernel() error {
	err := b.makeInKernelDir("oldconfig")
	if err != nil {
		return err
	}
	err = b.makeInKernelDir("prepare")
	if err != nil {
		return err
	}
	err = b.makeInKernelDir("modules_prepare")
	if err != nil {
		return err
	}
	return nil
}

func (b LocalBuilder) BuildModule() error {
	// Create necessary makefile
	makefilePath := path.Join(b.cfg.ModuleDir, "Makefile")
	if err := createMakefile(makefilePath, "falco", b.cfg.KernelDir, b.cfg.ModuleDir); err != nil {
		return fmt.Errorf("error creating the module Makefile: %v", err)
	}
	// Create the driver_config.h
	driverConfigPath := path.Join(b.cfg.ModuleDir, "driver_config.h")
	if err := createDriverConfig(driverConfigPath, b.cfg.ModuleVersion, b.cfg.ModuleName, b.cfg.DeviceName); err != nil {
		return fmt.Errorf("error creating the module Makefile: %v", err)
	}
	// Build the module against the designed kernel
	if err := b.makeInKernelDir("modules"); err != nil {
		return err
	}

	modulePath := path.Join(b.cfg.ModuleDir, fmt.Sprintf("%s.%s", b.cfg.ModuleName, moduleExtension))
	// Strip debugging symbols
	cmd := exec.Command("strip", "-g", modulePath)

	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
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
