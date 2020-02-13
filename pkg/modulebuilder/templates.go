package modulebuilder

import (
	"io"
	"text/template"
)

type makefileData struct {
	ModuleName     string
	KernelBuildDir string
	ModuleBuildDir string
}

const makefileTemplate = `
{{ .ModuleName }}-y += main.o dynamic_params_table.o fillers_table.o flags_table.o ppm_events.o ppm_fillers.o event_table.o syscall_table.o ppm_cputime.o
obj-m += {{ .ModuleName }}.o

all:
	make -C {{ .KernelBuildDir }} M={{ .ModuleBuildDir }} modules

clean:
	make -C {{ .KernelBuildDir }} M={{ .KernelBuildDir }} clean

install: all
	make -C {{ .KernelBuildDir }} M={{ .KernelBuildDir }} modules_install
`

func renderMakefile(w io.Writer, md makefileData) error {
	t := template.New("makefile")
	t, _ = t.Parse(makefileTemplate)
	return t.Execute(w, md)
}


type driverConfigData struct {
	ModuleVersion string
	ModuleName    string
	DeviceName    string
}

// TODO(fntlnz): these variables are still called probes because of how the driver code
// references to them. We must change the driver code and then change here to s/PROBE_*/MODULE_*/g
const driverConfigTemplate = `
#pragma once

#define PROBE_VERSION "{{ .ModuleVersion }}"

#define PROBE_NAME "{{ .ModuleName }}"

#define PROBE_DEVICE_NAME "{{ .DeviceName }}"
`

func renderDriverConfig(w io.Writer, dd driverConfigData) error {
	t := template.New("driverconfig")
	parsed, err := t.Parse(driverConfigTemplate)
	if err != nil {
		return err
	}
	return parsed.Execute(w, dd)
}

