package modulebuilder

import (
	"io"
	"text/template"

	"github.com/falcosecurity/driverkit/pkg/modulebuilder/builder"
)

var waitForModuleScript = `
touch /tmp/module-download.lock
while true; do
  if [ ! -f ` + builder.FalcoModuleFullPath + ` ]; then
    echo "Falco module not found - waiting for 10 seconds"
	sleep 10
	continue
  fi
  echo "module found, wait for the download lock to be released"
  if [ -f /tmp/module-download.lock ]; then
    echo "Lock not released yet - waiting for 5 seconds"
    sleep 5
    continue
  fi
  echo "download lock was released, we can exit now"
  break
done
`

// waitForModuleAndCat MUST only output the file, any other output will break
// the download file itself because it goes trough stdout
var waitForModuleAndCat = `
while true; do
  if [ ! -f ` + builder.FalcoModuleFullPath + ` ]; then
	sleep 10 1>&/dev/null
	continue
  fi
  break
done
cat ` + builder.FalcoModuleFullPath + `
rm /tmp/module-download.lock 1>&/dev/null
`

type makefileData struct {
	ModuleName     string
	ModuleBuildDir string
}

const makefileTemplate = `
{{ .ModuleName }}-y += main.o dynamic_params_table.o fillers_table.o flags_table.o ppm_events.o ppm_fillers.o event_table.o syscall_table.o ppm_cputime.o
obj-m += {{ .ModuleName }}.o
KERNELDIR ?= /lib/modules/$(shell uname -r)/build

all:
	make -C $(KERNELDIR) M={{ .ModuleBuildDir }} modules

clean:
	make -C $(KERNELDIR) M={{ .ModuleBuildDir }} clean

install: all
	make -C $(KERNELDIR) M={{ .ModuleBuildDir }} modules_install
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
