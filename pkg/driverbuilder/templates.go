package driverbuilder

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"text/template"

	"github.com/falcosecurity/driverkit/pkg/driverbuilder/builder"
)

var waitForLockScript = `
touch /tmp/download.lock
while true; do
  if [ -f /tmp/download.lock ]; then
    echo "Lock not released yet - waiting for 5 seconds"
    sleep 5
    continue
  fi
  echo "download lock was released, we can exit now"
  break
done
`

var deleteLock = `
rm -f /tmp/download.lock
`

const moduleLockFile = "/tmp/module.lock"
const probeLockFile = "/tmp/probe.lock"

// waitForLockAndCat MUST only output the file, any other output will break
// the download file itself because it goes trough stdout
var waitForLockAndCat = `
while true; do
  if [ -f "$2" ]; then
	sleep 10 1>&/dev/null
	continue
  fi
  break
done
cat "$1"
`

type makefileKmodData struct {
	ModuleName     string
	ModuleBuildDir string
	MakeObjList    string
}

const makefileKmodTemplate = `
{{ .ModuleName }}-y += {{ .MakeObjList }}
obj-m += {{ .ModuleName }}.o
KERNELDIR ?= /lib/modules/$(shell uname -r)/build

all:
	make -C $(KERNELDIR) M={{ .ModuleBuildDir }} modules

clean:
	make -C $(KERNELDIR) M={{ .ModuleBuildDir }} clean

install: all
	make -C $(KERNELDIR) M={{ .ModuleBuildDir }} modules_install
`

func renderKmodMakefile(w io.Writer, md makefileKmodData) error {
	t := template.New("kmod-makefile")
	t, _ = t.Parse(makefileKmodTemplate)
	return t.Execute(w, md)
}

func LoadKmodMakefile(buffer *bytes.Buffer, c builder.Config) error {
	objList, err := loadKmodMakefileObjList(c)
	if err != nil {
		return err
	}
	return renderKmodMakefile(buffer, makefileKmodData{ModuleName: c.DriverName, ModuleBuildDir: builder.DriverDirectory, MakeObjList: objList})
}

func loadKmodMakefileObjList(c builder.Config) (string, error) {
	parsedMakefile, err := downloadFile(fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/driver/Makefile.in", c.RepoOrg, c.RepoName, c.DriverVersion))
	if err != nil {
		return "", err
	}
	lines := strings.Split(parsedMakefile, "\n")
	for _, l := range lines {
		if strings.HasPrefix(l, "@DRIVER_NAME@-y +=") {
			return strings.Split(l, "@DRIVER_NAME@-y += ")[1], nil
		}
		if strings.HasPrefix(l, "@PROBE_NAME@-y +=") {
			return strings.Split(l, "@PROBE_NAME@-y += ")[1], nil
		}
	}
	return "", fmt.Errorf("kmod obj list not found")
}

type makefileBpfData struct {
	MakeObjList string
}

const makefileBpfTemplate = `
always-y += probe.o
always = $(always-y)

LLC ?= llc
CLANG ?= clang

KERNELDIR ?= /lib/modules/$(shell uname -r)/build

NEEDS_COS_73_WORKAROUND = $(shell expr ` + "`" + `grep -sc "^\s*struct\s\+audit_task_info\s\+\*audit;\s*$$" $(KERNELDIR)/include/linux/sched.h` + "`" + ` = 1) 
ifeq ($(NEEDS_COS_73_WORKAROUND), 1)
	KBUILD_CPPFLAGS += -DCOS_73_WORKAROUND
endif

IS_CLANG_OLDER_THAN_10 := $(shell expr ` + "`$(CLANG) -dumpversion | cut -f1 -d.`" + ` \<= 10)
ifeq ($(IS_CLANG_OLDER_THAN_10), 1)
	KBUILD_CPPFLAGS := $(filter-out -fmacro-prefix-map=%,$(KBUILD_CPPFLAGS))
endif

all:
	make -C $(KERNELDIR) M=$$PWD

clean:
	make -C $(KERNELDIR) M=$$PWD clean
	@rm -f *~

$(obj)/probe.o: {{ .MakeObjList }}
	$(CLANG) $(LINUXINCLUDE) \
		$(KBUILD_CPPFLAGS) \
		$(KBUILD_EXTRA_CPPFLAGS) \
		$(DEBUG) \
		-I.. \
		-D__KERNEL__ \
		-D__BPF_TRACING__ \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member \
		-fno-jump-tables \
		-fno-stack-protector \
		-Wno-tautological-compare \
		-O2 -g -emit-llvm -c $< -o $(patsubst %.o,%.ll,$@)
	$(LLC) -march=bpf -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)
`

func renderBpfMakefile(w io.Writer, md makefileBpfData) error {
	t := template.New("bpf-makefile")
	t, _ = t.Parse(makefileBpfTemplate)
	return t.Execute(w, md)
}

func LoadBpfMakefile(buffer *bytes.Buffer, c builder.Config) error {
	bpfMakefile, err := downloadFile(fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/driver/bpf/Makefile", c.RepoOrg, c.RepoName, c.DriverVersion))
	if err == nil {
		// Existent bpf/Makefile! (old libs versions, pre https://github.com/falcosecurity/libs/pull/1188)
		_, err = buffer.WriteString(bpfMakefile)
		return err
	}
	objList, err := loadBpfMakefileObjList(c)
	if err != nil {
		return err
	}
	return renderBpfMakefile(buffer, makefileBpfData{MakeObjList: objList})
}

func loadBpfMakefileObjList(c builder.Config) (string, error) {
	parsedCmakeLists, err := downloadFile(fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/driver/bpf/CMakeLists.txt", c.RepoOrg, c.RepoName, c.DriverVersion))
	if err != nil {
		return "", err
	}
	lines := strings.Split(parsedCmakeLists, "\n")
	startDeps := false
	var deps string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "set(BPF_SOURCES") {
			startDeps = true
		} else if startDeps {
			if l != ")" {
				if !strings.Contains(l, "${") {
					// skip sources that reference a cmake variable
					deps += "$(src)/" + l + " "
				}
			} else {
				deps += "$(src)/../driver_config.h"
				return deps, nil
			}
		}
	}
	return "", fmt.Errorf("bpf obj list not found")
}

type driverConfigData struct {
	DriverVersion string
	DriverName    string
	DeviceName    string
}

// XXX both PROBE and DRIVER variables are kept for now so that Driverkit is compatible with older versions.
// they can be removed when versions from early 2022/late 2021 will not be supported anymore.

// Note that in the future DRIVER_COMMIT will be different from DRIVER_VERSION. Currently, it is the same as the commit
// and no decision has been made yet about the distinction in falcosecurity/libs. Will need to be updated.
const fillDriverConfigTemplate = `
set -euxo pipefail

DRIVER_BUILD_DIR=$1
DRIVER_CONFIG_FILE="$DRIVER_BUILD_DIR/driver_config.h"

cat << EOF > $DRIVER_CONFIG_FILE
#pragma once

#define PROBE_VERSION "{{ .DriverVersion }}"
#define DRIVER_VERSION "{{ .DriverVersion }}"

#define DRIVER_COMMIT "{{ .DriverVersion }}"

#define PROBE_NAME "{{ .DriverName }}"
#define DRIVER_NAME "{{ .DriverName }}"

#define PROBE_DEVICE_NAME "{{ .DeviceName }}"
#define DRIVER_DEVICE_NAME "{{ .DeviceName }}"

#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME DRIVER_NAME
#endif
EOF

API_VERSION_FILE="$DRIVER_BUILD_DIR/API_VERSION"
if [[ -f $API_VERSION_FILE ]]; then
	PPM_API_CURRENT_VERSION_MAJOR=$(cut -f 1 -d . "$API_VERSION_FILE")
	PPM_API_CURRENT_VERSION_MINOR=$(cut -f 2 -d . "$API_VERSION_FILE")
	PPM_API_CURRENT_VERSION_PATCH=$(cut -f 3 -d . "$API_VERSION_FILE")

	echo "#define PPM_API_CURRENT_VERSION_MAJOR" $PPM_API_CURRENT_VERSION_MAJOR >> $DRIVER_CONFIG_FILE
	echo "#define PPM_API_CURRENT_VERSION_MINOR" $PPM_API_CURRENT_VERSION_MINOR >> $DRIVER_CONFIG_FILE
	echo "#define PPM_API_CURRENT_VERSION_PATCH" $PPM_API_CURRENT_VERSION_PATCH >> $DRIVER_CONFIG_FILE
fi

SCHEMA_VERSION_FILE="$DRIVER_BUILD_DIR/SCHEMA_VERSION"
if [[ -f $SCHEMA_VERSION_FILE ]]; then
	PPM_SCHEMA_CURRENT_VERSION_MAJOR=$(cut -f 1 -d . "$SCHEMA_VERSION_FILE")
	PPM_SCHEMA_CURRENT_VERSION_MINOR=$(cut -f 2 -d . "$SCHEMA_VERSION_FILE")
	PPM_SCHEMA_CURRENT_VERSION_PATCH=$(cut -f 3 -d . "$SCHEMA_VERSION_FILE")

	echo "#define PPM_SCHEMA_CURRENT_VERSION_MAJOR" $PPM_SCHEMA_CURRENT_VERSION_MAJOR >> $DRIVER_CONFIG_FILE
	echo "#define PPM_SCHEMA_CURRENT_VERSION_MINOR" $PPM_SCHEMA_CURRENT_VERSION_MINOR >> $DRIVER_CONFIG_FILE
	echo "#define PPM_SCHEMA_CURRENT_VERSION_PATCH" $PPM_SCHEMA_CURRENT_VERSION_PATCH >> $DRIVER_CONFIG_FILE

	echo '#include "ppm_api_version.h"' >> $DRIVER_CONFIG_FILE
fi
`

func renderFillDriverConfig(w io.Writer, dd driverConfigData) error {
	t := template.New("driverconfig")
	parsed, err := t.Parse(fillDriverConfigTemplate)
	if err != nil {
		return err
	}
	return parsed.Execute(w, dd)
}

func downloadFile(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("non-200 response")
	}
	file, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(file), nil
}
