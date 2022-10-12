package driverbuilder

import (
	"fmt"
	"github.com/falcosecurity/driverkit/pkg/driverbuilder/builder"
	"io"
	"net/http"
	"strings"
	"text/template"
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

type makefileData struct {
	ModuleName     string
	ModuleBuildDir string
	MakeObjList    string
}

const makefileTemplate = `
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

func renderMakefile(w io.Writer, md makefileData) error {
	t := template.New("makefile")
	t, _ = t.Parse(makefileTemplate)
	return t.Execute(w, md)
}

func LoadMakefileObjList(c builder.Config) (string, error) {
	makefileUrl := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/driver/Makefile.in", c.RepoOrg, c.RepoName, c.DriverVersion)
	resp, err := http.Get(makefileUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	parsedMakefile, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(parsedMakefile), "\n")
	for _, l := range lines {
		if strings.HasPrefix(l, "@DRIVER_NAME@-y +=") {
			return strings.Split(l, "@DRIVER_NAME@-y += ")[1], nil
		}
		if strings.HasPrefix(l, "@PROBE_NAME@-y +=") {
            return strings.Split(l, "@PROBE_NAME@-y += ")[1], nil
		}
	}
	return "", fmt.Errorf("obj list not found")
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
