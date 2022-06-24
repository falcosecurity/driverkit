package builder

import (
	"bytes"
	"text/template"
)

// TargetTypeRedhat identifies the redhat target.
const TargetTypeRedhat Type = "redhat"

// redhat is a driverkit target.
type redhat struct {
}

func init() {
	BuilderByTarget[TargetTypeRedhat] = &redhat{}
}

type redhatTemplateData struct {
	DriverBuildDir    string
	KernelPackage     string
	ModuleDownloadURL string
	ModuleDriverName  string
	ModuleFullPath    string
	BuildModule       bool
	BuildProbe        bool
}

const redhatTemplate = `
#!/bin/bash
set -xeuo pipefail

rm -Rf {{ .DriverBuildDir }}
mkdir {{ .DriverBuildDir }}
rm -Rf /tmp/module-download
mkdir -p /tmp/module-download

curl --silent -SL {{ .ModuleDownloadURL }} | tar -xzf - -C /tmp/module-download
mv /tmp/module-download/*/driver/* {{ .DriverBuildDir }}

cp /driverkit/module-Makefile {{ .DriverBuildDir }}/Makefile
bash /driverkit/fill-driver-config.sh {{ .DriverBuildDir }}

# Fetch the kernel
rm -Rf /tmp/kernel-download
mkdir /tmp/kernel-download
cd /tmp/kernel-download
yum install -y --downloadonly --downloaddir=/tmp/kernel-download kernel-devel-0:{{ .KernelPackage }}
rpm2cpio kernel-devel-{{ .KernelPackage }}.rpm | cpio --extract --make-directories

rm -Rf /tmp/kernel
mkdir -p /tmp/kernel
mv usr/src/kernels/*/* /tmp/kernel

{{ if .BuildModule }}
# Build the module
cd {{ .DriverBuildDir }}
make KERNELDIR=/tmp/kernel
mv {{ .ModuleDriverName }}.ko {{ .ModuleFullPath }}
strip -g {{ .ModuleFullPath }}
# Print results
modinfo {{ .ModuleFullPath }}
{{ end }}

{{ if .BuildProbe }}
# Build the eBPF probe
cd {{ .DriverBuildDir }}/bpf
make LLC=/usr/bin/llc CLANG=/usr/bin/clang CC=/usr/bin/gcc KERNELDIR=/tmp/kernel
ls -l probe.o
{{ end }}
`

func (v redhat) Script(cfg Config) (string, error) {
    t := template.New(string(TargetTypeRedhat))
  	parsed, err := t.Parse(redhatTemplate)
  	if err != nil {
  		return "", err
  	}

    kr := kernelReleaseFromBuildConfig(cfg.Build)

  	td := redhatTemplateData{
  	    DriverBuildDir:    DriverDirectory,
  	    KernelPackage:     kr.Fullversion + kr.FullExtraversion,
  	    ModuleDownloadURL: moduleDownloadURL(cfg),
  	    ModuleDriverName:  cfg.DriverName,
  	    ModuleFullPath:    ModuleFullPath,
  	    BuildModule:       len(cfg.Build.ModuleFilePath) > 0,
  	    BuildProbe:        len(cfg.Build.ProbeFilePath) > 0,
  	}

  	buf := bytes.NewBuffer(nil)
  	err = parsed.Execute(buf, td)
  	if err != nil {
  	    return "", err
  	}
  	return buf.String(), nil
}
