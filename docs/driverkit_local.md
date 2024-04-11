## driverkit local

Build Falco kernel modules and eBPF probes in local env with local kernel sources and gcc/clang.

```
driverkit local [flags]
```

### Options

```
  -c, --config string             config file path (default $HOME/.driverkit.yaml if exists)
      --dkms                      Enforce usage of DKMS to build the kernel module.
      --download-headers          Try to automatically download kernel headers.
      --driverversion string      driver version as a git commit hash or as a git tag (default "master")
      --dryrun                    do not actually perform the action
      --env stringToString        Env variables to be enforced during the driver build. (default [])
  -h, --help                      help for local
      --kernelrelease string      kernel release to build the module for, it can be found by executing 'uname -v'
      --kernelversion string      kernel version to build the module for, it's the numeric value after the hash when you execute 'uname -v' (default "1")
  -l, --loglevel string           Set level for logs (info, warn, debug, trace) (default "info")
      --moduledevicename string   kernel module device name (the default is falco, so the device will be under /dev/falco*) (default "falco")
      --moduledrivername string   kernel module driver name, i.e. the name you see when you check installed modules via lsmod (default "falco")
      --output-module string      filepath where to save the resulting kernel module
      --output-probe string       filepath where to save the resulting eBPF probe
      --repo-name string          repository github name (default "libs")
      --repo-org string           repository github organization (default "falcosecurity")
      --src-dir string            Enforce usage of local source dir to build drivers.
  -t, --target string             the system to target the build for, one of [alinux,almalinux,amazonlinux,amazonlinux2,amazonlinux2022,amazonlinux2023,arch,bottlerocket,centos,debian,fedora,flatcar,minikube,ol,opensuse,photon,redhat,rocky,sles,talos,ubuntu,vanilla]
      --timeout int               timeout in seconds (default 120)
```

### SEE ALSO

* [driverkit](driverkit.md)	 - A command line tool to build Falco kernel modules and eBPF probes.

