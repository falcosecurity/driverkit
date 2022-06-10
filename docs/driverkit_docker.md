## driverkit docker

Build Falco kernel modules and eBPF probes against a docker daemon.

### Synopsis

Build Falco kernel modules and eBPF probes against a docker daemon.

```
driverkit docker [flags]
```

### Options

```
      --architecture string       target architecture for the built driver (default "$runtime.GOARCH")
  -c, --config string             config file path (default $HOME/.driverkit.yaml if exists)
      --driverversion string      driver version as a git commit hash or as a git tag (default "master")
      --dryrun                    do not actually perform the action
  -h, --help                      help for docker
      --kernelconfigdata string   base64 encoded kernel config data: in some systems it can be found under the /boot directory, in other it is gzip compressed under /proc
      --kernelrelease string      kernel release to build the module for, it can be found by executing 'uname -v'
      --kernelurls []string       list of kernel header urls (e.g. --kernelurls <URL1> --kernelurls <URL2> --kernelurls "<URL3>,<URL4>")
      --kernelversion uint16      kernel version to build the module for, it's the numeric value after the hash when you execute 'uname -v' (default 1)
  -l, --loglevel string           log level (default "info")
      --moduledevicename string   kernel module device name (the default is falco, so the device will be under /dev/falco*) (default "falco")
      --moduledrivername string   kernel module driver name, i.e. the name you see when you check installed modules via lsmod (default "falco")
      --output-module string      filepath where to save the resulting kernel module
      --output-probe string       filepath where to save the resulting eBPF probe
      --proxy string              the proxy to use to download data
  -t, --target string             the system to target the build for
      --timeout int               timeout in seconds (default 120)
```

### SEE ALSO

* [driverkit](driverkit.md)	 - A command line tool to build Falco kernel modules and eBPF probes.

