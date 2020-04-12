## driverkit

A command line tool to build Falco kernel modules and eBPF probes.

### Synopsis

A command line tool to build Falco kernel modules and eBPF probes.

```
driverkit
```

### Options

```
  -c, --config string             config file path (default $HOME/.driverkit.yaml if exists)
      --driverversion string      driver version as a git commit hash or as a git tag (default "dev")
      --dryrun                    do not actually perform the action
  -h, --help                      help for driverkit
      --kernelconfigdata string   base64 encoded kernel config data: in some systems it can be found under the /boot directory, in other it is gzip compressed under /proc
      --kernelrelease string      kernel release to build the module for, it can be found by executing 'uname -v'
      --kernelversion uint16      kernel version to build the module for, it's the numeric value after the hash when you execute 'uname -v' (default 1)
  -l, --loglevel string           log level (default "info")
      --output-module string      filepath where to save the resulting kernel module
      --output-probe string       filepath where to save the resulting eBPF probe
  -t, --target string             the system to target the build for
      --timeout int               timeout in seconds (default 60)
```

### SEE ALSO

* [driverkit completion](driverkit_completion.md)	 - Generates completion scripts.
* [driverkit docker](driverkit_docker.md)	 - Build Falco kernel modules and eBPF probes against a docker daemon.
* [driverkit kubernetes](driverkit_kubernetes.md)	 - Build Falco kernel modules and eBPF probes against a Kubernetes cluster.

