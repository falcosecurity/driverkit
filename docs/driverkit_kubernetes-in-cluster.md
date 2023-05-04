## driverkit kubernetes-in-cluster

Build Falco kernel modules and eBPF probes against a Kubernetes cluster inside a Kubernetes cluster.

```
driverkit kubernetes-in-cluster [flags]
```

### Options

```
      --architecture string        target architecture for the built driver, one of [amd64,arm64] (default "amd64")
      --builderimage string        docker image to be used to build the kernel module and eBPF probe. If not provided, an automatically selected image will be used.
      --builderrepo strings        list of docker repositories or yaml file (absolute path) containing builder images index with the format 'images: [ { target:<target>, name:<image-name>, gcc_versions: [ <gcc-tag> ] },...]', in descending priority order. Used to search for builder images. eg: --builderrepo myorg/driverkit --builderrepo falcosecurity/driverkit --builderrepo '/path/to/my/index.yaml'. (default [docker.io/falcosecurity/driverkit])
  -c, --config string              config file path (default $HOME/.driverkit.yaml if exists)
      --driverversion string       driver version as a git commit hash or as a git tag (default "master")
      --dryrun                     do not actually perform the action
      --gccversion string          enforce a specific gcc version for the build
  -h, --help                       help for kubernetes-in-cluster
      --image-pull-secret string   ImagePullSecret
      --kernelconfigdata string    base64 encoded kernel config data: in some systems it can be found under the /boot directory, in other it is gzip compressed under /proc
      --kernelrelease string       kernel release to build the module for, it can be found by executing 'uname -v'
      --kernelurls strings         list of kernel header urls (e.g. --kernelurls <URL1> --kernelurls <URL2> --kernelurls "<URL3>,<URL4>")
      --kernelversion string       kernel version to build the module for, it's the numeric value after the hash when you execute 'uname -v' (default "1")
  -l, --loglevel string            log level (default "info")
      --moduledevicename string    kernel module device name (the default is falco, so the device will be under /dev/falco*) (default "falco")
      --moduledrivername string    kernel module driver name, i.e. the name you see when you check installed modules via lsmod (default "falco")
  -n, --namespace string           If present, the namespace scope for the pods and its config  (default "default")
      --output-module string       filepath where to save the resulting kernel module
      --output-probe string        filepath where to save the resulting eBPF probe
      --proxy string               the proxy to use to download data
      --repo-name string           repository github name (default "libs")
      --repo-org string            repository github organization (default "falcosecurity")
      --run-as-user int            Pods runner user
  -t, --target string              the system to target the build for, one of [alinux,almalinux,amazonlinux,amazonlinux2,amazonlinux2022,amazonlinux2023,arch,bottlerocket,centos,debian,fedora,flatcar,minikube,ol,opensuse,photon,redhat,rocky,talos,ubuntu,vanilla]
      --timeout int                timeout in seconds (default 120)
```

### SEE ALSO

* [driverkit](driverkit.md)	 - A command line tool to build Falco kernel modules and eBPF probes.

