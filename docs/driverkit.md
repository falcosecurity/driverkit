## driverkit

A command line tool to build Falco kernel modules.

```
driverkit
```

### Options

```
      --architecture string        target architecture for the built driver, one of [amd64,arm64] (default "amd64")
      --builderimage string        docker image to be used to build the kernel module. If not provided, an automatically selected image will be used.
      --builderrepo strings        list of docker repositories or yaml file (absolute path) containing builder images index with the format 'images: [ { target:<target>, name:<image-name>, arch: <arch>, tag: <imagetag>, gcc_versions: [ <gcc-tag> ] },...]', in descending priority order. Used to search for builder images. eg: --builderrepo myorg/driverkit-builder --builderrepo falcosecurity/driverkit-builder --builderrepo '/path/to/my/index.yaml'. (default [docker.io/falcosecurity/driverkit-builder])
  -c, --config string              config file path (default $HOME/.driverkit.yaml if exists)
      --driverversion string       driver version as a git commit hash or as a git tag (default "master")
      --dryrun                     do not actually perform the action
      --gccversion string          enforce a specific gcc version for the build
  -h, --help                       help for driverkit
      --kernelconfigdata string    base64 encoded kernel config data: in some systems it can be found under the /boot directory, in other it is gzip compressed under /proc
      --kernelrelease string       kernel release to build the module for, it can be found by executing 'uname -v'
      --kernelurls strings         list of kernel header urls (e.g. --kernelurls <URL1> --kernelurls <URL2> --kernelurls "<URL3>,<URL4>")
      --kernelversion string       kernel version to build the module for, it's the numeric value after the hash when you execute 'uname -v' (default "1")
  -l, --loglevel string            set level for logs (info, warn, debug, trace) (default "info")
      --moduledevicename string    kernel module device name (the default is falco, so the device will be under /dev/falco*) (default "falco")
      --moduledrivername string    kernel module driver name, i.e. the name you see when you check installed modules via lsmod (default "falco")
      --output-module string       filepath where to save the resulting kernel module
      --proxy string               the proxy to use to download data
      --registry-name string       registry name to which authenticate
      --registry-password string   registry password
      --registry-plain-http        allows interacting with remote registry via plain http requests
      --registry-user string       registry username
      --repo-name string           repository github name (default "libs")
      --repo-org string            repository github organization (default "falcosecurity")
  -t, --target string              the system to target the build for, one of [alinux,almalinux,amazonlinux,amazonlinux2,amazonlinux2022,amazonlinux2023,arch,bottlerocket,centos,debian,fedora,flatcar,minikube,ol,opensuse,photon,redhat,rocky,sles,talos,ubuntu,vanilla]
      --timeout int                timeout in seconds (default 120)
```

### SEE ALSO

* [driverkit completion](driverkit_completion.md)	 - Generates completion scripts.
* [driverkit docker](driverkit_docker.md)	 - Build Falco kernel modules against a docker daemon.
* [driverkit images](driverkit_images.md)	 - List builder images
* [driverkit kubernetes](driverkit_kubernetes.md)	 - Build Falco kernel modules against a Kubernetes cluster.
* [driverkit kubernetes-in-cluster](driverkit_kubernetes-in-cluster.md)	 - Build Falco kernel modules against a Kubernetes cluster inside a Kubernetes cluster.
* [driverkit local](driverkit_local.md)	 - Build Falco kernel modules in local env with local kernel sources and gcc/clang.

