## driverkit kubernetes

Build Falco kernel modules against a Kubernetes cluster.

```
driverkit kubernetes [flags]
```

### Options

```
      --architecture string            target architecture for the built driver, one of [amd64,arm64] (default "amd64")
      --as string                      username to impersonate for the operation, user could be a regular user or a service account in a namespace
      --as-group stringArray           group to impersonate for the operation, this flag can be repeated to specify multiple groups
      --as-uid string                  uID to impersonate for the operation
      --builderimage string            docker image to be used to build the kernel module. If not provided, an automatically selected image will be used.
      --builderrepo strings            list of docker repositories or yaml file (absolute path) containing builder images index with the format 'images: [ { target:<target>, name:<image-name>, arch: <arch>, tag: <imagetag>, gcc_versions: [ <gcc-tag> ] },...]', in descending priority order. Used to search for builder images. eg: --builderrepo myorg/driverkit-builder --builderrepo falcosecurity/driverkit-builder --builderrepo '/path/to/my/index.yaml'. (default [docker.io/falcosecurity/driverkit-builder])
      --cache-dir string               default cache directory (default "$HOME/.kube/cache")
      --certificate-authority string   path to a cert file for the certificate authority
      --client-certificate string      path to a client certificate file for TLS
      --client-key string              path to a client key file for TLS
      --cluster string                 the name of the kubeconfig cluster to use
  -c, --config string                  config file path (default $HOME/.driverkit.yaml if exists)
      --context string                 the name of the kubeconfig context to use
      --disable-compression            if true, opt-out of response compression for all requests to the server
      --driverversion string           driver version as a git commit hash or as a git tag (default "master")
      --dryrun                         do not actually perform the action
      --gccversion string              enforce a specific gcc version for the build
  -h, --help                           help for kubernetes
      --image-pull-secret string       ImagePullSecret
      --insecure-skip-tls-verify       if true, the server's certificate will not be checked for validity, this will make your HTTPS connections insecure
      --kernelconfigdata string        base64 encoded kernel config data: in some systems it can be found under the /boot directory, in other it is gzip compressed under /proc
      --kernelrelease string           kernel release to build the module for, it can be found by executing 'uname -v'
      --kernelurls strings             list of kernel header urls (e.g. --kernelurls <URL1> --kernelurls <URL2> --kernelurls "<URL3>,<URL4>")
      --kernelversion string           kernel version to build the module for, it's the numeric value after the hash when you execute 'uname -v' (default "1")
      --kubeconfig string              path to the kubeconfig file to use for CLI requests
  -l, --loglevel string                set level for logs (info, warn, debug, trace) (default "info")
      --moduledevicename string        kernel module device name (the default is falco, so the device will be under /dev/falco*) (default "falco")
      --moduledrivername string        kernel module driver name, i.e. the name you see when you check installed modules via lsmod (default "falco")
  -n, --namespace string               If present, the namespace scope for the pods and its config  (default "default")
      --output-module string           filepath where to save the resulting kernel module
      --proxy string                   the proxy to use to download data
      --registry-name string           registry name to which authenticate
      --registry-password string       registry password
      --registry-plain-http            allows interacting with remote registry via plain http requests
      --registry-user string           registry username
      --repo-name string               repository github name (default "libs")
      --repo-org string                repository github organization (default "falcosecurity")
      --request-timeout string         the length of time to wait before giving up on a single server request, non-zero values should contain a corresponding time unit (e.g, 1s, 2m, 3h), a value of zero means don't timeout requests (default "0")
      --run-as-user int                Pods runner user
  -s, --server string                  the address and port of the Kubernetes API server
  -t, --target string                  the system to target the build for, one of [alinux,almalinux,amazonlinux,amazonlinux2,amazonlinux2022,amazonlinux2023,arch,bottlerocket,centos,debian,fedora,flatcar,minikube,ol,opensuse,photon,redhat,rocky,sles,talos,ubuntu,vanilla]
      --timeout int                    timeout in seconds (default 120)
      --tls-server-name string         server name to use for server certificate validation, if it is not provided, the hostname used to contact the server is used
      --token string                   bearer token for authentication to the API server
      --user string                    the name of the kubeconfig user to use
```

### SEE ALSO

* [driverkit](driverkit.md)	 - A command line tool to build Falco kernel modules.

