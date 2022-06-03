## driverkit kubernetes

Build Falco kernel modules and eBPF probes against a Kubernetes cluster.

### Synopsis

Build Falco kernel modules and eBPF probes against a Kubernetes cluster.

```
driverkit kubernetes [flags]
```

### Options

```
      --architecture string            target architecture for the built driver (default "$runtime.GOARCH")
      --as string                      username to impersonate for the operation
      --as-group stringArray           group to impersonate for the operation, this flag can be repeated to specify multiple groups
      --cache-dir string               default HTTP cache directory (default "$HOME/.kube/http-cache")
      --certificate-authority string   path to a cert file for the certificate authority
      --client-certificate string      path to a client certificate file for TLS
      --client-key string              path to a client key file for TLS
      --cluster string                 the name of the kubeconfig cluster to use
  -c, --config string                  config file path (default $HOME/.driverkit.yaml if exists)
      --context string                 the name of the kubeconfig context to use
      --driverversion string           driver version as a git commit hash or as a git tag (default "master")
      --dryrun                         do not actually perform the action
  -h, --help                           help for kubernetes
      --insecure-skip-tls-verify       if true, the server's certificate will not be checked for validity, this will make your HTTPS connections insecure
      --kernelconfigdata string        base64 encoded kernel config data: in some systems it can be found under the /boot directory, in other it is gzip compressed under /proc
      --kernelrelease string           kernel release to build the module for, it can be found by executing 'uname -v'
      --kernelversion uint16           kernel version to build the module for, it's the numeric value after the hash when you execute 'uname -v' (default 1)
      --kubeconfig string              path to the kubeconfig file to use for CLI requests
  -l, --loglevel string                log level (default "info")
      --moduledevicename string        kernel module device name (the default is falco, so the device will be under /dev/falco*) (default "falco")
      --moduledrivername string        kernel module driver name, i.e. the name you see when you check installed modules via lsmod (default "falco")
  -n, --namespace string               if present, the namespace scope for this CLI request
      --output-module string           filepath where to save the resulting kernel module
      --output-probe string            filepath where to save the resulting eBPF probe
      --proxy string                   the proxy to use to download data
      --request-timeout string         the length of time to wait before giving up on a single server request, non-zero values should contain a corresponding time unit (e.g, 1s, 2m, 3h), a value of zero means don't timeout requests (default "0")
  -s, --server string                  the address and port of the Kubernetes API server
  -t, --target string                  the system to target the build for
      --timeout int                    timeout in seconds (default 120)
      --token string                   bearer token for authentication to the API server
      --user string                    the name of the kubeconfig user to use
```

### SEE ALSO

* [driverkit](driverkit.md)	 - A command line tool to build Falco kernel modules and eBPF probes.

