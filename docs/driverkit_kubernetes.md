## driverkit kubernetes

Build Falco kernel modules and eBPF probes against a Kubernetes cluster.

### Synopsis

Build Falco kernel modules and eBPF probes against a Kubernetes cluster.

```
driverkit kubernetes [flags]
```

### Options

```
      --as string                      Username to impersonate for the operation
      --as-group stringArray           Group to impersonate for the operation, this flag can be repeated to specify multiple groups.
      --cache-dir string               Default HTTP cache directory (default "$HOME/.kube/http-cache")
      --certificate-authority string   Path to a cert file for the certificate authority
      --client-certificate string      Path to a client certificate file for TLS
      --client-key string              Path to a client key file for TLS
      --cluster string                 The name of the kubeconfig cluster to use
      --context string                 The name of the kubeconfig context to use
  -h, --help                           help for kubernetes
      --insecure-skip-tls-verify       If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure
      --kubeconfig string              Path to the kubeconfig file to use for CLI requests.
  -n, --namespace string               If present, the namespace scope for this CLI request
      --request-timeout string         The length of time to wait before giving up on a single server request. Non-zero values should contain a corresponding time unit (e.g. 1s, 2m, 3h). A value of zero means don't timeout requests. (default "0")
  -s, --server string                  The address and port of the Kubernetes API server
      --token string                   Bearer token for authentication to the API server
      --user string                    The name of the kubeconfig user to use
```

### Options inherited from parent commands

```
  -c, --config string             config file path (default $HOME/.driverkit.yaml if exists)
      --driverversion string      driver version as a git commit hash or as a git tag (default "dev")
      --dryrun                    do not actually perform the action
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

* [driverkit](driverkit.md)	 - A command line tool to build Falco kernel modules and eBPF probes.

