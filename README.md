# driverkit

[![Latest](https://img.shields.io/github/v/release/falcosecurity/driverkit?style=for-the-badge)](https://github.com/falcosecurity/driverkit/releases/latest)
![Architectures](https://img.shields.io/badge/ARCHS-x86__64%7Caarch64-blueviolet?style=for-the-badge)
[![Go Report Card](https://goreportcard.com/badge/github.com/falcosecurity/driverkit?style=for-the-badge)](https://goreportcard.com/report/github.com/falcosecurity/driverkit)
[![Docker pulls](https://img.shields.io/docker/pulls/falcosecurity/driverkit?style=for-the-badge)](https://hub.docker.com/r/falcosecurity/driverkit)

A command line tool that can be used to build the [Falco](https://github.com/falcosecurity/falco) kernel module and eBPF probe.

## Glossary

When you meet `kernelversion` that refers to the version you get executing `uname -v`:

For example, below, the version is the `59` after the hash

```bash
uname -v
#59-Ubuntu SMP Wed Dec 4 10:02:00 UTC 2019
```

When you meet `kernelrelease`, that refers to the kernel release you get executing `uname -r`:

```
uname -r
4.15.0-1057-aws
```

## Help

By checking driverkit help, you can quickly discover info about:
* Supported options
* Supported commands
* Supported architectures
* Supported targets
* Default options

```
driverkit help
```

## Architecture

The target architecture is taken from runtime environment, but it can be overridden through `architecture` config.  
Driverkit also supports cross building for arm64 using qemu from an x86_64 host.

> **NOTE:** we could not automatically fetch correct architecture given a kernelrelease,
> because some kernel names do not have any architecture suffix, namely Ubuntu ones.

## Headers

Driverkit has an internal logic to retrieve headers urls given a target and desired kernelrelease/kernelversion.  
Unfortunately, the logic is quite hard to implement correctly for every supported target.   
As of today, the preferred method is to instead use the `kernelurls` configuration param,  
that allows to specify a list of headers.

> **NOTE:** the internal headers fetching logic should be considered a fallback that will be, sooner or later, deprecated.  

A solution to crawl all supported kernels by multiple distro was recently developed,  
and it provides a json output with aforementioned `kernelheaders`: https://github.com/falcosecurity/kernel-crawler.  
Json for supported architectures can be found at https://falcosecurity.github.io/kernel-crawler/.

## How to use

### Against a Kubernetes cluster

```bash
driverkit kubernetes --output-module /tmp/falco.ko --kernelversion=81 --kernelrelease=4.15.0-72-generic --driverversion=master --target=ubuntu-generic
```

### Against a Docker daemon

```bash
driverkit docker --output-module /tmp/falco.ko --kernelversion=81 --kernelrelease=4.15.0-72-generic --driverversion=master --target=ubuntu-generic
```

### Build using a configuration file

Create a file named `ubuntu-aws.yaml` containing the following content:

```yaml
kernelrelease: 4.15.0-1057-aws
kernelversion: 59
target: ubuntu-aws
output:
  module: /tmp/falco-ubuntu-aws.ko
  probe: /tmp/falco-ubuntu-aws.o
driverversion: master
```

Now run driverkit using the configuration file:

```bash
driverkit docker -c ubuntu-aws.yaml
```

### Configure the kernel module name

It is possible to customize the kernel module name that is produced by Driverkit with the `moduledevicename` and `moduledrivername` options.
In this context, the _device name_ is the prefix used for the devices in `/dev/`, while the _driver name_ is the kernel module name as reported by `modinfo` or `lsmod` once the module is loaded.

## Examples

For a comprehensive list of examples, heads to [example configs](Example_configs.md)!

## Support a new target

To add support for a new target, a new builder must be added.  
For more info, you can find specific docs in [docs/builder.md](docs/builder.md) file.

## Support a new builder image

To add support for a new builder image, follow the doc at [docs/builder_images.md](docs/builder_images.md) file.

## Survey

We are conducting a [survey](http://bit.ly/driverkit-survey-vote) to know what is the most interesting set of Operating Systems we must support first in driverkit.

You can find the results of the survey [here](http://bit.ly/driverkit-survey-results)
