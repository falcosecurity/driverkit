# driverkit

Status: **Under development**

A command line tool that can be used to build the Falco kernel module and eBPF probe.


## Usage

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

## Supported architectures

At the moment, driverkit supports:
* amd64 (x86_64)
* arm64 (aarch64)

The architecture is taken from runtime environment, but it can be overridden through `architecture` config.  
Driverkit also supports cross building for arm64 using qemu from an x86_64 host.  

Note: we could not automatically fetch correct architecture because some kernel names do not have the `-$arch`, namely Ubuntu ones.

## Supported targets

### ubuntu-generic
Example configuration file to build both the Kernel module and eBPF probe for Ubuntu generic.

```yaml
kernelrelease: 4.15.0-72-generic
kernelversion: 81
target: ubuntu-generic
output:
  module: /tmp/falco-ubuntu-generic.ko
  probe: /tmp/falco-ubuntu-generic.o
driverversion: master
```

### ubuntu-aws

Example configuration file to build both the Kernel module and eBPF probe for Ubuntu AWS.

```yaml
kernelrelease: 4.15.0-1057-aws
kernelversion: 59
target: ubuntu-aws
output:
  module: /tmp/falco-ubuntu-aws.ko
  probe: /tmp/falco-ubuntu-aws.o
driverversion: master
```

### centos 6

```yaml
kernelrelease: 2.6.32-754.14.2.el6.x86_64
kernelversion: 1
target: centos
output:
  module: /tmp/falco-centos6.ko
driverversion: master
```

### centos 7

```yaml
kernelrelease: 3.10.0-957.12.2.el7.x86_64
kernelversion: 1
target: centos
output:
  module: /tmp/falco-centos7.ko
driverversion: master
```

### centos 8

```yaml
kernelrelease: 4.18.0-147.5.1.el8_1.x86_64
kernelversion: 1
target: centos
output:
  module: /tmp/falco-centos8.ko
driverversion: master
```

### amazonlinux

```yaml
kernelrelease: 4.14.26-46.32.amzn1.x86_64
target: amazonlinux
output:
    module: /tmp/falco_amazonlinux_4.14.26-46.32.amzn1.x86_64.ko
driverversion: be1ea2d9482d0e6e2cb14a0fd7e08cbecf517f94
```

### amazonlinux 2

```yaml
kernelrelease: 4.14.171-136.231.amzn2.x86_64
target: amazonlinux2
output:
    module: /tmp/falco_amazonlinux2_4.14.171-136.231.amzn2.x86_64.ko
    probe: /tmp/falco_amazonlinux2_4.14.171-136.231.amzn2.x86_64.o
driverversion: be1ea2d9482d0e6e2cb14a0fd7e08cbecf517f94
```

### debian

Example configuration file to build both the Kernel module and eBPF probe for Debian.

```yaml
kernelrelease: 4.19.0-6-amd64
kernelversion: 1
output:
  module: /tmp/falco-debian.ko
  probe: /tmp/falco-debian.o
target: debian
driverversion: master
```

### flatcar

Example configuration file to build both the Kernel module and eBPF probe for Flatcar.
The Flatcar release version needs to be provided in the `kernelrelease` field instead of the kernel version.

```yaml
kernelrelease: 3185.0.0
target: flatcar
output:
  module: /tmp/falco-flatcar-3185.0.0.ko
  probe: /tmp/falco-flatcar-3185.0.0.o
driverversion: master
```

### vanilla

In case of vanilla, you also need to pass the kernel config data in base64 format.

In most systems you can get `kernelconfigdata`  by reading `/proc/config.gz`.

```yaml
kernelrelease: 5.5.2
kernelversion: 1
target: vanilla
output:
  module: /tmp/falco-vanilla.ko
  probe: /tmp/falco-vanilla.o
driverversion: 0de226085cc4603c45ebb6883ca4cacae0bd25b2
```

Now you can add the `kernelconfigdata` to the configuration file, to do so:

```bash
zcat /proc/config.gz| base64 -w0 | awk '{print "kernelconfigdata: " $1;}' >> /tmp/vanilla.yaml
```

The command above assumes that you saved the configuration file at `/tmp/vanilla.yaml`

#### Note

Usually, building for a `vanilla` target requires more time.

So, we suggest to increase the `driverkit` timeout (defaults to `60` seconds):

```bash
driverkit docker -c /tmp/vanilla.yaml --timeout=300
```

## Goals

- [x] Have a package that can build the Falco kernel module in k8s
- [x] Have a package that can build the Falco kernel module in docker
- [x] Have a package that can build the Falco eBPF probe in k8s
- [x] Have a package that can build the Falco eBPF probe in docker
- [x] Support the top distributions in our [Survey](http://bit.ly/driverkit-survey-vote) and the Vanilla Kernel
  - [x] Ubuntu (`ubuntu-aws`, `ubuntu-generic`)
  - [x] CentOS 8
  - [x] CentOS 7
  - [x] CentOS 6
  - [x] AmazonLinux (`amazonlinux`, `amazonlinux2`)
  - [x] Debian
  - [x] Vanilla kernel (`vanilla`)

## Survey

We are conducting a [survey](http://bit.ly/driverkit-survey-vote) to know what is the most interesting set of Operating Systems we must support first in driverkit.

You can find the results of the survey [here](http://bit.ly/driverkit-survey-results)

## Creating a new Builder

You probably came here because you want to tell the [Falco Drivers Build Grid](https://github.com/falcosecurity/test-infra/tree/master/driverkit) to
build drivers for a specific distro you care about.

If that distribution is not supported by driverkit, the Falco Drivers Build Grid will not be able to just build it as it does for other distros.

To add a new supported distribution, you need to create a specific file implementing the `builder.Builder` interface.

You can find the specific distribution files into the [pkg/driverbuilder/builder](/pkg/driverbuilder/builder) folder.

Here's the [Ubuntu](/pkg/driverbuilder/builder/ubuntu.go) one for reference.

Following this simple set of instructions should help you while you implement a new `builder.Builder`.


### 1. Builder file
Create a file, named with the name of the distro you want to add in the `pkg/driverbuilder/builder` folder.

```bash
touch pkg/driverbuilder/builder/archlinux.go
```

### 2. Target name

Your builder will need a constant for the target it implements. Usually that constant
can just be the name of the distribution you are implementing. A builder can implement 
more than one target at time. For example, the Ubuntu builder implements both `ubuntu-generic` and `ubuntu-aws`
to reflect the organization that the distro itself has.

Once you have the constant, you will need to add it to the `BuilderByTarget` map.


Open your file and you will need to have something like this:

```go
// TargetTypeArchLinux identifies the Arch Linux target.
const TargetTypeArchLinux Type = "archlinux"

type archLinux struct {
}

func init() {
	BuilderByTarget[TargetTypeArchLinux] = &archLinux{}
}
```

Now, you can implement the `builder.Builder` interface for the `archlinux` struct
you just registered.

Here's a very minimalistic example.


```go
func (v archLinux) Script(c Config) (string, error) {
  return "echo 'hello world'", nil
}
```

Essentially, the `Script` function that you are implementing will need to return a string containing
a `bash` script that will be executed by driverkit at build time.

Depending on how the distro works, the script will need to fetch the kernel headers for it at the specific kernel version specified
in the `Config` struct at `c.Build.KernelVersion`.
Once you have those, based on what that kernel can do and based on what was configured
by the user you will need to build the kernel module driver and/or the eBPF probe driver.

How does this work?

If the user specifies:

- `c.Build.ModuleFilePath` you will need to build the kernel module and save it in /tmp/driver/falco.ko`
- `c.Build.ProbeFilePath` you will need to build the eBPF probe and save it in /tmp/driver/probe.o`

The `/tmp/driver` MUST be interpolated from the `DriverDirectory` constant from [`builders.go`](/pkg/driverbuilder/builder/builders.go).

If you look at the various builder implemented, you will see that the task of creating a new builder
can be easy or difficult depending on how the distribution ships their artifacts.

### 3. Customize GCC version

Driverkit builder image supports 4 gcc versions:
* GCC-8
* GCC-6.3.0
* GCC-5.5.0
* GCC-4.8.4

You can dynamically choose the one you prefer, likely switching on the kernel version.  
For an example, you can check out Ubuntu builder, namely: `ubuntuGCCVersionFromKernelRelease`.  

### 4. Customize llvm version

Driverkit builder image supports 2 llvm versions:
* llvm-7
* llvm-12

You can dynamically choose the one you prefer, likely switching on the kernel version.  
For an example, you can check out Debian builder, namely: `debianLLVMVersionFromKernelRelease`.  