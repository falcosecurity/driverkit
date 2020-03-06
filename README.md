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
driverkit kubernetes -o /tmp/falco.ko --kernelversion=81 --kernelrelease=4.15.0-72-generic --moduleversion=dev --target=ubuntu-generic
```

### Against a Docker daemon

```bash
driverkit docker -o /tmp/falco.ko --kernelversion=81 --kernelrelease=4.15.0-72-generic --moduleversion=dev --target=ubuntu-generic
```


### Build using a configuration file

Create a file named `ubuntu-aws.yaml` containing the following content:

```yaml
kernelrelease: 4.15.0-1057-aws
kernelversion: 59
target: ubuntu-aws
output: /tmp/falco-ubuntu-aws.ko
moduleversion: 0de226085cc4603c45ebb6883ca4cacae0bd25b2
```

Now run driverkit using the configuration file:

```bash
driverkit docker -c ubuntu-aws.yaml
```

## Supported targets

### ubuntu-generic
Example configuration file

```yaml
kernelrelease: 4.15.0-72-generic
kernelversion: 81
target: ubuntu-generic
output: /tmp/falco-ubuntu-generic.ko
moduleversion: 0de226085cc4603c45ebb6883ca4cacae0bd25b2
```

### ubuntu-aws

```yaml
kernelrelease: 4.15.0-1057-aws
kernelversion: 59
target: ubuntu-aws
output: /tmp/falco-ubuntu-aws.ko
moduleversion: 0de226085cc4603c45ebb6883ca4cacae0bd25b2
```

### centos 6

```yaml
kernelrelease: 2.6.32-754.14.2.el6.x86_64
kernelversion: 1
target: centos
output: /tmp/falco-centos6.ko
moduleversion: dev
```

### centos 7

```yaml
kernelrelease: 3.10.0-957.12.2.el7.x86_64
kernelversion: 1
target: centos
output: /tmp/falco-centos7.ko
moduleversion: dev
```

### centos 8

```yaml
kernelrelease: 4.18.0-147.5.1.el8_1.x86_64
kernelversion: 1
target: centos
output: /tmp/falco-centos8.ko
moduleversion: dev
```

#### debian

```yaml
kernelrelease: 4.19.0-6-amd64
kernelversion: 1
output: /tmp/falco-debian.ko
target: debian
moduleversion: dev
```

### vanilla

In case of vanilla, you also need to pass the kernel config data in base64 format.

In most systems you can get `kernelconfigdata`  by reading `/proc/config.gz`.

```yaml
kernelrelease: 5.5.2
kernelversion: 1
target: vanilla
output: /tmp/falco-vanilla.ko
moduleversion: 0de226085cc4603c45ebb6883ca4cacae0bd25b2
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
- [ ] Have a package that can build the Falco eBPF probe in k8s
- [ ] Have a package that can build the Falco eBPF probe in docker
- [ ] Support the top distributions in our [Survey](http://bit.ly/driverkit-survey-vote) and the Vanilla Kernel
  - [x] Ubuntu (`ubuntu-aws`, `ubuntu-generic`)
  - [x] CentOS 8
  - [x] CentOS 7
  - [x] CentOS 6
  - [x] Debian
  - [x] Vanilla kernel (`vanilla`)

## Survey

We are conducting a [survey](http://bit.ly/driverkit-survey-vote) to know what is the most interesting set of Operating Systems we must support first in driverkit.

You can find the results of the survey [here](http://bit.ly/driverkit-survey-results)
