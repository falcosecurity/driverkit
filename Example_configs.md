# Example Configs

## aliyun linux 2 (Alibaba Cloud Linux 2)

```yaml
kernelrelease: 4.19.91-26.al7.x86_64
target: alinux
output:
    module: /tmp/falco_alinux_4.19.91-26.al7.x86_64.ko
    probe: /tmp/falco_alinux_4.19.91-26.al7.x86_64.o
driverversion: master
```

## aliyun linux 3 (Alibaba Cloud Linux 3)

```yaml
kernelrelease: 5.10.84-10.4.al8.x86_64
target: alinux
output:
    module: /tmp/falco_alinux_4.19.91-26.al7.x86_64.ko
    probe: /tmp/falco_alinux_4.19.91-26.al7.x86_64.o
driverversion: master
```

## alma linux

```yaml
kernelrelease: 5.14.0-162.12.1.el9_1.x86_64
target: almalinux
output:
    module: /tmp/falco_almalinux_5.14.0-162.12.1.el9_1.x86_64.ko
    probe: /tmp/falco_almalinux_5.14.0-162.12.1.el9_1.x86_64.o
driverversion: master
```

## amazonlinux

```yaml
kernelrelease: 4.14.26-46.32.amzn1.x86_64
target: amazonlinux
output:
    module: /tmp/falco_amazonlinux_4.14.26-46.32.amzn1.x86_64.ko
driverversion: master
```

## amazonlinux 2

```yaml
kernelrelease: 4.14.171-136.231.amzn2.x86_64
target: amazonlinux2
output:
    module: /tmp/falco_amazonlinux2_4.14.171-136.231.amzn2.x86_64.ko
    probe: /tmp/falco_amazonlinux2_4.14.171-136.231.amzn2.x86_64.o
driverversion: master
```

## amazonlinux 2022

```yaml
kernelrelease: 5.10.96-90.460.amzn2022.x86_64
target: amazonlinux2022
output:
    module: /tmp/falco_amazonlinux2022_5.10.96-90.460.amzn2022.x86_64.ko
    probe: /tmp/falco_amazonlinux2022_5.10.96-90.460.amzn2022.x86_64.o
driverversion: master
```

## archlinux

Example configuration file to build both the Kernel module and eBPF probe for Archlinux.
Note: archlinux target uses the [Arch Linux Archive](https://wiki.archlinux.org/title/Arch_Linux_Archive) to fetch
all ever supported kernel releases.
For arm64, it uses an user-provided mirror, as no official mirror is available: http://tardis.tiny-vps.com/aarm/.
The mirror has been up and updated since 2015.

NOTE: ArchLinux has updated to Linux Kernel 6.0+, which appears to enforce generation of BTF for kmod too. The typical Debian container builders in the repo currently do not work for building ArchLinux drivers as a result. While an agreement is being reached on how to handle this upstream, using a custom `--builderimage` with ArchLinux drivers works for now. For example:
```Dockerfile
# archlinux builder example
# Note: ArchLinux is a rolling release, the gcc versions and such will change over time
# pinned for now for gcc 11/12
FROM archlinux:base-20221030.0.98412

RUN pacman -Sy && pacman -Sy --noconfirm \
    make   \
    pahole \
    gcc11  \
    gcc && \
    ln -s /usr/bin/gcc /usr/bin/gcc-12
```

```yaml
kernelversion: 1
kernelrelease: 6.0.6.arch1-1
target: arch
output:
  module: /tmp/falco-arch.ko
  probe: /tmp/falco-arch.o
driverversion: master
builderimage: ${ARCH_BUILD_IMAGE_HERE}
```

## centos 6

```yaml
kernelrelease: 2.6.32-754.14.2.el6.x86_64
kernelversion: 1
target: centos
output:
  module: /tmp/falco-centos6.ko
driverversion: master
```

## centos 7

```yaml
kernelrelease: 3.10.0-957.12.2.el7.x86_64
kernelversion: 1
target: centos
output:
  module: /tmp/falco-centos7.ko
driverversion: master
```

## centos 8

```yaml
kernelrelease: 4.18.0-147.5.1.el8_1.x86_64
kernelversion: 1
target: centos
output:
  module: /tmp/falco-centos8.ko
driverversion: master
```

## debian

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

## fedora

```yaml
kernelrelease: 5.19.16-200.fc36.x86_64
kernelversion: 1
target: fedora
output:
  module: /tmp/falco-fedora.ko
driverversion: master
```

## flatcar

Example configuration file to build both the Kernel module and eBPF probe for Flatcar.
The Flatcar release version needs to be provided in the `kernelrelease` field instead of the kernel version;
moreover, kernelconfigdata must be provided.

```yaml
kernelrelease: 3185.0.0
target: flatcar
output:
  module: /tmp/falco-flatcar-3185.0.0.ko
  probe: /tmp/falco-flatcar-3185.0.0.o
driverversion: master
kernelconfigdata: Q09ORklHX0ZBTk9USUZZPXkKQ09ORklHX0t...
```

## minikube
Example configuration file to build both the Kernel module and eBPF probe for Minikube.
```yaml
kernelversion: 1_1.26.0
kernelrelease: 5.10.57
target: minikube
architecture: amd64
output:
  module: /tmp/falco_minikube_5.10.57_1_1.26.0.ko
  probe: /tmp/falco_minikube_5.10.57_1_1.26.0.o
kernelconfigdata: Q09ORklHX0ZBTk9USUZZPXkKQ09ORklHX0t...
```

## oracle linux 8

```yaml
kernelrelease: 5.4.17-2011.3.2.1.el8uek.x86_64
kernelversion: 1
target: ol
output:
  module: /tmp/falco-ol8.ko
driverversion: master
```

## redhat 7

```yaml
kernelrelease: 3.10.0-1160.66.1.el7.x86_64
target: redhat
output:
  module: /tmp/falco-redhat7.ko
driverversion: master
builderimage: registry.redhat.io/rhel7:rhel7_driverkit
```
The image used for this build was created with the following command:

```bash
docker build --build-arg rh_username=<username> --build-arg rh_password=<password> -t registry.redhat.io/rhel7:rhel7_driverkit -f Dockerfile.rhel7 .
````
| :warning: **Passing user credentials via command line**: Consider using `--secret` option! |
|--------------------------------------------------------------------------------------------|

and Dockerfile.rhel7:
```bash
FROM registry.redhat.io/rhel7

ARG rh_username
ARG rh_password

RUN subscription-manager register --username $rh_username --password $rh_password --auto-attach

RUN yum install gcc elfutils-libelf-devel make -y
```
| :warning: **Base image requires Redhat subscription to pull**:```docker login registry.redhat.io``` |
|-----------------------------------------------------------------------------------------------------|

## redhat 8

```yaml
kernelrelease: 4.18.0-372.9.1.el8.x86_64
target: redhat
output:
  module: /tmp/falco-redhat8.ko
  probe: /tmp/falco-redhat8.o
driverversion: master
builderimage: redhat/ubi8:rhel8_driverkit
```

The image used for this build was created with the following command:

```bash
docker build --build-arg rh_username=<username> --build-arg rh_password=<password> -t redhat/ubi8:rhel8_driverkit -f Dockerfile.rhel8 .
````
| :warning: **Passing user credentials via command line**: Consider using `--secret` option! |
|--------------------------------------------------------------------------------------------|

and Dockerfile.rhel8:
```bash
FROM redhat/ubi8

ARG rh_username
ARG rh_password

RUN subscription-manager register --username $rh_username --password $rh_password --auto-attach

RUN yum install gcc curl elfutils-libelf-devel kmod make \
                llvm-toolset-0:12.0.1-1.module+el8.5.0+11871+08d0eab5.x86_64 cpio -y
```

## redhat 9

```yaml
kernelrelease: 5.14.0-70.13.1.el9_0.x86_64
target: redhat
output:
  module: /tmp/falco-redhat9.ko
  probe: /tmp/falco-redhat9.o
driverversion: master
builderimage: docker.io/redhat/ubi9:rhel9_driverkit
```
The image used for this build was created with the following command:

```bash
docker build -t docker.io/redhat/ubi9:rhel9_driverkit -f Dockerfile.rhel9 .
````

and Dockerfile.rhel9:
```bash
FROM docker.io/redhat/ubi9

RUN yum install gcc elfutils-libelf-devel kmod make cpio llvm-toolset -y
```
| :exclamation: **subscription-manager does not work on RHEL9 containers**: Host must have a valid RHEL subscription |
|--------------------------------------------------------------------------------------------------------------------|

## rocky linux

```yaml
kernelrelease: 5.14.0-162.18.1.el9_1.x86_64
target: rocky
output:
    module: /tmp/falco_almalinux_5.14.0-162.18.1.el9_1.x86_64.ko
    probe: /tmp/falco_almalinux_5.14.0-162.18.1.el9_1.x86_64.o
driverversion: master
```

## ubuntu
Example configuration file to build both the Kernel module and eBPF probe for Ubuntu (works with any flavor!).

```yaml
kernelrelease: 5.0.0-1021-aws-5.0
kernelversion: 24~18.04.1
target: ubuntu
output:
  module: /tmp/falco-ubuntu-generic.ko
  probe: /tmp/falco-ubuntu-generic.o
driverversion: master
```

## ubuntu-aws

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

> **NOTE:** ubuntu-aws exists to retain backward compatibility only,
> and should not be used in new configs.

## ubuntu-generic
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

> **NOTE:** ubuntu-generic exists to retain backward compatibility only,
> and should not be used in new configs.

## vanilla

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

### Note

Usually, building for a `vanilla` target requires more time.

So, we suggest to increase the `driverkit` timeout (defaults to `60` seconds):

```bash
driverkit docker -c /tmp/vanilla.yaml --timeout=300
```
