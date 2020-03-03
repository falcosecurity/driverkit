# driverkit

Status: **Under development**

A command line tool that can be used to build the Falco kernel module and eBPF probe.


## Usage

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

- ubuntu-generic
- ubuntu-aws
- vanilla

## Goals

- [x] Have a package that can build the Falco kernel module in k8s - **DONE** (look at [/pkg/modulebuilder](/pkg/modulebuilder))
- [ ] Have a package that can build the Falco kernel module in docker
- [ ] Have a package that can build the Falco eBPF probe in k8s - **DONE** (look at [/pkg/modulebuilder](/pkg/modulebuilder))
- [ ] Have a package that can build the eBPF probe in docker
- [ ] Support the top 4 distributions in our [Survey](http://bit.ly/driverkit-survey-vote) and the Vanilla Kernel
  - [x] Ubuntu (`ubuntu-aws`, `ubuntu-generic`)
  - [ ] CentOS 8
  - [ ] CentOS 7
  - [ ] Debian stable
  - [x] Vanilla kernel (`vanilla`)
  
 ## Survey
 
 We are conducting a [survey](http://bit.ly/driverkit-survey-vote) to know what is the most interesting set of Operating Systems we must support first
 in driverkit. 
 
 You can find the results of the survey [here](http://bit.ly/driverkit-survey-results)