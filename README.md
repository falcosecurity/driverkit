# Falco Build Service

Status: Under development

## Client usage

### Request a  build

To obtain the kernel release, execute:

```bash
uname -r
```

It will show something like:

```
4.15.0-72-generic
```

To obtain the kernel version:

```bash
uname -v
```

It will give something like:

```
#81-Ubuntu SMP Tue Nov 26 12:20:02 UTC 2019
```

In this case, the version is `81`, the number after the hash.

#### Vanilla
```bash
echo '{"buildType": "vanilla", "architecture": "x86_64", "kernelrelease": "5.5.2", "kernelConfigData": "'"$(zcat /proc/config.gz|base64)"'"}' | 
    curl  --header "Content-Type: application/json"   -d @-  -v http://127.0.0.1:8093/v1/module
```

#### Ubuntu AWS
```bash
 echo '{"buildType": "ubuntu-aws", "moduleVersion": "dev", "architecture": "x86_64", "kernelversion": "81", "kernelrelease": "4.15.0-72-generic",  "kernelConfigData": "'"$(cat /boot/config-4.15.0-72-generic |base64)"'"}' | 
    curl  --header "Content-Type: application/json"   -d @-  -v http://bdb769cd.ngrok.io/v1/module
```

#### Ubuntu Generic

```bash
 echo '{"buildType": "ubuntu-aws", "moduleVersion": "dev", "architecture": "x86_64", "kernelversion": "59", "kernelrelease": "4.15.0-1057-aws",  "kernelConfigData": "'"$(cat /boot/config-4.15.0-1057-aws|base64)"'"}' | 
    curl  --header "Content-Type: application/json"   -d @-  -v http://bdb769cd.ngrok.io/v1/module
```


### Retrieve a built module

When you request the build, the response will give you the final destination.
In general this is the pattern:

```
/v1/module/<buildtype>/<architecture>/<module-version>/<kernel-release>/<kernel-version>/<kernel-config-sha256sum>
```

Here's an example:

```bash
curl -O  -v http://127.0.0.1:8093/v1/module/vanilla/x86_64/dev/5.5.2-arch1-1/1/51878ec3bfc7e45a02d8161557116486d058cd3160d6aa8ad7bc683ab4cf3000/falco.ko
```

## Goals
- [x] Have a package that can build the kernel module in k8s - **DONE** (look at [/pkg/modulebuilder](/pkg/modulebuilder))
- [x] Have a package that can verify the kernel module - **DONE** (look at [/pkg/modinfo](/pkg/modinfo))
- [x] To have a mechanism that can fetch the kernel sources for a given distribution (or alternatively, a vanilla kernel) and setup a module build environment for it for any given kernel version. - DONE for vanilla kernel
- [x] To store artifacts (modules and packages) on a remote storage like s3 (low priority) as well as the local filesystem (high priority) - DONE for local filesystem
- [ ] Expose an endpoint to grab built Kernel modules that builds them on demand when are not found in the storage
- [ ] Find a way to allow rebuilds when a module is corrupted or needs to be refreshed (like for branch names used as moduleversion)

## Todo after the MVP

- [ ] Kernel module build endpoint rate limiting and DDoS prevention
- [ ] Expose a DEB repository for Falco Ubuntu/Debian packages
- [ ] Expose an RPM repository for Falco CentOS/RHEL/Fedora packages

## Interactions Diagram

![Interaction Diagram](docs/img/interactions.png)

https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-aws/linux-headers-4.15.0-1057-aws_4.15.0-1057.59_amd64.deb
https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-aws/linux-headers-4.15.0-1057-aws_4.15.0.59_amd64.deb  