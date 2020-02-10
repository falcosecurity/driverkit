# Falco Build Service

Status: Under development

## Goals
- [x] Have a package that can build the kernel module in k8s - **DONE** (look at [/pkg/modulebuilder](/pkg/modulebuilder))
- [x] Have a package that can verify the kernel module - **DONE** (look at [/pkg/modinfo](/pkg/modinfo))
- [ ] To have a mechanism that can fetch the kernel sources for a given distribution (or alternatively, a vanilla kernel) and setup a module build environment for it for any given kernel version.
- [ ] To store artifacts (modules and packages) on a remote storage like s3 (low priority) as well as the local filesystem (high priority)
- [ ] Expose an endpoint to grab built Kernel modules that builds them on demand when are not found in the storage
- [ ] Expose a DEB repository for Falco Ubuntu/Debian packages
- [ ] Expose an RPM repository for Falco CentOS/RHEL/Fedora packages

## Interactions Diagram

![Interaction Diagram](docs/img/interactions.png)

