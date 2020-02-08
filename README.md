# Falco Build Service

Status: Under development

**Note:** this is still in initial development, please try it and send issues but wait for a bit
to make substantial changes since the initial scaffolding is not finished yet and everything might change.

## Goals
- [x] Have a package that can build the kernel module - **DONE** (look at [/pkg/modulebuilder](/pkg/modulebuilder))
- [x] Have a package that can verify the kernel module - **DONE** (look at [/pkg/modinfo](/pkg/modinfo))
- [ ] To have a mechanism that can fetch the kernel sources for a given distribution (or alternatively, a vanilla kernel) and setup a module build environment for it for any given kernel version.
- [ ] To store artifacts (modules and packages) on a remote storage like s3 (low priority) as well as the local filesystem ( high priority)
- [ ] Expose an endpoint to grab built Kernel modules that builds them on demand when are not found in the storage
- [ ] Expose a DEB repository for Falco Ubuntu/Debian packages
- [ ] Expose an RPM repository for Falco CentOS/RHEL/Fedora packages

## Interactions Diagram

![Interaction Diagram](docs/img/interactions.png)



# modules todo

- get kernel sources at version
- copy config to `.config`
- make oldconfig
- make prepare
- make modules_prepare
