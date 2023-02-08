# Builder Images

Driverkit supports multiple builder images.  
A builder image is the docker image used to build the drivers.

## Adding a builder image

Adding a builder image is just a matter of adding a new dockerfile under the [docker/builders](../docker/builders) folder,  
with a name matching the following regex: `builder-(?P<target>[a-z0-9]+)-(?P<arch>x86_64|aarch64)(?P<gccVers>(_gcc[0-9]+.[0-9]+.[0-9]+)+).Dockerfile$`.    
For example: `builder-centos-x86_64_gcc5.8.0_gcc6.0.0.Dockerfile`.

> **NOTE:** `any` is also a valid target, and means "apply as fallback for any target"

The image **MUST** symlink all of its provided GCC versions to their full semver name, like:
* `/usr/bin/gcc5` must be linked to `/usr/bin/gcc-5.0.0`
* `/usr/bin/gcc-4.8` must be linked to `/usr/bin/gcc-4.8.0`

This is needed because driverkit logic must be able to differentiate eg: between  
an image that provides gcc4 and one that provides 4.8, in a reliable manner.

The makefile will be then automatically able to collect the new docker images and pushing it as part of the CI.  

## Selection algorithm

Once pushed, driverkit will be able to correctly load the image during startup, using a `docker search`.  
Then, it will map images whose target and architecture are correct for the current build, storing the provided GCCs list.  
The algorithm goes as follows:
* load any image for the build arch and build target
* load any image for the build arch and "any" target
* if any of the target-specific image provides the targetGCC for the build, we are over
* if any of the "any" fallback image provides the targetGCC for the build, we are over
* else, find the image between target-specific and fallback ones, that provides nearest GCC.  
In this latest step, there is no distinction between/different priority given to target specific or fallback images.

## Customize builder images repos

Moreover, users can also ship their own builder images in their own docker repositories, by using `--builderrepo` CLI option.  
One can use this option multiple times; builder repos are a priority first list of docker repositories that can each provide up to 100 builder images.  
Note that default falcosecurity repo will always be enforced as lowest priority repo.

## Force use a builder image

Users can also force-specify the builder image to be used for the current build,  
instead of relying on the internal algorithm, by using `--builderimage` CLI option.  

> **NOTE**: builderimage MUST provide the selected gcc for the build

A special value for builder image is available:
* `auto:$tag`, that is used to tell driverkit to use the automatic algorithm, but forcing a certain image tag

> **NOTE**: since `docker search` has no way to differentiate between image tags, all builder images are expected to be tagged together.

## Force use a gcc version

Users can specify the target gcc version of the build, using `--gccversion` option.  
As seen above, this needs to be a fully expanded gcc version, like `4.8.0`, or `8.0.0`.  
When set, the image selection algorithm will pick the best builder image, 
ie: the one that provides the nearest gcc version.  
One can also play with both `--gccversion` and `--builderimage` options to enforce the  
usage of a specific builder image that ships a specific gcc version.