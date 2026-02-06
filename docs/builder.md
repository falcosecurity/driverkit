# Builders

The [builder](../pkg/driverbuilder/builder) package contains all of the actual builders code, for each supported target.  
Their bash-like build templates live under the [templates](../pkg/driverbuilder/builder/templates) subfolder.

# Support a new distro

You probably came here because you want to tell the [Falco Drivers Build Grid](https://github.com/falcosecurity/test-infra/tree/master/driverkit) to
build drivers for a specific distro you care about.

If that distribution is not yet supported by driverkit, the Falco Drivers Build Grid will not be able to just build it as it does for other distros.

Adding support for a new distro is a multiple-step work:
* first of all, a new builder on driverkit must be created
* secondly, [kernel-crawler](https://github.com/falcosecurity/kernel-crawler) must also be updated to support the new distro; see [below](#5-kernel-crawler) section
* third, [dbg-go](https://github.com/falcosecurity/dbg-go) must [bump driverkit](https://github.com/falcosecurity/dbg-go?tab=readme-ov-file#bumping-driverkit) and enable support to generate configs for the new distro: https://github.com/falcosecurity/dbg-go/blob/main/pkg/root/distro.go#L30.
* lastly, [test-infra](https://github.com/falcosecurity/test-infra) must be updated to add the new [prow config](https://github.com/falcosecurity/test-infra/tree/master/config/jobs/build-drivers) for new distro related jobs and `dbg-go` images must be bumped, see https://github.com/falcosecurity/test-infra/tree/master/images/build-drivers and https://github.com/falcosecurity/test-infra/tree/master/images/update-dbg.

Here, we will only focus about driverkit part.

## Creating a new Builder

To add a new supported distribution, you need to create a specific file implementing the `builder.Builder` interface.  
Here's the [archlinux](../pkg/driverbuilder/builder/archlinux.go) one for reference.  
Following this simple set of instructions should help you while you implement a new `builder.Builder`.

### 1. Builder file

Create a file, named with the name of the distro you want to add in the `pkg/driverbuilder/builder` folder.

```bash
touch pkg/driverbuilder/builder/archlinux.go
```

### 2. Target name

Your builder will need a constant for the target it implements. Usually that constant
can just be the ID of the distribution you are implementing, as taken reading `/etc/os-release` file.  
A builder can implement more than one target at time. For example, the minikube builder is just a vanilla one.

Once you have the constant, you will need to add it to the [byTarget](https://github.com/falcosecurity/driverkit/blob/master/pkg/driverbuilder/builder/target.go) map. 
Open your file and you will need to add something like this:

```go
// TargetTypeArchLinux identifies the Arch Linux target.
const TargetTypeArchLinux Type = "arch"

type archLinux struct {
}

func init() {
	byTarget[TargetTypeArchLinux] = &archLinux{}
}
```

Now, you can implement the `builder.Builder` interface for the `archlinux` struct
you just registered.

Here's a very minimalistic example:

```go
func (c *archlinux) Name() string {
    return TargetTypeArchlinux.String()
}

func (c *archlinux) TemplateKernelUrlsScript() string { 
	return archlinuxKernelTemplate 
}

func (c *archlinux) TemplateScript() string {
    return archlinuxTemplate
}

func (c archlinux) URLs(kr kernelrelease.KernelRelease) ([]string, error) {
    urls := []string{}
    if kr.Architecture == kernelrelease.ArchitectureAmd64 {
        urls = append(urls, fmt.Sprintf("https://archive.archlinux.org/packages/l/linux-headers/linux-headers-%s.%s-%d-%s.pkg.tar.xz",
            kr.Fullversion,
            kr.Extraversion,
            cfg.KernelVersion,
            kr.Architecture.ToNonDeb()))
    } else {
        urls = append(urls, fmt.Sprintf("https://alaa.ad24.cz/packages/l/linux-%s-headers/linux-%s-headers-%s-%d-%s.pkg.tar.xz",
            kr.Architecture.ToNonDeb(),
            kr.Architecture.ToNonDeb(),
            kr.Fullversion,
            cfg.KernelVersion,
            kr.Architecture.ToNonDeb()))
    }
    return urls, nil
}

func (c *archlinux) KernelTemplateData(_ kernelrelease.KernelRelease, urls []string) interface{} {
    return archlinuxTemplateData{
        KernelDownloadURL: urls[0],
    }
}
```

Essentially, the various methods that you are implementing are needed to:
* fill the kernel download/extract script template, a `bash` script responsible to fetch and extract the kernel headers for the distro
* fill the build script template (see below), that is a `bash` script that will be executed by driverkit at build time
* return a list of possible kernel headers urls that will later be downloaded by the kernel download script, and then used for the driver build

Under `pkg/driverbuilder/builder/templates` folder, you can find all the template scripts for the supported builders.  
Adding a new template there and using `go:embed` to include it in your builder, allows leaner code
without mixing up templates and builder logic.  
For example:

```go
//go:embed templates/archlinux_kernel.sh
var archlinuxKernelTemplate string

//go:embed templates/archlinux.sh
var archlinuxTemplate string
```

Depending on how the distro works, the "kernel" template script will fetch the kernel headers for it at the specific kernel version specified
in the `Config` struct at `c.Build.KernelVersion`, and then extracting them.  
Finally, the script will also `export` the `KERNELDIR` variable to be consumed by the actual build script.  
Example kernel download template for archlinux:
```bash
set -xeuo pipefail

# Fetch the kernel
mkdir /tmp/kernel-download
cd /tmp/kernel-download
curl --silent -o kernel-devel.pkg.tar.xz -SL {{ .KernelDownloadURL }}
tar -xf kernel-devel.pkg.tar.xz
rm -Rf /tmp/kernel
mkdir -p /tmp/kernel
mv usr/lib/modules/*/build/* /tmp/kernel

# exit value
export KERNELDIR=/tmp/kernel
```

Once you have those, based on what that kernel can do and based on what was configured
by the user, the build script will build the kernel module driver.
Example build template for archlinux:
```bash
set -xeuo pipefail

cd {{ .DriverBuildDir }}
mkdir -p build && cd build
{{ .CmakeCmd }}

{{ if .BuildModule }}
# Build the module
make CC=/usr/bin/gcc-{{ .GCCVersion }} driver
strip -g {{ .ModuleFullPath }}
# Print results
modinfo {{ .ModuleFullPath }}
{{ end }}
```

How does this work?

If the user specifies:

- `c.Build.ModuleFilePath` you will need to build the kernel module and save it in /tmp/driver/falco.ko`

The `/tmp/driver` MUST be interpolated from the `DriverDirectory` constant from [`builders.go`](/pkg/driverbuilder/builder/builders.go).

If you look at the various builder implemented, you will see that the task of creating a new builder
can be easy or difficult depending on how the distribution ships their artifacts.  
Indeed, the hardest part is fetching the kernel headers urls for each distro.

### 3. Customize GCC version

A builder can enforce a GCC selection algorithm,  
by implementing the `builder.GCCVersionRequestor` interface.  
A sane default algorithm is provided, that selects a GCC version based on the kernel version.   
The requested gcc version is then [used to find the correct builder image to be used](builder_images.md#selection-algorithm).  

> **NOTE**: when implementing the `builder.GCCVersionRequestor`, returning an empty `semver.Version` means to fallback at default algorithm.

However, there is no mechanism to dynamically choose a clang version, because there should never be any need of touching it.   
The build will use the one provided by the chosen builder image.  
Any failure must be treated as a bug, and reported on [libs](https://github.com/falcosecurity/libs) repository.

### 5. kernel-crawler

When creating a new builder, it is recommended to check that [kernel-crawler](https://github.com/falcosecurity/kernel-crawler)
can also support collecting the new builders kernel versions and header package URLs. This will make sure that the latest drivers
for the new builder are automatically built by [test-infra](https://github.com/falcosecurity/test-infra). If required, add a feature request
for support for the new builder on the kernel-crawler repository.  

> **NOTE**: be sure that the crawler you are going to add is interesting for the community as a whole.
