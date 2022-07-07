package builder

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"text/template"

	"database/sql"

	_ "modernc.org/sqlite"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	logger "github.com/sirupsen/logrus"
)

type amazonBuilder interface {
	Builder
	repos() []string
	baseUrl() string
	ext() string
	target() Type
}

type amazonlinux2022 struct {
}

type amazonlinux2 struct {
}

type amazonlinux struct {
}

// TargetTypeAmazonLinux2022 identifies the AmazonLinux2022 target.
const TargetTypeAmazonLinux2022 Type = "amazonlinux2022"

// TargetTypeAmazonLinux2 identifies the AmazonLinux2 target.
const TargetTypeAmazonLinux2 Type = "amazonlinux2"

// TargetTypeAmazonLinux identifies the AmazonLinux target.
const TargetTypeAmazonLinux Type = "amazonlinux"

func init() {
	BuilderByTarget[TargetTypeAmazonLinux2022] = &amazonlinux2022{}
	BuilderByTarget[TargetTypeAmazonLinux2] = &amazonlinux2{}
	BuilderByTarget[TargetTypeAmazonLinux] = &amazonlinux{}
}

const amazonlinuxTemplate = `
#!/bin/bash
set -xeuo pipefail

rm -Rf {{ .DriverBuildDir }}
mkdir {{ .DriverBuildDir }}
rm -Rf /tmp/module-download
mkdir -p /tmp/module-download

curl --silent -SL {{ .ModuleDownloadURL }} | tar -xzf - -C /tmp/module-download
mv /tmp/module-download/*/driver/* {{ .DriverBuildDir }}

cp /driverkit/module-Makefile {{ .DriverBuildDir }}/Makefile
bash /driverkit/fill-driver-config.sh {{ .DriverBuildDir }}

# Fetch the kernel
mkdir /tmp/kernel-download
cd /tmp/kernel-download
{{ range $url := .KernelDownloadURLs }}
curl --silent -o kernel.rpm -SL {{ $url }}
rpm2cpio kernel.rpm | cpio --extract --make-directories
rm -rf kernel.rpm
{{ end }}
rm -Rf /tmp/kernel
mkdir -p /tmp/kernel
mv usr/src/kernels/*/* /tmp/kernel

{{ if .BuildModule }}
# Build the kernel module
cd {{ .DriverBuildDir }}

make KERNELDIR=/tmp/kernel CC=/usr/bin/gcc LD=/usr/bin/ld.bfd CROSS_COMPILE=""
mv {{ .ModuleDriverName }}.ko {{ .ModuleFullPath }}
# Print results
modinfo {{ .ModuleFullPath }}
{{ end }}

{{ if .BuildProbe }}
# Build the eBPF probe
cd {{ .DriverBuildDir }}/bpf
make LLC=/usr/bin/llc-{{ .LLVMVersion }} CLANG=/usr/bin/clang-{{ .LLVMVersion }} CC=/usr/bin/gcc KERNELDIR=/tmp/kernel
ls -l probe.o
{{ end }}
`

type amazonlinuxTemplateData struct {
	DriverBuildDir     string
	ModuleDownloadURL  string
	KernelDownloadURLs []string
	ModuleDriverName   string
	ModuleFullPath     string
	BuildModule        bool
	BuildProbe         bool
	LLVMVersion        string
}

// Script compiles the script to build the kernel module and/or the eBPF probe.
func (a amazonlinux2022) Script(c Config, kr kernelrelease.KernelRelease) (string, error) {
	return script(a, c, kr)
}

func (a amazonlinux2022) repos() []string {
	return []string{
		"2022.0.20220202",
		"2022.0.20220315",
	}
}

func (a amazonlinux2022) baseUrl() string {
	return "https://al2022-repos-us-east-1-9761ab97.s3.dualstack.us-east-1.amazonaws.com/core/mirrors"
}

func (a amazonlinux2022) ext() string {
	return "gz"
}

func (a amazonlinux2022) target() Type {
	return TargetTypeAmazonLinux2022
}

// Script compiles the script to build the kernel module and/or the eBPF probe.
func (a amazonlinux2) Script(c Config, kr kernelrelease.KernelRelease) (string, error) {
	return script(a, c, kr)
}

func (a amazonlinux2) repos() []string {
	return []string{
		"core/2.0",
		"core/latest",
		"extras/kernel-5.4/latest",
		"extras/kernel-5.10/latest",
	}
}

func (a amazonlinux2) baseUrl() string {
	return "http://amazonlinux.us-east-1.amazonaws.com/2"
}

func (a amazonlinux2) ext() string {
	return "gz"
}

func (a amazonlinux2) target() Type {
	return TargetTypeAmazonLinux2
}

// Script compiles the script to build the kernel module and/or the eBPF probe.
func (a amazonlinux) Script(c Config, kr kernelrelease.KernelRelease) (string, error) {
	return script(a, c, kr)
}

func (a amazonlinux) repos() []string {
	return []string{
		"latest/updates",
		"latest/main",
		"2017.03/updates",
		"2017.03/main",
		"2017.09/updates",
		"2017.09/main",
		"2018.03/updates",
		"2018.03/main",
	}
}

func (a amazonlinux) baseUrl() string {
	return "http://repo.us-east-1.amazonaws.com"
}

func (a amazonlinux) ext() string {
	return "bz2"
}

func (a amazonlinux) target() Type {
	return TargetTypeAmazonLinux
}

func script(a amazonBuilder, c Config, kr kernelrelease.KernelRelease) (string, error) {
	t := template.New(string(a.target()))
	parsed, err := t.Parse(amazonlinuxTemplate)
	if err != nil {
		return "", err
	}

	var urls []string
	if c.KernelUrls == nil {
		// Check (and filter) existing kernels before continuing
		var packages []string
		packages, err = fetchAmazonLinuxPackagesURLs(a, kr)
		if err != nil {
			return "", err
		}
		urls, err = getResolvingURLs(packages)
	} else {
		urls, err = getResolvingURLs(c.KernelUrls)
	}
	if err != nil {
		return "", err
	}

	td := amazonlinuxTemplateData{
		DriverBuildDir:     DriverDirectory,
		ModuleDownloadURL:  moduleDownloadURL(c),
		KernelDownloadURLs: urls,
		ModuleDriverName:   c.DriverName,
		ModuleFullPath:     ModuleFullPath,
		BuildModule:        len(c.Build.ModuleFilePath) > 0,
		BuildProbe:         len(c.Build.ProbeFilePath) > 0,
		LLVMVersion:        amazonLLVMVersionFromKernelRelease(kr),
	}

	buf := bytes.NewBuffer(nil)
	err = parsed.Execute(buf, td)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func buildMirror(a amazonBuilder, r string, kv kernelrelease.KernelRelease) (string, error) {
	var baseURL string
	switch a.target() {
	case TargetTypeAmazonLinux:
		baseURL = fmt.Sprintf("%s/%s", a.baseUrl(), r)
	case TargetTypeAmazonLinux2:
		baseURL = fmt.Sprintf("%s/%s/%s", a.baseUrl(), r, kv.Architecture.ToNonDeb())
	case TargetTypeAmazonLinux2022:
		baseURL = fmt.Sprintf("%s/%s/%s", a.baseUrl(), r, kv.Architecture.ToNonDeb())
	default:
		return "", fmt.Errorf("unsupported target")
	}

	mirror := fmt.Sprintf("%s/%s", baseURL, "mirror.list")
	logger.WithField("url", mirror).WithField("version", r).Debug("looking for repo...")
	return mirror, nil
}

type unzipFunc func(io.Reader) ([]byte, error)

func unzipFuncFromBuilder(a amazonBuilder) (unzipFunc, error) {
	switch a.ext() {
	case "gz":
		return gunzip, nil
	case "bz2":
		return bunzip, nil
	}
	return nil, fmt.Errorf("unsupported extension: %s", a.ext())
}

func fetchAmazonLinuxPackagesURLs(a amazonBuilder, kv kernelrelease.KernelRelease) ([]string, error) {
	urls := []string{}
	visited := make(map[string]struct{})

	for _, v := range a.repos() {
		mirror, err := buildMirror(a, v, kv)
		if err != nil {
			return nil, err
		}

		// Obtain the repo URL by getting mirror URL content
		mirrorRes, err := http.Get(mirror)
		if err != nil {
			return nil, err
		}
		defer mirrorRes.Body.Close()

		var repo string
		scanner := bufio.NewScanner(mirrorRes.Body)
		if scanner.Scan() {
			repo = scanner.Text()
		}
		if repo == "" {
			return nil, fmt.Errorf("repository not found")
		}
		repo = strings.ReplaceAll(strings.TrimSuffix(repo, "\n"), "$basearch", kv.Architecture.ToNonDeb())
		repo = strings.TrimSuffix(repo, "/")
		repoDatabaseURL := fmt.Sprintf("%s/repodata/primary.sqlite.%s", repo, a.ext())
		if _, ok := visited[repoDatabaseURL]; ok {
			continue
		}
		// Download the repo database
		repoRes, err := http.Get(repoDatabaseURL)
		logger.WithField("url", repoDatabaseURL).Debug("downloading...")
		if err != nil {
			return nil, err
		}
		defer repoRes.Body.Close()
		visited[repoDatabaseURL] = struct{}{}

		unzip, err := unzipFuncFromBuilder(a)
		if err != nil {
			return nil, err
		}

		dbBytes, err := unzip(repoRes.Body)
		if err != nil {
			return nil, err
		}
		// Create the temporary database file
		dbFile, err := ioutil.TempFile(os.TempDir(), fmt.Sprintf("%s-*.sqlite", string(a.target())))
		if err != nil {
			return nil, err
		}
		defer os.Remove(dbFile.Name())
		if _, err := dbFile.Write(dbBytes); err != nil {
			return nil, err
		}
		// Open the database
		db, err := sql.Open("sqlite", dbFile.Name())
		if err != nil {
			return nil, err
		}
		defer db.Close()
		logger.WithField("db", dbFile.Name()).Debug("connecting to database...")
		// Query the database
		rel := strings.TrimPrefix(strings.TrimSuffix(kv.FullExtraversion, fmt.Sprintf(".%s", kv.Architecture.ToNonDeb())), "-")
		q := fmt.Sprintf("SELECT location_href FROM packages WHERE name LIKE 'kernel-devel%%' AND version='%s' AND release='%s'", kv.Fullversion, rel)
		stmt, err := db.Prepare(q)
		if err != nil {
			return nil, err
		}
		defer stmt.Close()
		rows, err := stmt.Query()
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var href string
			err = rows.Scan(&href)
			if err != nil {
				log.Fatal(err)
			}
			urls = append(urls, fmt.Sprintf("%s/%s", repo, href))
		}

		if err := dbFile.Close(); err != nil {
			return nil, err
		}

		// Found, do not continue
		if len(urls) > 0 {
			break
		}
	}

	return urls, nil
}

func gunzip(data io.Reader) (res []byte, err error) {
	var r io.Reader
	r, err = gzip.NewReader(data)
	if err != nil {
		return
	}

	var b bytes.Buffer
	_, err = b.ReadFrom(r)
	if err != nil {
		return
	}

	res = b.Bytes()

	return
}

func bunzip(data io.Reader) (res []byte, err error) {
	var r io.Reader
	r = bzip2.NewReader(data)

	var b bytes.Buffer
	_, err = b.ReadFrom(r)
	if err != nil {
		return
	}

	res = b.Bytes()

	return
}

func amazonLLVMVersionFromKernelRelease(kr kernelrelease.KernelRelease) string {
	switch kr.Version {
	case 4:
		return "7"
	case 5:
		return "12"
	default:
		return "12"
	}
}
