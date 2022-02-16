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

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	_ "github.com/mattn/go-sqlite3" // Why do you want me to justify? Leave me alone :)
	logger "github.com/sirupsen/logrus"
)

type amazonlinux2 struct {
}

type amazonlinux struct {
}

// TargetTypeAmazonLinux2 identifies the AmazonLinux2 target.
const TargetTypeAmazonLinux2 Type = "amazonlinux2"

// TargetTypeAmazonLinux identifies the AmazonLinux target.
const TargetTypeAmazonLinux Type = "amazonlinux"

func init() {
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
make KERNELDIR=/tmp/kernel
mv {{ .ModuleDriverName }}.ko {{ .ModuleFullPath }}
# Print results
modinfo {{ .ModuleFullPath }}
{{ end }}

{{ if .BuildProbe }}
# Build the eBPF probe
cd {{ .DriverBuildDir }}/bpf
make LLC=/usr/bin/llc-7 CLANG=/usr/bin/clang-7 CC=/usr/bin/gcc KERNELDIR=/tmp/kernel
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
}

// Script compiles the script to build the kernel module and/or the eBPF probe.
func (a amazonlinux2) Script(c Config) (string, error) {
	return script(c, TargetTypeAmazonLinux2)
}

// Script compiles the script to build the kernel module and/or the eBPF probe.
func (a amazonlinux) Script(c Config) (string, error) {
	return script(c, TargetTypeAmazonLinux)
}

func script(c Config, targetType Type) (string, error) {
	t := template.New(string(targetType))
	parsed, err := t.Parse(amazonlinuxTemplate)
	if err != nil {
		return "", err
	}

	kv := kernelrelease.FromString(c.Build.KernelRelease)

	// Check (and filter) existing kernels before continuing
	packages, err := fetchAmazonLinuxPackagesURLs(kv, c.Build.Architecture, targetType)
	if err != nil {
		return "", err
	}
	if len(packages) != 2 {
		return "", fmt.Errorf("target %s needs to find both kernel and kernel-devel packages", targetType)
	}
	urls, err := getResolvingURLs(packages)
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
	}

	buf := bytes.NewBuffer(nil)
	err = parsed.Execute(buf, td)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

var reposByTarget = map[Type][]string{
	TargetTypeAmazonLinux2: []string{
		"core/2.0",
		"core/latest",
		"extras/kernel-5.4/latest",
	},
	TargetTypeAmazonLinux: []string{
		"latest/updates",
		"latest/main",
		"2017.03/updates",
		"2017.03/main",
		"2017.09/updates",
		"2017.09/main",
		"2018.03/updates",
		"2018.03/main",
	},
}

var baseByTarget = map[Type]string{
	TargetTypeAmazonLinux:  "http://repo.us-east-1.amazonaws.com/%s",
	TargetTypeAmazonLinux2: "http://amazonlinux.us-east-1.amazonaws.com/2/core/%s/%s",
}

func fetchAmazonLinuxPackagesURLs(kv kernelrelease.KernelRelease, arch string, targetType Type) ([]string, error) {
	urls := []string{}
	visited := map[string]bool{}
	amazonlinux2baseURL := "http://amazonlinux.us-east-1.amazonaws.com"

	for _, v := range reposByTarget[targetType] {
		var baseURL string
		switch targetType {
		case TargetTypeAmazonLinux:
			baseURL = fmt.Sprintf("http://repo.us-east-1.amazonaws.com/%s", v)
		case TargetTypeAmazonLinux2:
			baseURL = fmt.Sprintf("%s/2/%s/%s", amazonlinux2baseURL, v, arch)
		default:
			return nil, fmt.Errorf("unsupported target")
		}

		mirror := fmt.Sprintf("%s/%s", baseURL, "mirror.list")
		logger.WithField("url", mirror).WithField("version", v).Debug("looking for repo...")
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
		repo = strings.ReplaceAll(strings.TrimSuffix(string(repo), "\n"), "$basearch", arch)

		ext := "gz"
		if targetType == TargetTypeAmazonLinux {
			ext = "bz2"
		}
		repoDatabaseURL := fmt.Sprintf("%s/repodata/primary.sqlite.%s", repo, ext)
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
		visited[repoDatabaseURL] = true
		// Decompress the database
		var unzipFunc func(io.Reader) ([]byte, error)
		if targetType == TargetTypeAmazonLinux {
			unzipFunc = bunzip
		} else {
			unzipFunc = gunzip
		}
		dbBytes, err := unzipFunc(repoRes.Body)
		if err != nil {
			return nil, err
		}
		// Create the temporary database file
		dbFile, err := ioutil.TempFile(os.TempDir(), fmt.Sprintf("%s-*.sqlite", targetType))
		if err != nil {
			return nil, err
		}
		defer os.Remove(dbFile.Name())
		if _, err := dbFile.Write(dbBytes); err != nil {
			return nil, err
		}
		// Open the database
		db, err := sql.Open("sqlite3", dbFile.Name())
		if err != nil {
			return nil, err
		}
		defer db.Close()
		logger.WithField("db", dbFile.Name()).Debug("connecting to database...")
		// Query the database
		rel := strings.TrimPrefix(strings.TrimSuffix(kv.FullExtraversion, fmt.Sprintf(".%s", arch)), "-")
		q := fmt.Sprintf("SELECT location_href FROM packages WHERE name LIKE 'kernel%%' AND name NOT LIKE 'kernel-livepatch%%' AND name NOT LIKE '%%doc%%' AND name NOT LIKE '%%tools%%' AND name NOT LIKE '%%headers%%' AND version='%s' AND release='%s'", kv.Fullversion, rel)
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
			base := repo
			if targetType == TargetTypeAmazonLinux2 {
				base = amazonlinux2baseURL
			}
			href = strings.ReplaceAll(href, "../", "")
			urls = append(urls, fmt.Sprintf("%s/%s", base, href))
		}

		if err := dbFile.Close(); err != nil {
			return nil, err
		}

		// Found, do not continue
		// todo > verify amazonlinux always needs 2 packages (kernel and kernel-devel) too
		if len(urls) == 2 {
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
