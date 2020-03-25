package builder

import (
	"bytes"
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

// TargetTypeAmazonLinux2 identifies the AmazonLinux2 target.
const TargetTypeAmazonLinux2 Type = "amazonlinux2"

func init() {
	BuilderByTarget[TargetTypeAmazonLinux2] = &amazonlinux2{}
}

const amazonlinux2Template = `
{{ range $url := .KernelDownloadURLs }}
echo {{ $url }}
{{ end }}
`

type amazonlinux2TemplateData struct {
	DriverBuildDir     string
	ModuleDownloadURL  string
	KernelDownloadURLs []string
	BuildModule        bool
	BuildProbe         bool
}

// Script compiles the script to build the kernel module and/or the eBPF probe.
func (v amazonlinux2) Script(c Config) (string, error) {
	t := template.New(string(TargetTypeAmazonLinux2))
	parsed, err := t.Parse(amazonlinux2Template)
	if err != nil {
		return "", err
	}

	kv := kernelrelease.FromString(c.Build.KernelRelease)

	// Check (and filter) existing kernels before continuing
	packages, err := fetchAmazonLinux2PackagesURLsFromKernelVersion(kv, c.Build.Architecture)
	if err != nil {
		return "", err
	}
	urls, err := getResolvingURLs(packages)
	if err != nil {
		return "", err
	}

	td := amazonlinux2TemplateData{
		DriverBuildDir:     DriverDirectory,
		ModuleDownloadURL:  moduleDownloadURL(c),
		KernelDownloadURLs: urls,
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

var amazonlinux2repos = []string{"2.0", "latest"}

func fetchAmazonLinux2PackagesURLsFromKernelVersion(kv kernelrelease.KernelRelease, arch string) ([]string, error) {
	urls := []string{}
	visited := map[string]bool{}
	for _, v := range amazonlinux2repos {
		baseURL := fmt.Sprintf("http://amazonlinux.us-east-1.amazonaws.com/2/core/%s/%s", v, arch)
		mirror := fmt.Sprintf("%s/%s", baseURL, "mirror.list")
		logger.WithField("url", mirror).WithField("version", v).Debug("looking for repo...")
		// Obtain the repo URL by getting mirror URL content
		mirrorRes, err := http.Get(mirror)
		if err != nil {
			return nil, err
		}
		defer mirrorRes.Body.Close()
		repo, err := ioutil.ReadAll(mirrorRes.Body)
		if err != nil {
			return nil, err
		}
		repoDatabaseURL := fmt.Sprintf("%s/repodata/primary.sqlite.gz", strings.TrimSuffix(string(repo), "\n"))
		if _, ok := visited[repoDatabaseURL]; ok {
			continue
		}
		// Download the repo database
		repoRes, err := http.Get(repoDatabaseURL)
		logger.WithField("url", repoDatabaseURL).Debug("downloading ...")
		if err != nil {
			return nil, err
		}
		defer repoRes.Body.Close()
		visited[repoDatabaseURL] = true
		// Decompress the database
		dbBytes, err := gunzip(repoRes.Body)
		if err != nil {
			return nil, err
		}
		// Create the temporary database file
		dbFile, err := ioutil.TempFile(os.TempDir(), "amazonlinux2-*.sqlite")
		if err != nil {
			return nil, err
		}
		//defer os.Remove(dbFile.Name())
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
		// fixme > it seems they should always be 2 URLs (and the most recent ones?)
		// https://github.com/draios/sysdig/blob/fb08e7f59cca570383bdafb5de96824b8a2e9e6b/probe-builder/kernel-crawler.py#L414
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
			urls = append(urls, fmt.Sprintf("%s/%s", baseURL, href))
		}

		if err := dbFile.Close(); err != nil {
			return nil, err
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

	var resB bytes.Buffer
	_, err = resB.ReadFrom(r)
	if err != nil {
		return
	}

	res = resB.Bytes()

	return
}
