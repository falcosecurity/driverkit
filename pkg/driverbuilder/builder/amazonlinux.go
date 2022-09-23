package builder

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"database/sql"
	_ "embed"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	logger "github.com/sirupsen/logrus"
)

//go:embed templates/amazonlinux.sh
var amazonlinuxTemplate string

type amazonBuilder interface {
	Builder
	repos() []string
	baseUrl() string
	ext() string
}

type amazonlinux struct {
}

type amazonlinux2 struct {
	amazonlinux
}

type amazonlinux2022 struct {
	amazonlinux
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

type amazonlinuxTemplateData struct {
	commonTemplateData
	KernelDownloadURLs []string
}

func (a *amazonlinux) Name() string {
	return TargetTypeAmazonLinux.String()
}

func (a *amazonlinux) TemplateScript() string {
	return amazonlinuxTemplate
}

func (a *amazonlinux) URLs(_ Config, kr kernelrelease.KernelRelease) ([]string, error) {
	return fetchAmazonLinuxPackagesURLs(a, kr)
}

func (a *amazonlinux) TemplateData(c Config, kr kernelrelease.KernelRelease, urls []string) interface{} {
	return amazonlinuxTemplateData{
		commonTemplateData: c.toTemplateData(a, kr),
		KernelDownloadURLs: urls,
	}
}

func (a *amazonlinux) repos() []string {
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

func (a *amazonlinux) baseUrl() string {
	return "http://repo.us-east-1.amazonaws.com"
}

func (a *amazonlinux) ext() string {
	return "bz2"
}

func (a *amazonlinux2022) Name() string {
	return TargetTypeAmazonLinux2022.String()
}

func (a *amazonlinux2022) URLs(_ Config, kr kernelrelease.KernelRelease) ([]string, error) {
	return fetchAmazonLinuxPackagesURLs(a, kr)
}

func (a *amazonlinux2022) repos() []string {
	return []string{
		"2022.0.20220202",
		"2022.0.20220315",
	}
}

func (a *amazonlinux2022) baseUrl() string {
	return "https://al2022-repos-us-east-1-9761ab97.s3.dualstack.us-east-1.amazonaws.com/core/mirrors"
}

func (a *amazonlinux2022) ext() string {
	return "gz"
}

func (a *amazonlinux2) Name() string {
	return TargetTypeAmazonLinux2.String()
}

func (a *amazonlinux2) URLs(_ Config, kr kernelrelease.KernelRelease) ([]string, error) {
	return fetchAmazonLinuxPackagesURLs(a, kr)
}

func (a *amazonlinux2) repos() []string {
	return []string{
		"core/2.0",
		"core/latest",
		"extras/kernel-5.4/latest",
		"extras/kernel-5.10/latest",
	}
}

func (a *amazonlinux2) baseUrl() string {
	return "http://amazonlinux.us-east-1.amazonaws.com/2"
}

func (a *amazonlinux2) ext() string {
	return "gz"
}

func buildMirror(a amazonBuilder, r string, kv kernelrelease.KernelRelease) (string, error) {
	var baseURL string
	switch a.(type) {
	case *amazonlinux:
		baseURL = fmt.Sprintf("%s/%s", a.baseUrl(), r)
	case *amazonlinux2:
		baseURL = fmt.Sprintf("%s/%s/%s", a.baseUrl(), r, kv.Architecture.ToNonDeb())
	case *amazonlinux2022:
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
		dbFile, err := ioutil.TempFile(os.TempDir(), fmt.Sprintf("%s-*.sqlite", a.Name()))
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
