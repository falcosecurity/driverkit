package builder

import (
	"bufio"
	"context"
	"fmt"
	"github.com/blang/semver"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	logger "github.com/sirupsen/logrus"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type Image struct {
	Target     Type
	GCCVersion semver.Version // we expect images to internally link eg: gcc5 to gcc5.0.0
	Name       string
}

type ImagesLister interface {
	LoadImages() []Image
}

type FileImagesLister struct {
	file     *os.File
	FilePath string
}

type RepoImagesLister struct {
	repo string
}

type ImageKey string

func (i *Image) toKey() ImageKey {
	return ImageKey(i.Target.String() + "_" + i.GCCVersion.String())
}

type ImagesMap map[ImageKey]Image

var repoRegs = make([]*regexp.Regexp, 0, 2)

func (im ImagesMap) findImage(target Type, gccVers semver.Version) (Image, bool) {
	targetImage := Image{
		Target:     target,
		GCCVersion: gccVers,
	}
	// Try to find specific image for specific target first
	if img, ok := im[targetImage.toKey()]; ok {
		return img, true
	}

	// Fallback at "any" target that offers specific gcc
	targetImage.Target = "any"
	if img, ok := im[targetImage.toKey()]; ok {
		return img, true
	}
	return Image{}, false
}

func (f *FileImagesLister) LoadImages() []Image {
	// loop over lines in file to print them
	file, err := os.Open(f.FilePath)
	if err != nil {
		logger.WithError(err).WithField("FilePath", f.FilePath).Fatal("error opening builder repo file")
	}
	scanner := bufio.NewScanner(file)
	var res []Image
	for scanner.Scan() {
		infos := strings.Split(scanner.Text(), ",")
		if len(infos) < 3 {
			logger.WithField("FilePath", f.FilePath).WithField("line", scanner.Text()).Fatal("Invalid image list file: expected at least 3 fields (name,target,gcc_version) but got " + strconv.Itoa(len(infos)) + ".")
		}
		name := infos[0]
		target := Type(infos[1])
		gccVersions := infos[2:]
		for _, gcc := range gccVersions {
			buildImage := Image{
				Name:       name,
				Target:     target,
				GCCVersion: mustParseTolerant(gcc),
			}
			res = append(res, buildImage)
		}
	}
	if err := scanner.Err(); err != nil {
		logger.WithField("file", file.Name()).WithError(err).Fatal()
	}
	err = file.Close()
	if err != nil {
		logger.WithField("file", file.Name()).WithError(err).Fatal()
	}
	return res
}

func NewRepoImagesLister(repo string, build *Build) *RepoImagesLister {
	if len(repoRegs) == 0 {
		// Create the proper regexes to load "any" and target-specific images for requested arch
		arch := kernelrelease.Architecture(build.Architecture).ToNonDeb()
		targetFmt := fmt.Sprintf("driverkit-builder-%s-%s(?P<gccVers>(_gcc[0-9]+.[0-9]+.[0-9]+)+)$", build.TargetType.String(), arch)
		repoRegs = append(repoRegs, regexp.MustCompile(targetFmt))
		genericFmt := fmt.Sprintf("driverkit-builder-any-%s(?P<gccVers>(_gcc[0-9]+.[0-9]+.[0-9]+)+)$", arch)
		repoRegs = append(repoRegs, regexp.MustCompile(genericFmt))
	}
	return &RepoImagesLister{repo: repo}
}

func (repo *RepoImagesLister) LoadImages() []Image {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		log.Fatal(err)
	}
	imgs, err := cli.ImageSearch(context.Background(), repo.repo, types.ImageSearchOptions{Limit: 100})
	if err != nil {
		logger.WithField("Repository", repo.repo).WithError(err).Warnf("Skipping repo")
		return []Image{}
	}
	var res []Image
	for _, img := range imgs {
		for regIdx, reg := range repoRegs {
			match := reg.FindStringSubmatch(img.Name)
			if len(match) == 0 {
				continue
			}

			var gccVers []string
			for i, name := range reg.SubexpNames() {
				if i > 0 && i <= len(match) {
					switch name {
					case "gccVers":
						gccVers = strings.Split(match[i], "_gcc")
						gccVers = gccVers[1:] // remove initial whitespace
					}
				}
			}

			if len(gccVers) == 0 {
				logger.Debug("Malformed image name: ", img.Name, len(match))
				continue
			}

			// Note: we store "any" target images as "any",
			// instead of adding them to the target,
			// because we always prefer specific target images,
			// and we cannot guarantee here that any subsequent docker repos
			// does not provide a target-specific image that offers same gcc version
			for _, gccVer := range gccVers {
				// If user set a fixed gcc version, only load images that provide it.
				buildImage := Image{
					GCCVersion: mustParseTolerant(gccVer),
					Name:       img.Name,
				}
				if regIdx == 0 {
					buildImage.Target = Type("target-placeholder")
				} else {
					buildImage.Target = Type("any")
				}
				res = append(res, buildImage)
			}
		}
	}
	return res
}

func (b *Build) LoadImages() {
	for _, imagesLister := range b.ImagesListers {
		for _, image := range imagesLister.LoadImages() {
			if b.GCCVersion != "" && b.GCCVersion != image.GCCVersion.String() {
				continue
			}
			if image.Target == "target-placeholder" {
				image.Target = b.TargetType
			}
			// Skip if key already exists: we have a descending prio list of docker repos!
			if _, ok := b.Images[image.toKey()]; !ok {
				b.Images[image.toKey()] = image
			}
		}
	}
}
