package builder

import (
	"context"
	"fmt"
	"github.com/blang/semver"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"github.com/falcosecurity/falcoctl/pkg/oci/repository"
	logger "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	"os"
	"regexp"
	"strings"
)

type YAMLImage struct {
	Target      string   `yaml:"target"`
	GCCVersions []string `yaml:"gcc_versions"` // we expect images to internally link eg: gcc5 to gcc5.0.0
	Name        string   `yaml:"name"`
	Arch        string   `yaml:"arch"`
	Tag         string   `yaml:"tag"`
}

type YAMLImagesList struct {
	Images []YAMLImage `yaml:"images"`
}

type Image struct {
	Target     Type
	GCCVersion semver.Version // we expect images to internally link eg: gcc5 to gcc5.0.0
	Name       string
}

type ImagesLister interface {
	LoadImages() []Image
}

type FileImagesLister struct {
	FilePath string
	Arch     string
	Tag      string
}

type RepoImagesLister struct {
	repo string
}

type ImageKey string

func (i *Image) toKey() ImageKey {
	return ImageKey(i.Target.String() + "_" + i.GCCVersion.String())
}

type ImagesMap map[ImageKey]Image

var tagReg *regexp.Regexp

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

func NewFileImagesLister(filePath string, build *Build) *FileImagesLister {
	// Create the proper regexes to load "any" and target-specific images for requested arch
	arch := kernelrelease.Architecture(build.Architecture).ToNonDeb()
	return &FileImagesLister{FilePath: filePath, Arch: arch, Tag: build.builderImageTag()}
}

func (f *FileImagesLister) LoadImages() []Image {
	var (
		res       []Image
		imageList YAMLImagesList
	)

	// loop over lines in file to print them
	fileData, err := os.ReadFile(f.FilePath)
	if err != nil {
		logger.WithError(err).WithField("FilePath", f.FilePath).Warnf("Error opening builder repo file: %s\n", err.Error())
		return res
	}

	err = yaml.Unmarshal(fileData, &imageList)
	if err != nil {
		logger.WithError(err).WithField("FilePath", f.FilePath).Warnf("Error unmarshalling builder repo file: %s\n", err.Error())
		return res
	}

	if len(imageList.Images) == 0 {
		logger.WithField("FilePath", f.FilePath).Warnf("Malformed image list file: expected at least 1 image\n")
	}

	for _, image := range imageList.Images {
		// Fixup empty fields using default values
		if image.Arch == "" {
			image.Arch = f.Arch
		}
		if image.Tag == "" {
			image.Tag = f.Tag
		}

		// Values checks
		if image.Arch != f.Arch {
			logger.WithField("FilePath", f.FilePath).WithField("image", image).Debug("Skipping wrong-arch image")
			continue
		}
		if image.Tag != f.Tag {
			logger.WithField("FilePath", f.FilePath).WithField("image", image).Debug("Skipping wrong-tag image")
			continue
		}
		if image.Target != "any" && BuilderByTarget[Type(image.Target)] == nil {
			logger.WithField("FilePath", f.FilePath).WithField("image", image).Debug("Skipping unexistent target image")
			continue
		}
		if image.Name == "" {
			logger.WithField("FilePath", f.FilePath).WithField("image", image).Debug("Skipping empty name image")
			continue
		}
		if len(image.GCCVersions) == 0 {
			logger.WithField("FilePath", f.FilePath).WithField("image", image).Debug("Expected at least 1 gcc version")
			continue
		}

		for _, gcc := range image.GCCVersions {
			buildImage := Image{
				Name:       image.Name,
				Target:     Type(image.Target),
				GCCVersion: mustParseTolerant(gcc),
			}
			res = append(res, buildImage)
		}
	}
	return res
}

func NewRepoImagesLister(repo string, build *Build) *RepoImagesLister {
	// Lazy inizialization
	if tagReg == nil {
		imageTag := build.builderImageTag()
		// Create the proper regexes to load "any" and target-specific images for requested arch
		arch := kernelrelease.Architecture(build.Architecture).ToNonDeb()
		targetFmt := fmt.Sprintf("^(?P<target>%s|any)-%s(?P<gccVers>(_gcc[0-9]+.[0-9]+.[0-9]+)+)-%s$", build.TargetType.String(), arch, imageTag)
		tagReg = regexp.MustCompile(targetFmt)
	}
	return &RepoImagesLister{repo: repo}
}

func (repo *RepoImagesLister) LoadImages() []Image {
	noCredentials := func(r *repository.Repository) {
		// The default client will be used by oras.
		// TODO: we don't support private repositories for now.
		r.Client = nil
	}

	repoOCI, err := repository.NewRepository(repo.repo, noCredentials)
	if err != nil {
		logger.WithField("Repo", repo.repo).Warnf("Skipping repo %s: %s\n", repo, err.Error())
		return nil
	}

	tags, err := repoOCI.Tags(context.Background())
	if err != nil {
		logger.WithField("Repo", repo.repo).Warnf("Skipping repo %s: %s\n", repo, err.Error())
		return nil
	}

	var res []Image
	for _, t := range tags {
		img := fmt.Sprintf("%s:%s", repo.repo, t)
		match := tagReg.FindStringSubmatch(t)
		if len(match) != 2 {
			logger.WithField("Repo", repo.repo).WithField("Image", img).Debug("Malformed image name")
			continue
		}

		var (
			target  string
			gccVers []string
		)
		for i, name := range tagReg.SubexpNames() {
			if i > 0 && i <= len(match) {
				switch name {
				case "gccVers":
					gccVers = strings.Split(match[i], "_gcc")
					gccVers = gccVers[1:] // remove initial whitespace
				case "target":
					target = match[i]
				}
			}
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
				Name:       img,
				Target:     Type(target),
			}
			res = append(res, buildImage)
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
			// Skip if key already exists: we have a descending prio list of docker repos!
			if _, ok := b.Images[image.toKey()]; !ok {
				b.Images[image.toKey()] = image
			}
		}
	}
	if len(b.Images) == 0 {
		logger.Fatal("Could not load any builder image. Leaving.")
	}
}
