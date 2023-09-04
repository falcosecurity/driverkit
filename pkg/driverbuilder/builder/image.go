package builder

import (
	"context"
	"fmt"
	"github.com/blang/semver"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"github.com/falcosecurity/falcoctl/pkg/oci/repository"
	"gopkg.in/yaml.v3"
	"log/slog"
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
	Target   string
}

type RepoImagesLister struct {
	*repository.Repository
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

func NewFileImagesLister(filePath string, build *Build) (*FileImagesLister, error) {
	return &FileImagesLister{
		FilePath: filePath,
		Arch:     kernelrelease.Architecture(build.Architecture).ToNonDeb(),
		Tag:      build.builderImageTag(),
		Target:   build.TargetType.String(),
	}, nil
}

func (f *FileImagesLister) LoadImages() []Image {
	var (
		res       []Image
		imageList YAMLImagesList
	)

	// loop over lines in file to print them
	fileData, err := os.ReadFile(f.FilePath)
	if err != nil {
		slog.With("err", err.Error(), "FilePath", f.FilePath).Warn("Error opening builder repo file")
		return res
	}

	err = yaml.Unmarshal(fileData, &imageList)
	if err != nil {
		slog.With("err", err.Error(), "FilePath", f.FilePath).Warn("Error unmarshalling builder repo file")
		return res
	}

	for _, image := range imageList.Images {
		logger := slog.With("FilePath", f.FilePath, "image", image)
		// Values checks
		if image.Arch != f.Arch {
			logger.Debug("Skipping wrong-arch image")
			continue
		}
		if image.Tag != f.Tag {
			logger.Debug("Skipping wrong-tag image")
			continue
		}
		if image.Target != "any" && image.Target != f.Target {
			logger.Debug("Skipping wrong-target image")
			continue
		}
		if image.Name == "" {
			logger.Debug("Skipping empty name image")
			continue
		}
		if len(image.GCCVersions) == 0 {
			logger.Debug("Expected at least 1 gcc version")
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

func NewRepoImagesLister(repo string, build *Build) (*RepoImagesLister, error) {
	// Lazy inizialization
	if tagReg == nil {
		imageTag := build.builderImageTag()
		// Create the proper regexes to load "any" and target-specific images for requested arch
		arch := kernelrelease.Architecture(build.Architecture).ToNonDeb()
		targetFmt := fmt.Sprintf("^(?P<target>%s|any)-%s(?P<gccVers>(_gcc[0-9]+.[0-9]+.[0-9]+)+)-%s$", build.TargetType.String(), arch, imageTag)
		tagReg = regexp.MustCompile(targetFmt)
	}

	// Get the registry URL from repository.
	registry, err := getRegistryFromRef(repo)
	if err != nil {
		return nil, err
	}

	repoOCI, err := repository.NewRepository(repo,
		repository.WithPlainHTTP(build.RegistryPlainHTTP),
		repository.WithClient(build.ClientForRegistry(registry)))
	if err != nil {
		return nil, err
	}
	return &RepoImagesLister{repoOCI}, nil
}

func (repo *RepoImagesLister) LoadImages() []Image {
	tags, err := repo.Tags(context.Background())
	if err != nil {
		slog.With("Repo", repo.Reference, "err", err.Error()).Warn("Skipping repo")
		return nil
	}

	var res []Image
	for _, t := range tags {
		img := fmt.Sprintf("%s:%s", repo.Reference, t)
		match := tagReg.FindStringSubmatch(t)
		if len(match) == 0 {
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
			// User forced a gcc version? Only load images matching the requested gcc version.
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
		slog.Error("Could not load any builder image. Leaving.")
		os.Exit(1)
	}
}

// getRegistryFromRef extracts the registry from a ref string.
func getRegistryFromRef(ref string) (string, error) {
	index := strings.Index(ref, "/")
	if index <= 0 {
		return "", fmt.Errorf("cannot extract registry name from ref %q", ref)
	}

	return ref[0:index], nil
}
