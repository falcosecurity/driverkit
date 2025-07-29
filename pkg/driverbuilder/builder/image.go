// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package builder

import (
	"context"
	"fmt"
	"github.com/falcosecurity/falcoctl/pkg/output"
	"os"
	"regexp"
	"strings"

	"github.com/blang/semver/v4"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"github.com/falcosecurity/falcoctl/pkg/oci/repository"
	"gopkg.in/yaml.v3"
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
	LoadImages(printer *output.Printer) []Image
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

func (f *FileImagesLister) LoadImages(printer *output.Printer) []Image {
	var (
		res       []Image
		imageList YAMLImagesList
	)

	// loop over lines in file to print them
	fileData, err := os.ReadFile(f.FilePath)
	if err != nil {
		printer.Logger.Warn("error opening builder repo file",
			printer.Logger.Args("err", err.Error(), "filepath", f.FilePath))
		return res
	}

	err = yaml.Unmarshal(fileData, &imageList)
	if err != nil {
		printer.Logger.Warn("error unmarshalling builder repo file",
			printer.Logger.Args("err", err.Error(), "filepath", f.FilePath))
		return res
	}

	for _, image := range imageList.Images {
		// Values checks
		if image.Arch != f.Arch {
			printer.Logger.Debug("skipping wrong-arch image",
				printer.Logger.Args("filepath", f.FilePath, "image", image))
			continue
		}
		if image.Tag != f.Tag {
			printer.Logger.Debug("skipping wrong-tag image",
				printer.Logger.Args("filepath", f.FilePath, "image", image))
			continue
		}
		if image.Target != "any" && image.Target != f.Target {
			printer.Logger.Debug("skipping wrong-target image",
				printer.Logger.Args("filepath", f.FilePath, "image", image))
			continue
		}
		if image.Name == "" {
			printer.Logger.Debug("skipping empty name image",
				printer.Logger.Args("filepath", f.FilePath, "image", image))
			continue
		}
		if len(image.GCCVersions) == 0 {
			printer.Logger.Debug("expected at least 1 gcc version",
				printer.Logger.Args("filepath", f.FilePath, "image", image))
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

func (repo *RepoImagesLister) LoadImages(printer *output.Printer) []Image {
	tags, err := repo.Tags(context.Background())
	if err != nil {
		printer.Logger.Warn("skipping repo",
			printer.Logger.Args("repo", repo.Reference, "err", err.Error()))
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
		for _, image := range imagesLister.LoadImages(b.Printer) {
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
		b.Printer.Logger.Fatal("Could not load any builder image. Leaving.")
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
