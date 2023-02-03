package builder

import (
	"context"
	"fmt"
	"github.com/blang/semver"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	logger "github.com/sirupsen/logrus"
	"log"
	"regexp"
	"strings"
)

type Image struct {
	Target     Type
	GCCVersion semver.Version // we expect images to internally link eg: gcc5 to gcc5.0.0
	Name       string
}

type ImageKey string

func (i *Image) toKey() ImageKey {
	return ImageKey(i.Target.String() + "_" + i.GCCVersion.String())
}

type ImagesMap map[ImageKey]Image

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

func (b *Build) LoadImages() {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		log.Fatal(err)
	}

	// Create the proper regexes to load "any" and target-specific images for requested arch
	arch := kernelrelease.Architecture(b.Architecture).ToNonDeb()
	regs := make([]*regexp.Regexp, 0)
	targetFmt := fmt.Sprintf("driverkit-builder-%s-%s(?P<gccVers>(_gcc[0-9]+.[0-9]+.[0-9]+)+)$", b.TargetType.String(), arch)
	regs = append(regs, regexp.MustCompile(targetFmt))
	genericFmt := fmt.Sprintf("driverkit-builder-any-%s(?P<gccVers>(_gcc[0-9]+.[0-9]+.[0-9]+)+)$", arch)
	regs = append(regs, regexp.MustCompile(genericFmt))

	b.Images = make(ImagesMap)
	for _, repo := range b.DockerRepos {
		imgs, err := cli.ImageSearch(context.Background(), repo, types.ImageSearchOptions{Limit: 100})
		if err != nil {
			logger.Warnf("Skipping repo %s: %s\n", repo, err.Error())
			continue
		}
		for _, img := range imgs {
			for regIdx, reg := range regs {
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
					if b.GCCVersion != "" && b.GCCVersion != gccVer {
						continue
					}
					buildImage := Image{
						GCCVersion: mustParseTolerant(gccVer),
						Name:       img.Name,
					}
					if regIdx == 0 {
						buildImage.Target = b.TargetType
					} else {
						buildImage.Target = Type("any")
					}
					// Skip if key already exists: we have a descending prio list of docker repos!
					if _, ok := b.Images[buildImage.toKey()]; !ok {
						b.Images[buildImage.toKey()] = buildImage
					}
				}
			}
		}
	}
	if len(b.Images) == 0 {
		log.Fatal("Could not load any builder image. Leaving.")
	}
}
