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
	"strings"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"oras.land/oras-go/v2/registry/remote/auth"
)

var defaultImageTag = "latest" // This is overwritten when using the Makefile to build

// Build contains the info about the on-going build.
type Build struct {
	TargetType        Type
	KernelConfigData  string
	KernelRelease     string
	KernelVersion     string
	DriverVersion     string
	Architecture      string
	ModuleFilePath    string
	ProbeFilePath     string
	ModuleDriverName  string
	ModuleDeviceName  string
	BuilderImage      string
	BuilderRepos      []string
	ImagesListers     []ImagesLister
	KernelUrls        []string
	GCCVersion        string
	RepoOrg           string
	RepoName          string
	Images            ImagesMap
	RegistryName      string
	RegistryUser      string
	RegistryPassword  string
	RegistryPlainHTTP bool
}

func (b *Build) KernelReleaseFromBuildConfig() kernelrelease.KernelRelease {
	kv := kernelrelease.FromString(b.KernelRelease)
	kv.Architecture = kernelrelease.Architecture(b.Architecture)
	kv.KernelVersion = b.KernelVersion
	return kv
}

func (b *Build) toGithubRepoArchive() string {
	return fmt.Sprintf("https://github.com/%s/%s/archive", b.RepoOrg, b.RepoName)
}

func (b *Build) ToConfig() Config {
	return Config{
		DriverName:      b.ModuleDriverName,
		DeviceName:      b.ModuleDeviceName,
		DownloadBaseURL: b.toGithubRepoArchive(),
		Build:           b,
	}
}

// hasCustomBuilderImage return true if a custom builder image has been set by the user.
func (b *Build) hasCustomBuilderImage() bool {
	if len(b.BuilderImage) > 0 {
		customNames := strings.Split(b.BuilderImage, ":")
		return customNames[0] != "auto"
	}
	return false
}

// builderImageTag returns the tag(latest, master or hash) to be used for the builder image.
func (b *Build) builderImageTag() string {
	if len(b.BuilderImage) > 0 {
		customNames := strings.Split(b.BuilderImage, ":")
		// Updated image tag if "auto:tag" is passed
		if len(customNames) > 1 {
			return customNames[1]
		}
	}
	return defaultImageTag
}

func (b *Build) ClientForRegistry(registry string) *auth.Client {
	client := auth.DefaultClient
	client.SetUserAgent("driverkit")
	client.Credential = func(ctx context.Context, reg string) (auth.Credential, error) {
		if b.RegistryName == registry {
			return auth.Credential{
				Username: b.RegistryUser,
				Password: b.RegistryPassword,
			}, nil
		}

		return auth.EmptyCredential, nil
	}

	return client
}

func (b *Build) HasOutputs() bool {
	return b.ModuleFilePath != "" || b.ProbeFilePath != ""
}
