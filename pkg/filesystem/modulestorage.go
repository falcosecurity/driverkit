package filesystem

import (
	"fmt"
	"io"
	"path"

	"github.com/falcosecurity/build-service/pkg/modulebuilder/build"
	"github.com/falcosecurity/build-service/pkg/server/types"
)

type ModuleStorage struct {
	filesystem Filesystem
}

func NewModuleStorage(fs Filesystem) *ModuleStorage {
	return &ModuleStorage{filesystem: fs}
}

func (ms *ModuleStorage) CreateModuleWriter(b build.Build) (io.WriteCloser, error) {
	return ms.filesystem.Create(moduleFilenameFromBuild(b))
}

func (ms *ModuleStorage) FindModuleWithBuild(b build.Build) (io.ReadCloser, error) {
	return ms.filesystem.Open(moduleFilenameFromBuild(b))
}

func (ms *ModuleStorage) FindModuleWithModuleRetrieveRequest(b types.ModuleRetrieveRequest) (io.ReadCloser, error) {
	return ms.filesystem.Open(moduleFilenameFromModuleRetrieveRequest(b))
}

func moduleFilenameFromBuild(b build.Build) string {
	s, _ := b.SHA256()
	return moduleFilenameFromParams(string(b.BuildType), b.Architecture, b.KernelVersion, b.ModuleVersion, s)
}
func moduleFilenameFromModuleRetrieveRequest(b types.ModuleRetrieveRequest) string {
	return moduleFilenameFromParams(string(b.BuildType), b.Architecture, b.KernelVersion, b.ModuleVersion, b.ConfigSHA256)
}

func moduleFilenameFromParams(buildType, architecture, kernelVersion, moduleVersion, sha256 string) string {
	return path.Clean(path.Base(fmt.Sprintf("falco-%s-%s-%s-%s-%s.ko", buildType, architecture, kernelVersion, moduleVersion, sha256)))
}
