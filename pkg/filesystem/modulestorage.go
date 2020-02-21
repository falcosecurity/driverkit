package filesystem

import (
	"errors"
	"fmt"
	"io"
	"path"

	"github.com/falcosecurity/build-service/pkg/modulebuilder/build"
	"github.com/falcosecurity/build-service/pkg/server/types"
)

var ErrModuleDoesNotExists = errors.New("module does not exists")

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
	n := moduleFilenameFromBuild(b)
	return ms.openModule(n)
}

func (ms *ModuleStorage) FindModuleWithModuleRetrieveRequest(b types.ModuleRetrieveRequest) (io.ReadCloser, error) {
	n := moduleFilenameFromModuleRetrieveRequest(b)
	return ms.openModule(n)
}

func (ms *ModuleStorage) openModule(name string) (io.ReadCloser, error) {
	if !ms.filesystem.Exists(name) {
		return nil, ErrModuleDoesNotExists
	}
	f, err := ms.filesystem.Open(name)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func moduleFilenameFromBuild(b build.Build) string {
	s, _ := b.SHA256()
	return moduleFilenameFromParams(string(b.BuildType), b.Architecture, b.KernelRelease, b.KernelVersion, b.ModuleVersion, s)
}
func moduleFilenameFromModuleRetrieveRequest(b types.ModuleRetrieveRequest) string {
	return moduleFilenameFromParams(string(b.BuildType), b.Architecture, b.KernelRelease, b.KernelVersion, b.ModuleVersion, b.ConfigSHA256)
}

func moduleFilenameFromParams(buildType, architecture, kernelRelease, kernelVersion, moduleVersion, sha256 string) string {
	return path.Clean(path.Base(fmt.Sprintf("falco-%s-%s--%s-%s-%s-%s.ko", buildType, architecture, kernelRelease, kernelVersion, moduleVersion, sha256)))
}

func ErrIsModuleDoesNotExists(err error) bool {
	return err == ErrModuleDoesNotExists
}
