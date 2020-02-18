package filesystem

import (
	"fmt"
	"io"
	"path"

	"github.com/falcosecurity/build-service/pkg/modulebuilder/build"
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

func (ms *ModuleStorage) FindModule(b build.Build) (io.ReadCloser, error) {
	return ms.filesystem.Open(moduleFilenameFromBuild(b))
}

func moduleFilenameFromBuild(b build.Build) string {
	return path.Clean(path.Base(fmt.Sprintf("falco-%s-%s-%s-%s-%s.ko", b.BuildType, b.Architecture, b.KernelVersion, b.ModuleVersion, b.SHA256())))
}
