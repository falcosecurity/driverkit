package filesystem

import (
	"io"
	"os"
	"path"
	"strings"
)

const LocalFilesystemStr = "local"

type Local struct {
	basePath string
}

func NewLocal(options map[string]string) *Local {
	basePath, ok := options["basepath"]
	if !ok {
		basePath = os.TempDir()
	}
	return &Local{
		basePath: basePath,
	}
}

func (f *Local) Open(name string) (io.ReadCloser, error) {
	p := path.Join(f.basePath, stripPath(name))
	return os.Open(p)
}

func (f *Local) Exists(name string) bool {
	p := path.Join(f.basePath, stripPath(name))
	s, err := os.Stat(p)
	if os.IsNotExist(err) {
		return false
	}

	// let's say that it does not exists if it's empty
	if s.Size() == 0 {
		return false
	}

	return true
}

func (f *Local) Size(name string) (int64, error) {
	p := path.Join(f.basePath, stripPath(name))
	s, err := os.Stat(p)
	if err != nil {
		return 0, err
	}
	return s.Size(), nil
}

func (f *Local) Create(name string) (io.WriteCloser, error) {
	p := path.Join(f.basePath, stripPath(name))
	return os.Create(p)
}

func stripPath(p string) string {
	newPath := path.Clean(p)
	trimmed := strings.TrimPrefix(newPath, "../")

	for trimmed != newPath {
		newPath = trimmed
		trimmed = strings.TrimPrefix(newPath, "../")
	}

	if newPath == "." || newPath == ".." {
		newPath = ""
	}

	if len(newPath) > 0 && string(newPath[0]) == "/" {
		return newPath[1:]
	}

	return newPath
}
