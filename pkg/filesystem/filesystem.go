package filesystem

import (
	"fmt"
	"io"
)

type Filesystem interface {
	Open(name string) (io.ReadCloser, error)
	Create(name string) (io.WriteCloser, error)
}

func Factory(name string, options map[string]string) (Filesystem, error) {
	switch name {
	case LocalFilesystemStr:
		return NewLocal(options), nil
	}
	return nil, fmt.Errorf("filesystem not implemented: %s", name)
}
