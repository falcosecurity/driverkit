package kernelversion

import (
	"errors"
	"strings"
)

type KernelVersion struct {
	Version      string
	LocalVersion string
}

func FromString(kernelVersionStr string) (KernelVersion, error) {
	kv := KernelVersion{}
	if len(kernelVersionStr) == 0 {
		return kv, errors.New("kernelVersionStr can't be empty")
	}

	sp := strings.SplitN(kernelVersionStr, "-", 2)
	if len(sp) < 1 {
		return kv, errors.New("could not determine a kernel version from the provided kernelVersionStr")
	}

	kv.Version = sp[0]
	if len(sp) == 2 {
		kv.LocalVersion = sp[1]
	}
	return kv, nil
}
