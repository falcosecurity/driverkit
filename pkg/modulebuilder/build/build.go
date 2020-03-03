package build

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/falcosecurity/driverkit/pkg/modulebuilder/buildtype"
)

type Build struct {
	BuildType        buildtype.BuildType
	KernelConfigData string
	KernelRelease    string // TODO(fntlnz): make specific validator for this?
	KernelVersion    string
	ModuleVersion    string // TODO(fntlnz):make specific validator for this?
	Architecture     string
	OutputFilePath   string
}

func (b *Build) SHA256() (string, error) {
	configDecoded, err := base64.StdEncoding.DecodeString(b.KernelConfigData)
	if err != nil {
		return "", err
	}

	shasum := sha256.Sum256([]byte(configDecoded))
	return fmt.Sprintf("%x", shasum), nil
}
