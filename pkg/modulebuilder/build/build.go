package build

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/asaskevich/govalidator"
	"github.com/falcosecurity/build-service/pkg/modulebuilder/builder"
)

type Build struct {
	BuildType        builder.BuildType `valid:"buildtype"`
	KernelConfigData string            `valid:"base64"`
	KernelVersion    string            `valid:"ascii"` // TODO(fntlnz): make specific validator for this?
	ModuleVersion    string            `valid:"ascii"` // TODO(fntlnz):make specific validator for this? (check govalidator semver)
	Architecture     string            `valid:"buildarchitecture"`
}

func (b *Build) Validate() (bool, error) {
	return govalidator.ValidateStruct(b)
}

func (b *Build) SHA256() (string, error) {
	configDecoded, err := base64.StdEncoding.DecodeString(b.KernelConfigData)
	if err != nil {
		return "", err
	}

	shasum := sha256.Sum256([]byte(configDecoded))
	return fmt.Sprintf("%x", shasum), nil
}
