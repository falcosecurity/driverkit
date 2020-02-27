package build

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/falcosecurity/build-service/pkg/modulebuilder/buildtype"

	"github.com/asaskevich/govalidator"
)

type Build struct {
	BuildType        buildtype.BuildType `valid:"buildtype,required"`
	KernelConfigData string              `valid:"base64"`
	KernelRelease    string              `valid:"ascii,required"` // TODO(fntlnz): make specific validator for this?
	KernelVersion    string              `valid:"int,required"`
	ModuleVersion    string              `valid:"ascii,required"` // TODO(fntlnz):make specific validator for this? (check govalidator semver)
	Architecture     string              `valid:"buildarchitecture,required"`
	OutputFilePath   string              `valid:"ascii,required"`
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
