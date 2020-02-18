package build

import (
	"crypto/sha256"
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

func (b *Build) SHA256() string {
	shasum := sha256.Sum256([]byte(b.KernelConfigData))
	return fmt.Sprintf("%x", shasum)
}
