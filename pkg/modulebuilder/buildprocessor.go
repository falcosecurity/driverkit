package modulebuilder

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/asaskevich/govalidator"
	"github.com/falcosecurity/build-service/pkg/modulebuilder/builder"
	"go.uber.org/zap"
)

type BuildArchitecture string

const BuildArchitectureX86_64 BuildArchitecture = "x86_64"

func (ba BuildArchitecture) String() string {
	return string(ba)
}

var EnabledBuildArchitectures = map[BuildArchitecture]bool{}

func init() {
	govalidator.TagMap["buildarchitecture"] = isBuildArchitectureEnabled
	EnabledBuildArchitectures[BuildArchitectureX86_64] = true
}

type Build struct {
	BuildType        builder.BuildType `valid:"buildtype"`
	KernelConfigData string
	KernelVersion    string
	// only architecture supported is x86_64 now, if you want to add one, just add it:
	// e.g: in(x86_64|ppcle64|armv7hf)
	Architecture string `valid:"buildarchitecture"`
}

func (b *Build) Validate() (bool, error) {
	return govalidator.ValidateStruct(b)
}

func (b *Build) SHA256() string {
	shasum := sha256.Sum256([]byte(b.KernelConfigData))
	return fmt.Sprintf("%x", shasum)
}

type BuildProcessor interface {
	Start() error
	Request(b Build) error
	WithContext(c context.Context)
	WithLogger(logger *zap.Logger)
	String() string
}

func isBuildArchitectureEnabled(str string) bool {
	if val, ok := EnabledBuildArchitectures[BuildArchitecture(str)]; ok {
		return val
	}
	return false
}
