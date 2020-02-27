package modulebuilder

import (
	"github.com/falcosecurity/driverkit/pkg/modulebuilder/build"

	"github.com/asaskevich/govalidator"
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

type BuildProcessor interface {
	Start(b build.Build) error
	WithLogger(logger *zap.Logger)
	String() string
}

func isBuildArchitectureEnabled(str string) bool {
	if val, ok := EnabledBuildArchitectures[BuildArchitecture(str)]; ok {
		return val
	}
	return false
}
