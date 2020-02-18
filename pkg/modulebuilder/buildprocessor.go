package modulebuilder

import (
	"context"

	"github.com/asaskevich/govalidator"
	"github.com/falcosecurity/build-service/pkg/filesystem"
	"github.com/falcosecurity/build-service/pkg/modulebuilder/build"
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
	Start() error
	Request(b build.Build) error
	WithContext(c context.Context)
	WithLogger(logger *zap.Logger)
	WithModuleStorage(ms *filesystem.ModuleStorage)
	String() string
}

func isBuildArchitectureEnabled(str string) bool {
	if val, ok := EnabledBuildArchitectures[BuildArchitecture(str)]; ok {
		return val
	}
	return false
}
