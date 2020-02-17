package builder

import (
	"fmt"
	"path"

	"github.com/asaskevich/govalidator"
)

const KernelDirectory = "/tmp/kernel"
const ModuleDirectory = "/tmp/module"

var FalcoModuleFullPath = path.Join(ModuleDirectory, "falco.ko")

type BuildType string

func (bt BuildType) String() string {
	return string(bt)
}

var EnabledBuildTypes = map[BuildType]bool{}

func init() {
	govalidator.TagMap["buildtype"] = isBuildTypeEnabled
}

type BuilderConfig struct {
	ModuleConfig  ModuleConfig
	KernelVersion string
}

type ModuleConfig struct {
	ModuleVersion   string
	ModuleName      string
	DeviceName      string
	DownloadBaseURL string
}

type Builder interface {
	Script(bc BuilderConfig) (string, error)
}

func Factory(buildType BuildType) (Builder, error) {
	switch buildType {
	case BuildTypeVanilla:
		return &Vanilla{}, nil
	}
	return nil, fmt.Errorf("build type not found: %s", buildType)
}

func isBuildTypeEnabled(str string) bool {
	if val, ok := EnabledBuildTypes[BuildType(str)]; ok {
		return val
	}
	return false
}
