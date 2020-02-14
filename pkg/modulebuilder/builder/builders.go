package builder

import (
	"fmt"

	"github.com/asaskevich/govalidator"
)

const KernelDirectory = "/tmp/kernel"
const ModuleDirectory = "/tmp/module"

type BuildType string

var EnabledBuildTypes = map[BuildType]bool{}

func init() {
	govalidator.TagMap["buildtype"] = func(str string) bool {
		if val, ok := EnabledBuildTypes[BuildType(str)]; ok {
			return val
		}
		return false
	}
}

type BuilderConfig struct {
	ModuleConfig     ModuleConfig
	KernelConfigData string
	KernelVersion    string
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
