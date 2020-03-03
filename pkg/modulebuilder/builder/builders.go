package builder

import (
	"fmt"
	buildmeta "github.com/falcosecurity/driverkit/pkg/modulebuilder/build"
	"github.com/falcosecurity/driverkit/pkg/modulebuilder/buildtype"
	"path"
)

const ModuleDirectory = "/tmp/module"
const ModuleFileName = "falco.ko"

var FalcoModuleFullPath = path.Join(ModuleDirectory, ModuleFileName)

type BuilderConfig struct {
	ModuleConfig ModuleConfig
	Build        *buildmeta.Build
}

type ModuleConfig struct {
	ModuleName      string
	DeviceName      string
	DownloadBaseURL string
}

type Builder interface {
	Script(bc BuilderConfig) (string, error)
}

func Factory(buildType buildtype.BuildType) (Builder, error) {
	// TODO(fntlnz): avoid duplicating this information, we already know which ones are enabled
	// look at buildtype.EnabledBuildTypes
	switch buildType {
	case BuildTypeVanilla:
		return &Vanilla{}, nil
	case BuildTypeUbuntuGeneric:
		return &UbuntuGeneric{}, nil
	case BuildTypeUbuntuAWS:
		return &UbuntuAWS{}, nil
	}
	return nil, fmt.Errorf("build type not found: %s", buildType)
}

func moduleDownloadURL(bc BuilderConfig) string {
	return fmt.Sprintf("%s/%s.tar.gz", bc.ModuleConfig.DownloadBaseURL, bc.Build.ModuleVersion)
}
