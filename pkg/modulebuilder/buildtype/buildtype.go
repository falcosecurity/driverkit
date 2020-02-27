package buildtype

import (
	"github.com/asaskevich/govalidator"
)

type BuildType string

func init() {
	govalidator.TagMap["buildtype"] = isBuildTypeEnabled
}

func (bt BuildType) String() string {
	return string(bt)
}

var EnabledBuildTypes = map[BuildType]bool{}

func isBuildTypeEnabled(str string) bool {
	if val, ok := EnabledBuildTypes[BuildType(str)]; ok {
		return val
	}
	return false
}
