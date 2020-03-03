package buildtype

type BuildType string

func (bt BuildType) String() string {
	return string(bt)
}

var EnabledBuildTypes = map[BuildType]bool{}
