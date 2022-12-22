package builder

import (
	"github.com/blang/semver"
)

type Image struct {
	Target     Type
	GCCVersion semver.Version // we expect images to internally link eg: gcc5 to gcc5.0.0
	Name       string
}

func (i *Image) toKey() string {
	return i.Target.String() + "_" + i.GCCVersion.String()
}
