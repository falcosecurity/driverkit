package types

import (
	"github.com/falcosecurity/build-service/pkg/modulebuilder/builder"
	"github.com/falcosecurity/build-service/pkg/modulebuilder/buildtype"
	"path"

	"github.com/asaskevich/govalidator"
	"github.com/falcosecurity/build-service/pkg/modulebuilder/build"
)

func init() {
	govalidator.TagMap["sha256"] = govalidator.IsSHA256
}

type ErrorResponse struct {
	Reason string `json:"reason"`
}

func NewErrorResponse(err error) ErrorResponse {
	return ErrorResponse{Reason: err.Error()}
}

type ModuleRetrieveRequest struct {
	BuildType     buildtype.BuildType `valid:"buildtype,required"`
	Architecture  string              `valid:"buildarchitecture,required"`
	ConfigSHA256  string              `valid:"sha256,required"`
	KernelRelease string              `valid:"ascii,required"` // TODO(fntlnz): make specific validator for this?
	KernelVersion string              `valid:"int,required"`
	ModuleVersion string              `valid:"ascii,required"` // TODO(fntlnz):make specific validator for this? (check govalidator semver)

}

func (m *ModuleRetrieveRequest) Validate() (bool, error) {
	return govalidator.ValidateStruct(m)
}

type ModuleBuildResponse struct {
	Href string `json:"href"`
}

func NewBuildResponseFromBuild(b build.Build) ModuleBuildResponse {
	s, _ := b.SHA256()
	return ModuleBuildResponse{Href: path.Join("/v1/module", b.BuildType.String(), b.Architecture, b.ModuleVersion, b.KernelRelease, b.KernelVersion, s, builder.ModuleFileName)}
}
