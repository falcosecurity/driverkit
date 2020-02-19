package types

import (
	"path"

	"github.com/asaskevich/govalidator"
	"github.com/falcosecurity/build-service/pkg/modulebuilder/build"
	"github.com/falcosecurity/build-service/pkg/modulebuilder/builder"
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
	BuildType     builder.BuildType `valid:"buildtype"`
	Architecture  string            `valid:"buildarchitecture"`
	ConfigSHA256  string            `valid:"sha256"`
	KernelVersion string            `valid:"ascii"` // TODO(fntlnz): make specific validator for this?
	ModuleVersion string            `valid:"ascii"` // TODO(fntlnz):make specific validator for this? (check govalidator semver)

}

func (m *ModuleRetrieveRequest) Validate() (bool, error) {
	return govalidator.ValidateStruct(m)
}

type ModuleBuildResponse struct {
	Href string `json:"href"`
}

func NewBuildResponseFromBuild(b build.Build) ModuleBuildResponse {
	s, _ := b.SHA256()
	return ModuleBuildResponse{Href: path.Join("module", b.BuildType.String(), b.Architecture, b.ModuleVersion, b.KernelVersion, s)}
}
