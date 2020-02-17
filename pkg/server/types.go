package server

import (
	"path"

	"github.com/asaskevich/govalidator"
	"github.com/falcosecurity/build-service/pkg/modulebuilder"
	"github.com/falcosecurity/build-service/pkg/modulebuilder/builder"
)

type ErrorResponse struct {
	Reason string `json:"reason"`
}

func NewErrorResponse(err error) ErrorResponse {
	return ErrorResponse{Reason: err.Error()}
}

type ModuleRetrieveRequest struct {
	BuildType     builder.BuildType `valid:"buildtype"`
	Architecture  string            `valid:"buildarchitecture"`
	KernelVersion string
	ConfigSHA256  string
}

func (m *ModuleRetrieveRequest) Validate() (bool, error) {
	return govalidator.ValidateStruct(m)
}

type ModuleBuildResponse struct {
	Href string `json:"href"`
}

func NewBuildResponseFromBuild(b modulebuilder.Build) ModuleBuildResponse {
	return ModuleBuildResponse{Href: path.Join("module", b.BuildType.String(), b.Architecture, b.KernelVersion, b.SHA256())}
}
