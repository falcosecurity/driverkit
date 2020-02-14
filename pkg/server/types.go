package server

import (
	"path"

	"github.com/falcosecurity/build-service/pkg/modulebuilder"
)

type ErrorResponse struct {
	Reason string `json:"reason"`
}

func NewErrorResponse(err error) ErrorResponse {
	return ErrorResponse{Reason: err.Error()}
}

type ModuleBuildResponse struct {
	Href string `json:"href"`
}

func NewBuildResponseFromBuild(b modulebuilder.Build) ModuleBuildResponse {
	return ModuleBuildResponse{Href: path.Join("module", b.BuildType.String(), b.Architecture, b.KernelVersion, b.SHA256())}
}
