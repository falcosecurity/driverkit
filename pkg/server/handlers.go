package server

import (
	"context"
	"net/http"

	"github.com/falcosecurity/build-service/pkg/modulebuilder"
	"go.uber.org/zap"
)

type Handlers struct {
	logger         *zap.Logger
	ctx            context.Context
	buildProcessor modulebuilder.BuildProcessor
}

func NewHandlers() *Handlers {
	return &Handlers{
		logger:         zap.NewNop(),
		ctx:            context.TODO(),
		buildProcessor: modulebuilder.NewNopBuildProcessor(),
	}
}

func (h *Handlers) WithLogger(logger *zap.Logger) {
	h.logger = logger
}

func (h *Handlers) WithContext(c context.Context) {
	h.ctx = c
}

func (h *Handlers) WithBuildProcessor(bp modulebuilder.BuildProcessor) {
	h.buildProcessor = bp
}

func (h *Handlers) ModuleHandler(w http.ResponseWriter, req *http.Request) {
	// TODO(fntlnz): This will need to come from the request
	// TODO(fntlnz): we only want to build if the module for this config is not in storage
	b := modulebuilder.Build{
		BuildType: modulebuilder.BuildTypeVanilla,
	}
	err := h.buildProcessor.Request(b)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}
