package server

import (
	"context"
	"fmt"
	"net/http"

	"github.com/falcosecurity/build-service/pkg/modulebuilder/builder"
	"github.com/gorilla/mux"

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

func (h *Handlers) ModuleHandlerGet(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	buildType := vars["buildtype"]
	architecture := vars["architecture"]
	kernel := vars["kernel"]
	configSHA256 := vars["configsha256"]

	w.Write([]byte(fmt.Sprintf("you to retrieve - this is not yet implemented: %s - %s - %s - %s", buildType, architecture, kernel, configSHA256)))
}

func (h *Handlers) ModuleHandlerPost(w http.ResponseWriter, req *http.Request) {
	b := modulebuilder.Build{
		BuildType:        builder.BuildTypeVanilla,
		KernelConfigData: "",
		KernelVersion:    "5.5.2",
		Architecture:     "x86_64",
	}

	if valid, err := b.Validate(); !valid || err != nil {
		// TODO(fntlnz): write validation errors to response?
		h.logger.Info("ciao", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err := h.buildProcessor.Request(b)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}

	// TODO(fntlnz): write location for the future resource or inform about the existing one
	w.WriteHeader(http.StatusAccepted)
}
