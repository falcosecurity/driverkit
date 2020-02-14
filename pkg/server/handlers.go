package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

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
	// TODO(fntlnz): build a struct and validate the paramaters
	vars := mux.Vars(req)
	buildType := vars["buildtype"]
	architecture := vars["architecture"]
	kernel := vars["kernel"]
	configSHA256 := vars["configsha256"]

	// TODO(fntlnz): download from the configured filesystem here
	w.Write([]byte(fmt.Sprintf("you to retrieve - this is not yet implemented: %s - %s - %s - %s", buildType, architecture, kernel, configSHA256)))
}

func (h *Handlers) ModuleHandlerPost(w http.ResponseWriter, req *http.Request) {
	logger := h.logger.With(zap.String("handler", "ModuleHandlerPost"))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	if req.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusBadRequest)
		e := json.NewEncoder(w)
		if err := e.Encode(NewErrorResponse(fmt.Errorf("bad content type, please use: application/json"))); err != nil {
			logger.Error("error decoding response", zap.Error(err))
			return
		}
		return
	}
	b := modulebuilder.Build{}
	if err := JsonRequestDecode(req.Body, &b); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		logger.Error("error decoding build", zap.Error(err))
		return
	}

	if valid, err := b.Validate(); !valid || err != nil {
		logger.Info("build not valid", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		e := json.NewEncoder(w)
		if err := e.Encode(NewErrorResponse(err)); err != nil {
			logger.Error("error decoding response", zap.Error(err))
			return
		}
		return
	}

	if err := h.buildProcessor.Request(b); err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}

	w.WriteHeader(http.StatusAccepted)
	e := json.NewEncoder(w)
	if err := e.Encode(NewBuildResponseFromBuild(b)); err != nil {
		logger.Error("error decoding response", zap.Error(err))
		return
	}
}
