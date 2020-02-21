package server

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/falcosecurity/build-service/pkg/modulebuilder/buildtype"
	"io"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/falcosecurity/build-service/pkg/filesystem"
	"github.com/falcosecurity/build-service/pkg/modulebuilder"
	"github.com/falcosecurity/build-service/pkg/modulebuilder/build"
	"github.com/falcosecurity/build-service/pkg/server/types"
	"go.uber.org/zap"
)

type Handlers struct {
	logger         *zap.Logger
	ctx            context.Context
	buildProcessor modulebuilder.BuildProcessor
	moduleStorage  *filesystem.ModuleStorage
}

func NewHandlers() *Handlers {
	return &Handlers{
		logger:         zap.NewNop(),
		ctx:            context.TODO(),
		buildProcessor: modulebuilder.NewNopBuildProcessor(),
		moduleStorage:  filesystem.NewModuleStorage(filesystem.NewNop()),
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

func (h *Handlers) WithModuleStorage(ms *filesystem.ModuleStorage) {
	h.moduleStorage = ms
}

// TODO(fntlnz): need better json error handling here
func (h *Handlers) ModuleHandlerGet(w http.ResponseWriter, req *http.Request) {
	logger := h.logger.With(zap.String("handler", "ModuleHandlerGet"))
	vars := mux.Vars(req)
	mrr := types.ModuleRetrieveRequest{
		BuildType:     buildtype.BuildType(vars["buildtype"]),
		Architecture:  vars["architecture"],
		KernelRelease: vars["kernelrelease"],
		KernelVersion: vars["kernelversion"],
		ModuleVersion: vars["moduleversion"],
		ConfigSHA256:  vars["configsha256"],
	}
	if valid, err := mrr.Validate(); !valid {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		e := json.NewEncoder(w)
		if err := e.Encode(types.NewErrorResponse(err)); err != nil {
			logger.Error("error decoding response", zap.Error(err))
			return
		}
		return
	}

	r, err := h.moduleStorage.FindModuleWithModuleRetrieveRequest(mrr)
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		status := http.StatusInternalServerError
		if filesystem.ErrIsModuleDoesNotExists(err) {
			status = http.StatusNotFound
		}
		w.WriteHeader(status)
		e := json.NewEncoder(w)
		if err := e.Encode(types.NewErrorResponse(err)); err != nil {
			logger.Error("error decoding response", zap.Error(err))
			return
		}
		return
	}

	defer r.Close()

	io.Copy(w, r)
}

func (h *Handlers) ModuleHandlerPost(w http.ResponseWriter, req *http.Request) {
	logger := h.logger.With(zap.String("handler", "ModuleHandlerPost"))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	if req.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusBadRequest)
		e := json.NewEncoder(w)
		if err := e.Encode(types.NewErrorResponse(fmt.Errorf("bad content type, please use: application/json"))); err != nil {
			logger.Error("error decoding response", zap.Error(err))
			return
		}
		return
	}
	b := build.Build{}
	if err := JsonRequestDecode(req.Body, &b); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		logger.Error("error decoding build", zap.Error(err))
		return
	}

	if valid, err := b.Validate(); !valid || err != nil {
		logger.Info("build not valid", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		e := json.NewEncoder(w)
		if err := e.Encode(types.NewErrorResponse(err)); err != nil {
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
	if err := e.Encode(types.NewBuildResponseFromBuild(b)); err != nil {
		logger.Error("error decoding response", zap.Error(err))
		return
	}
}
