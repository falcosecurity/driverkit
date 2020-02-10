package server

import (
	"context"
	"net"
	"net/http"

	"github.com/falcosecurity/build-service/pkg/modulebuilder"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
)

type TLSOptions struct {
	certFile string
	keyFile  string
}

func NewTLSOptions(certFile, keyFile string) *TLSOptions {
	return &TLSOptions{certFile: certFile, keyFile: keyFile}
}

type Server struct {
	logger           *zap.Logger
	kubernetesClient *kubernetes.Clientset
	handlers         *Handlers
	buildProcessor   modulebuilder.BuildProcessor
	address          string
	tlsOptions       *TLSOptions
	router           *mux.Router
	ctx              context.Context
}

func NewServer(addr string) *Server {
	s := &Server{
		logger:     zap.NewNop(),
		handlers:   NewHandlers(),
		tlsOptions: nil,
		address:    addr,
		router:     mux.NewRouter(),
		ctx:        context.Background(),
	}
	s.router.HandleFunc("/module", s.handlers.ModuleHandler)
	return s
}

func (s *Server) WithLogger(logger *zap.Logger) {
	s.logger = logger
	s.handlers.WithLogger(logger)
}

func (s *Server) WithBuildProcessor(bp modulebuilder.BuildProcessor) {
	s.buildProcessor = bp
	s.handlers.WithBuildProcessor(bp)
}

func (s *Server) WithTLSOptions(tlsopts *TLSOptions) {
	s.tlsOptions = tlsopts
}

func (s *Server) WithContext(ctx context.Context) {
	s.ctx = ctx
}

func (s *Server) ListenAndServe() error {
	server := &http.Server{Addr: s.address, Handler: s.router}
	server.BaseContext = func(l net.Listener) context.Context {
		return s.ctx
	}
	if s.tlsOptions != nil {
		s.logger.Info(
			"started https server",
			zap.String("address", s.address),
			zap.String("certfile", s.tlsOptions.certFile),
			zap.String("keyfile", s.tlsOptions.keyFile),
		)
		return server.ListenAndServeTLS(s.tlsOptions.certFile, s.tlsOptions.keyFile)
	}
	s.logger.Info(
		"started http server",
		zap.String("address", s.address),
	)
	return server.ListenAndServe()
}
