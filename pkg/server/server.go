package server

import (
	"context"
	"net"
	"net/http"
	"time"

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
	ctx := context.Background()

	handlers := NewHandlers()
	handlers.WithContext(ctx)

	router := mux.NewRouter()

	s := &Server{
		logger:     zap.NewNop(),
		handlers:   handlers,
		tlsOptions: nil,
		address:    addr,
		router:     router,
		ctx:        ctx,
	}

	v1Router := router.PathPrefix("/v1").Subrouter()

	v1Router.HandleFunc("/module/{buildtype}/{architecture}/{kernel}/{configsha256}", handlers.ModuleHandlerGet).Methods(http.MethodGet)
	v1Router.HandleFunc("/module", handlers.ModuleHandlerPost).Methods(http.MethodPost)
	router.Use(s.loggingMiddleware)
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
	s.handlers.WithContext(ctx)
}

func (s *Server) ListenAndServe() error {
	server := &http.Server{
		Addr:              s.address,
		Handler:           s.router,
		WriteTimeout:      time.Second * 15,
		ReadTimeout:       time.Second * 15,
		ReadHeaderTimeout: time.Second * 15,
		IdleTimeout:       time.Second * 60,
		ErrorLog:          zap.NewStdLog(s.logger.With(zap.String("source", "net/http"))),
	}
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

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.logger.Info("request", zap.String("url", r.URL.String()), zap.String("remote_addr", r.RemoteAddr))
		next.ServeHTTP(w, r)
	})
}
