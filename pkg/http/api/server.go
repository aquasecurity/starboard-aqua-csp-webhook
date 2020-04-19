package api

import (
	"context"
	"net/http"

	"github.com/aquasecurity/starboard-aqua-csp-webhook/pkg/etc"
	log "github.com/sirupsen/logrus"
)

type Server struct {
	config etc.API
	server *http.Server
}

func NewServer(config etc.API, handler http.Handler) (server *Server) {
	server = &Server{
		config: config,
		server: &http.Server{
			Handler: handler,
			Addr:    config.Addr,
		},
	}
	return
}

func (s *Server) ListenAndServe() {
	log.Infof("Starting API server on %s", s.config.Addr)
	if err := s.server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Error: %v", err)
	}
	log.Trace("API server stopped listening for incoming connections")
}

func (s *Server) Shutdown() {
	log.Trace("API server shutdown started")
	if err := s.server.Shutdown(context.Background()); err != nil {
		log.WithError(err).Error("Error while shutting down API server")
		return
	}
	log.Trace("API server shutdown completed")
}
