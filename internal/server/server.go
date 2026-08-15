// Package server exposes the small P0 operational HTTP surface.
package server

import (
	"context"
	"net/http"
	"time"

	"github.com/localenv/localenv/internal/config"
)

// readinessStore is the small store contract required by operational routes.
type readinessStore interface {
	Ready(context.Context) error
}

// Server holds dependencies for HTTP handlers.
type Server struct {
	config config.Config
	store  readinessStore
}

// New constructs a server.
func New(config config.Config, store readinessStore) *Server {
	return &Server{config: config, store: store}
}

// Handler returns the public HTTP routes available during P0.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /readyz", s.readyz)
	return mux
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if s.store.Ready(ctx) != nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready\n"))
}
