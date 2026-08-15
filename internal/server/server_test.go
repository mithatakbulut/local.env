package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/localenv/localenv/internal/config"
)

type testStore struct{ err error }

func (s testStore) Ready(context.Context) error { return s.err }

func TestOperationalEndpoints(t *testing.T) {
	app := New(config.Config{}, testStore{})
	for _, path := range []string{"/healthz", "/readyz"} {
		recorder := httptest.NewRecorder()
		app.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, want 200", path, recorder.Code)
		}
	}
}

func TestReadyzFailsWhenStoreIsUnavailable(t *testing.T) {
	app := New(config.Config{}, testStore{err: errors.New("unavailable")})
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("GET /readyz status = %d, want 503", recorder.Code)
	}
}
