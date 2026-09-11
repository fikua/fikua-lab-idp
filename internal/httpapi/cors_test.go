package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWithCORSSetsHeadersOnOrdinaryRequest(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Origin", "https://wallet.fikua.com")
	rec := httptest.NewRecorder()

	WithCORS(next).ServeHTTP(rec, req)

	if !called {
		t.Error("WithCORS must call through to next for a non-OPTIONS request")
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want \"*\"", got)
	}
	if rec.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("Access-Control-Allow-Methods must be set")
	}
	if rec.Header().Get("Access-Control-Allow-Headers") == "" {
		t.Error("Access-Control-Allow-Headers must be set")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (from next)", rec.Code)
	}
}

func TestWithCORSShortCircuitsPreflight(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest(http.MethodOptions, "/oid4vci/v1/par", nil)
	req.Header.Set("Origin", "https://wallet.fikua.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()

	WithCORS(next).ServeHTTP(rec, req)

	if called {
		t.Error("WithCORS must not call next for an OPTIONS preflight request")
	}
	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want \"*\"", got)
	}
}
