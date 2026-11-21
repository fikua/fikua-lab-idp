package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthPass(t *testing.T) {
	rec := httptest.NewRecorder()
	(&Handler{}).health(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/health+json" || rec.Body.String() != `{"status":"pass"}`+"\n" {
		t.Fatalf("%d %q %s", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
	}
}
