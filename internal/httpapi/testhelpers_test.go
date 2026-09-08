package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fikua/fikua-lab-idp/internal/issuerclient"
)

// testBaseURL is this AS's own identifier for every test in this package
// — arbitrary but fixed, since nothing here dereferences it as a real
// host; it only has to match consistently between the handler under test
// and whatever it signs/checks against (DPoP htu, client_id, etc).
const testBaseURL = "https://idp.test.fikua.internal"

// newStubIssuerServer stands in for the Credential Issuer this AS talks
// to via internal/issuerclient. found controls FindByIssuerState's
// result — true answers every by-issuer-state lookup with a fixed
// issuance record id, false answers every lookup with 404 (an ordinary
// "no matching record", per issuerclient.FindByIssuerState's own doc
// comment). Only implements the two issuerclient endpoints this
// package's tests actually exercise: PID claim collection has no test
// coverage here that reaches CredentialClaims.
func newStubIssuerServer(t *testing.T, found bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /oid4vci/v1/issuance/by-issuer-state/", func(w http.ResponseWriter, r *http.Request) {
		if !found {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(issuerclient.Record{ID: "test-issuance-record"})
	})
	mux.HandleFunc("POST /oid4vci/v1/issuance", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"issuance_id": "test-issuance-record"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}
