package httpapi_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	fikuacrypto "github.com/fikua/fikua-lab-idp/internal/crypto"
	"github.com/fikua/fikua-lab-idp/internal/issuerclient"
)

// testBaseURL is this AS's own identifier for every test in this package
// — arbitrary but fixed, since nothing here dereferences it as a real
// host; it only has to match consistently between the handler under test
// and whatever it signs/checks against (DPoP htu, client_id, etc).
const testBaseURL = "https://idp.test.fikua.internal"

// newTestSigningKey builds a *fikuacrypto.SigningKey backed by a fresh
// EC P-256 key written to a temp certs dir — the only way
// fikuacrypto.LoadFromPEM constructs one (see its own doc comment on why
// there is no in-memory constructor: production deliberately has no
// ephemeral-key fallback, so tests go through the same file-loading path
// rather than a separate code path that could drift from it).
func newTestSigningKey(t *testing.T) *fikuacrypto.SigningKey {
	t.Helper()
	dir := t.TempDir()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, "idp-key.pem"), pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := fikuacrypto.LoadFromPEM(dir)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

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
