// Package httpapi_test exercises Handler's routes end-to-end via a real
// httptest.Server, mirroring fikua-lab-attestation-registry's own
// internal/httpapi/handlers_test.go pattern: an external test package, a
// newTestServer(t) helper, small table-free test funcs, no assertion
// framework.
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

	"github.com/fikua/fikua-lab-idp/internal/authz"
	fikuacrypto "github.com/fikua/fikua-lab-idp/internal/crypto"
	"github.com/fikua/fikua-lab-idp/internal/httpapi"
	"github.com/fikua/fikua-lab-idp/internal/issuerclient"
	"github.com/fikua/fikua-lab-idp/internal/oauth2"
	"github.com/fikua/fikua-lab-idp/internal/session"
)

const testBaseURL = "https://idp.fikua.test"

// newStubIssuerServer starts a minimal Credential Issuer stand-in. When
// healthy is false, /health answers with a non-200 status so
// GET /health on the Handler under test can be observed reporting
// "degraded" — issuerclient.Client.Healthy treats anything but 200 as
// unhealthy.
func newStubIssuerServer(t *testing.T, healthy bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		if !healthy {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /oid4vci/v1/issuance/by-issuer-state/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("POST /oid4vci/v1/issuance", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"issuance_id": "issuance-1"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// newTestSigningKey builds a fikuacrypto.SigningKey via the same PEM file
// round trip production code uses — SigningKey has no in-memory
// constructor of its own.
func newTestSigningKey(t *testing.T) *fikuacrypto.SigningKey {
	t.Helper()
	dir := t.TempDir()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating EC key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshaling PKCS#8 key: %v", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	if err := os.WriteFile(filepath.Join(dir, "idp-key.pem"), pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("writing idp-key.pem: %v", err)
	}
	key, err := fikuacrypto.LoadFromPEM(dir)
	if err != nil {
		t.Fatalf("LoadFromPEM: %v", err)
	}
	return key
}

// newTestServer wires a real httpapi.Handler against a stub Credential
// Issuer (healthy by default) and no OID4VP Verifier (verifierService is
// nil, matching how cmd/idp/main.go runs with no FIKUA_DSS_URL — Routes
// simply doesn't register the /oid4vp/v1/* endpoints in that case).
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return newTestServerWithIssuerHealth(t, true)
}

func newTestServerWithIssuerHealth(t *testing.T, issuerHealthy bool) *httptest.Server {
	t.Helper()
	issuerSrv := newStubIssuerServer(t, issuerHealthy)
	issuer := issuerclient.New(issuerSrv.URL)
	sessions := session.NewStore()
	signingKey := newTestSigningKey(t)
	minter := oauth2.NewMinter(signingKey, testBaseURL, "https://issuer.fikua.test")
	authzService := authz.NewService(testBaseURL, sessions, issuer, minter, nil)

	mux := http.NewServeMux()
	httpapi.NewHandler(testBaseURL, signingKey, authzService, issuer, nil).Routes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestHealthOK(t *testing.T) {
	srv := newTestServer(t)

	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "ok" {
		t.Errorf("status field = %q, want %q", body["status"], "ok")
	}
}

func TestHealthDegradedWhenIssuerUnhealthy(t *testing.T) {
	srv := newTestServerWithIssuerHealth(t, false)

	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (degraded is still a 200 body)", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "degraded" {
		t.Errorf("status field = %q, want %q", body["status"], "degraded")
	}
}

func TestOpenAPISpecIsServed(t *testing.T) {
	srv := newTestServer(t)

	resp, err := http.Get(srv.URL + "/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, err := readAll(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) == 0 {
		t.Fatal("expected a non-empty OpenAPI spec body")
	}
}

func TestSwaggerUIPageIsServed(t *testing.T) {
	srv := newTestServer(t)

	resp, err := http.Get(srv.URL + "/swagger")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestAuthServerMetadataShape(t *testing.T) {
	srv := newTestServer(t)

	resp, err := http.Get(srv.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["issuer"] != testBaseURL {
		t.Errorf("issuer = %v, want %q", body["issuer"], testBaseURL)
	}
	if body["token_endpoint"] != testBaseURL+"/oid4vci/v1/token" {
		t.Errorf("token_endpoint = %v", body["token_endpoint"])
	}
	if body["pushed_authorization_request_endpoint"] != testBaseURL+"/oid4vci/v1/par" {
		t.Errorf("pushed_authorization_request_endpoint = %v", body["pushed_authorization_request_endpoint"])
	}
	if required, ok := body["require_pushed_authorization_requests"].(bool); !ok || !required {
		t.Errorf("require_pushed_authorization_requests = %v, want true", body["require_pushed_authorization_requests"])
	}
	methods, ok := body["code_challenge_methods_supported"].([]any)
	if !ok || len(methods) != 1 || methods[0] != "S256" {
		t.Errorf("code_challenge_methods_supported = %v, want [S256]", body["code_challenge_methods_supported"])
	}
}

func TestParMissingAttestationReturns400(t *testing.T) {
	srv := newTestServer(t)

	resp, err := http.PostForm(srv.URL+"/oid4vci/v1/par", parFormNoAttestation())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestParHappyPathReturnsRequestURI(t *testing.T) {
	srv := newTestServer(t)
	client := newTestWalletClient(t)

	form := parFormNoAttestation()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/oid4vci/v1/par", formBody(form))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(oauth2.HeaderClientAttestation, client.wia)
	req.Header.Set(oauth2.HeaderClientAttestationPoP, client.pop(t))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	requestURI, _ := body["request_uri"].(string)
	if requestURI == "" {
		t.Fatal("expected a non-empty request_uri")
	}
	if body["expires_in"] != float64(60) {
		t.Errorf("expires_in = %v, want 60", body["expires_in"])
	}
}

func TestAuthorizeMissingRequestURIReturnsErrorPage(t *testing.T) {
	srv := newTestServer(t)

	resp, err := http.Get(srv.URL + "/oid4vci/v1/authorize")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if want := "text/html"; ct == "" || !containsPrefix(ct, want) {
		t.Errorf("Content-Type = %q, want prefix %q", ct, want)
	}
}

func TestTokenMissingGrantReturns400(t *testing.T) {
	srv := newTestServer(t)

	form := map[string][]string{}
	resp, err := http.Post(srv.URL+"/oid4vci/v1/token", "application/x-www-form-urlencoded", formBody(form))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}

	var body oauth2.Error
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Code != oauth2.UnsupportedGrantType {
		t.Errorf("error code = %q, want %q", body.Code, oauth2.UnsupportedGrantType)
	}
}
