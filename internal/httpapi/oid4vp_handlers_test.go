package httpapi_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	fikuacrypto "github.com/fikua/fikua-lab-idp/internal/crypto"
	"github.com/fikua/fikua-lab-idp/internal/httpapi"
	"github.com/fikua/fikua-lab-idp/internal/issuerclient"
	"github.com/fikua/fikua-lab-idp/internal/session"
	"github.com/fikua/fikua-lab-idp/internal/verifier"
)

// newTestRequestSigningKey builds a *fikuacrypto.RequestSigningKey backed
// by a fresh in-memory ECDSA P-256 key and a self-signed leaf certificate —
// this Verifier's Algorithm() is fixed at ES256 (ECDSA/P-256/SHA-256), so
// this is the only key shape it accepts. Stands in for the DSS-issued key
// every real deployment uses (see fikuacrypto.RequestSigningKey's own doc
// comment on why there is no local-PEM alternative in production).
func newTestRequestSigningKey(t *testing.T) *fikuacrypto.RequestSigningKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-verifier"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	key, err := fikuacrypto.NewRequestSigningKey(priv, [][]byte{der})
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// newTestServerWithVerifier is newTestServer's counterpart with a real
// OID4VP Verifier wired in (direct_post response mode — no JWE round
// trip needed to exercise the HTTP layer these tests cover).
func newTestServerWithVerifier(t *testing.T) *httptest.Server {
	t.Helper()
	issuerSrv := newStubIssuerServer(t, true)
	issuer := issuerclient.New(issuerSrv.URL)
	sessions := session.NewStore()
	signingKey := newTestSigningKey(t)
	verifierService := verifier.NewService(testBaseURL, newTestRequestSigningKey(t), sessions, verifier.ResponseModeDirectPost)

	mux := http.NewServeMux()
	httpapi.NewHandler(testBaseURL, signingKey, nil, issuer, verifierService).Routes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestOid4vpCreateSessionDefaultsToPID(t *testing.T) {
	srv := newTestServerWithVerifier(t).URL

	resp, err := http.Post(srv+"/oid4vp/v1/session", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["session_id"] == "" || body["request_uri"] == "" || body["client_id"] == "" || body["state"] == "" {
		t.Fatalf("incomplete session response: %+v", body)
	}
}

func TestOid4vpCreateSessionMultiCredential(t *testing.T) {
	srv := newTestServerWithVerifier(t).URL

	reqBody := `{"credentials":[
		{"id":"pid","credential_type":"eu.europa.ec.eudi.pid.1","claims":["given_name"],"format":"dc+sd-jwt"},
		{"id":"padro_attestation","credential_type":"urn:fikua:padro:barcelona:1","claims":["resident_municipality"],"format":"dc+sd-jwt"}
	]}`
	resp, err := http.Post(srv+"/oid4vp/v1/session", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
}

func TestOid4vpRequestObjectServesJARContentType(t *testing.T) {
	srv := newTestServerWithVerifier(t).URL

	createResp, err := http.Post(srv+"/oid4vp/v1/session", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer createResp.Body.Close()
	var created map[string]string
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}

	resp, err := http.Get(srv + "/oid4vp/v1/request/" + created["session_id"])
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	wantContentType := "application/" + verifier.JARType
	if got := resp.Header.Get("Content-Type"); got != wantContentType {
		t.Errorf("Content-Type = %q, want %q", got, wantContentType)
	}
}

func TestOid4vpRequestObjectUnknownSessionIs404(t *testing.T) {
	srv := newTestServerWithVerifier(t).URL

	resp, err := http.Get(srv + "/oid4vp/v1/request/does-not-exist")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestOid4vpResponseRejectsMissingVPToken(t *testing.T) {
	srv := newTestServerWithVerifier(t).URL

	createResp, err := http.Post(srv+"/oid4vp/v1/session", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer createResp.Body.Close()
	var created map[string]string
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}

	form := url.Values{"state": {created["state"]}}
	resp, err := http.PostForm(srv+"/oid4vp/v1/response", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestOid4vpResultPendingBeforePresentation(t *testing.T) {
	srv := newTestServerWithVerifier(t).URL

	createResp, err := http.Post(srv+"/oid4vp/v1/session", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer createResp.Body.Close()
	var created map[string]string
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}

	resp, err := http.Get(srv + "/oid4vp/v1/result/" + created["session_id"])
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var result verifier.Result
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Status != verifier.StatusError || result.Error != "pending" {
		t.Fatalf("expected a pending status, got: %+v", result)
	}
}

func TestOid4vpResultUnknownSessionIs404(t *testing.T) {
	srv := newTestServerWithVerifier(t).URL

	resp, err := http.Get(srv + "/oid4vp/v1/result/does-not-exist")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}
