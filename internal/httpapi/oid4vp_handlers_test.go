package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	fikuacrypto "github.com/fikua/fikua-lab-idp/internal/crypto"
	"github.com/fikua/fikua-lab-idp/internal/httpapi"
	"github.com/fikua/fikua-lab-idp/internal/issuerclient"
	"github.com/fikua/fikua-lab-idp/internal/session"
	"github.com/fikua/fikua-lab-idp/internal/verifier"
)

// newTestServerWithVerifier is newTestServer's counterpart with a real
// OID4VP Verifier wired in (direct_post response mode — no JWE round
// trip needed to exercise the HTTP layer these tests cover).
func newTestServerWithVerifier(t *testing.T) *httptest.Server {
	t.Helper()
	issuerSrv := newStubIssuerServer(t, true)
	issuer := issuerclient.New(issuerSrv.URL)
	sessions := session.NewStore()
	signingKey := fikuacrypto.NewTestSigningKey(t)
	verifierService := verifier.NewService(testBaseURL, fikuacrypto.NewTestRequestSigningKey(t), sessions, verifier.ResponseModeDirectPost)

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
