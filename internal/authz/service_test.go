package authz

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"

	fikuacrypto "github.com/fikua/fikua-lab-idp/internal/crypto"
	"github.com/fikua/fikua-lab-idp/internal/issuerclient"
	"github.com/fikua/fikua-lab-idp/internal/oauth2"
	"github.com/fikua/fikua-lab-idp/internal/session"
)

const testBaseURL = "https://idp.fikua.test"

// stubIssuer is a minimal in-memory stand-in for the Credential Issuer's
// issuance API, exercised through a real httptest.Server (issuerclient.Client
// only ever speaks HTTP, so this is the cheapest way to drive it without
// touching production code).
type stubIssuer struct {
	mu      sync.Mutex
	records map[string]issuerclient.Record
	nextID  int
}

func newStubIssuer() *stubIssuer {
	return &stubIssuer{records: make(map[string]issuerclient.Record)}
}

// newStubIssuerServer starts an httptest.Server implementing the two
// issuerclient.Client endpoints Service depends on: FindByIssuerState (GET
// by-issuer-state/{state}) and Create (POST /oid4vci/v1/issuance). The
// issuer_state -> record binding is set up via issuerState so tests can
// exercise HandleAuthorize's fast path.
func newStubIssuerServer(t *testing.T, issuerStateToRecord map[string]string) *httptest.Server {
	t.Helper()
	stub := newStubIssuer()
	for state, recordID := range issuerStateToRecord {
		stub.records[state] = issuerclient.Record{ID: recordID}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /oid4vci/v1/issuance/by-issuer-state/", func(w http.ResponseWriter, r *http.Request) {
		state, err := url.PathUnescape(r.URL.Path[len("/oid4vci/v1/issuance/by-issuer-state/"):])
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		stub.mu.Lock()
		rec, ok := stub.records[state]
		stub.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSONStub(w, rec)
	})
	mux.HandleFunc("POST /oid4vci/v1/issuance", func(w http.ResponseWriter, r *http.Request) {
		var req issuerclient.CreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		stub.mu.Lock()
		stub.nextID++
		id := "issuance-" + strconv.Itoa(stub.nextID)
		stub.records[id] = issuerclient.Record{ID: id}
		stub.mu.Unlock()
		writeJSONStub(w, map[string]string{"issuance_id": id})
	})
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func writeJSONStub(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// newTestSigningKey builds a fikuacrypto.SigningKey via the same PEM file
// round trip LoadFromPEM uses in production — SigningKey has no in-memory
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

// newTestService wires a Service against a stub Credential Issuer with no
// pre-seeded issuer_state records and no Wallet Provider trust pinning
// (accepts any self-consistent client attestation).
func newTestService(t *testing.T) (*Service, *httptest.Server) {
	t.Helper()
	return newTestServiceWithRecords(t, nil)
}

func newTestServiceWithRecords(t *testing.T, issuerStateToRecord map[string]string) (*Service, *httptest.Server) {
	t.Helper()
	issuerSrv := newStubIssuerServer(t, issuerStateToRecord)
	sessions := session.NewStore()
	issuer := issuerclient.New(issuerSrv.URL)
	minter := oauth2.NewMinter(newTestSigningKey(t), testBaseURL, "https://issuer.fikua.test")
	svc := NewService(testBaseURL, sessions, issuer, minter, nil)
	return svc, issuerSrv
}

// testClient bundles a wallet's client-attestation key material (WIA +
// cnf key) and its DPoP key, everything HandlePar/HandleAuthCodeToken
// authenticate a request by.
type testClient struct {
	clientID string
	wia      string
	pop      func(t *testing.T) string // PoP is minted fresh per call since iat matters
	dpopKey  *ecdsa.PrivateKey
}

func newTestClient(t *testing.T, clientID string) testClient {
	t.Helper()
	walletKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating wallet key: %v", err)
	}
	cnfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating cnf key: %v", err)
	}
	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating DPoP key: %v", err)
	}

	cnfPub, err := jwk.PublicKeyOf(cnfKey)
	if err != nil {
		t.Fatalf("building cnf public JWK: %v", err)
	}
	walletPub, err := jwk.PublicKeyOf(walletKey)
	if err != nil {
		t.Fatalf("building wallet public JWK: %v", err)
	}

	wiaTok, err := jwt.NewBuilder().
		Subject(clientID).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Claim("cnf", map[string]any{"jwk": cnfPub}).
		Build()
	if err != nil {
		t.Fatalf("building WIA claims: %v", err)
	}
	wiaHeaders := jws.NewHeaders()
	_ = wiaHeaders.Set(jws.JWKKey, walletPub)
	wiaSigned, err := jwt.Sign(wiaTok, jwt.WithKey(jwa.ES256(), walletKey, jws.WithProtectedHeaders(wiaHeaders)))
	if err != nil {
		t.Fatalf("signing WIA: %v", err)
	}

	return testClient{
		clientID: clientID,
		wia:      string(wiaSigned),
		dpopKey:  dpopKey,
		pop: func(t *testing.T) string {
			t.Helper()
			cnfPub, _ := jwk.PublicKeyOf(cnfKey)
			popTok, err := jwt.NewBuilder().
				Audience([]string{testBaseURL}).
				IssuedAt(time.Now()).
				Expiration(time.Now().Add(time.Hour)).
				JwtID(oauth2.RandomJTI()).
				Build()
			if err != nil {
				t.Fatalf("building PoP claims: %v", err)
			}
			popHeaders := jws.NewHeaders()
			_ = popHeaders.Set(jws.JWKKey, cnfPub)
			popSigned, err := jwt.Sign(popTok, jwt.WithKey(jwa.ES256(), cnfKey, jws.WithProtectedHeaders(popHeaders)))
			if err != nil {
				t.Fatalf("signing PoP: %v", err)
			}
			return string(popSigned)
		},
	}
}

// dpopProof mints a fresh DPoP proof for htm/htu, signed by c's DPoP key.
func (c testClient) dpopProof(t *testing.T, htm, htu string) string {
	t.Helper()
	pub, err := jwk.PublicKeyOf(c.dpopKey)
	if err != nil {
		t.Fatalf("building DPoP public JWK: %v", err)
	}
	tok, err := jwt.NewBuilder().
		Claim("htm", htm).
		Claim("htu", htu).
		JwtID(oauth2.RandomJTI()).
		IssuedAt(time.Now()).
		Build()
	if err != nil {
		t.Fatalf("building DPoP claims: %v", err)
	}
	headers := jws.NewHeaders()
	_ = headers.Set(jws.TypeKey, "dpop+jwt")
	_ = headers.Set(jws.JWKKey, pub)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), c.dpopKey, jws.WithProtectedHeaders(headers)))
	if err != nil {
		t.Fatalf("signing DPoP proof: %v", err)
	}
	return string(signed)
}

// testPKCEVerifier is a fixed code_verifier used by every PAR-only test
// that doesn't itself drive a full flow to /token (where PKCE actually
// gets checked) — its value only matters for those that do.
const testPKCEVerifier = "verifier-1234567890123456789012345678901234567890123"

func validPARParams() map[string]string {
	return map[string]string{
		"response_type":         "code",
		"client_id":             "client-1",
		"redirect_uri":          "https://wallet.example.com/callback",
		"code_challenge":        computeChallenge(testPKCEVerifier),
		"code_challenge_method": "S256",
		"state":                 "xyz",
	}
}

// computeChallenge computes the RFC 7636 S256 code_challenge for verifier,
// mirroring oauth2's own unexported computeS256Challenge so tests can mint
// a matching code_verifier/code_challenge pair without reaching into the
// oauth2 package's internals.
func computeChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func TestHandleParHappyPath(t *testing.T) {
	svc, _ := newTestService(t)
	client := newTestClient(t, "client-1")

	params := validPARParams()
	requestURI, expiresIn, err := svc.HandlePar(params, client.wia, client.pop(t), "")
	if err != nil {
		t.Fatalf("HandlePar: %v", err)
	}
	if requestURI == "" {
		t.Fatal("expected a non-empty request_uri")
	}
	if expiresIn != 60 {
		t.Errorf("expiresIn = %d, want 60", expiresIn)
	}
}

func TestHandleParMissingAttestation(t *testing.T) {
	svc, _ := newTestService(t)
	params := validPARParams()

	if _, _, err := svc.HandlePar(params, "", "", ""); err == nil {
		t.Fatal("expected missing client attestation to be rejected")
	}
}

func TestHandleParMissingPKCE(t *testing.T) {
	svc, _ := newTestService(t)
	client := newTestClient(t, "client-1")
	params := validPARParams()
	delete(params, "code_challenge")

	if _, _, err := svc.HandlePar(params, client.wia, client.pop(t), ""); err == nil {
		t.Fatal("expected a missing code_challenge to be rejected")
	}
}

func TestHandleParNonS256Method(t *testing.T) {
	svc, _ := newTestService(t)
	client := newTestClient(t, "client-1")
	params := validPARParams()
	params["code_challenge_method"] = "plain"

	if _, _, err := svc.HandlePar(params, client.wia, client.pop(t), ""); err == nil {
		t.Fatal("expected a non-S256 code_challenge_method to be rejected")
	}
}

func TestHandleParDPoPJKTMismatch(t *testing.T) {
	svc, _ := newTestService(t)
	client := newTestClient(t, "client-1")
	params := validPARParams()
	params["dpop_jkt"] = "some-unrelated-thumbprint"
	proof := client.dpopProof(t, "POST", testBaseURL+"/oid4vci/v1/par")

	if _, _, err := svc.HandlePar(params, client.wia, client.pop(t), proof); err == nil {
		t.Fatal("expected a dpop_jkt not matching the DPoP proof's key to be rejected")
	}
}

func TestHandleParRejectsRequestURI(t *testing.T) {
	svc, _ := newTestService(t)
	client := newTestClient(t, "client-1")
	params := validPARParams()
	params["request_uri"] = "urn:ietf:params:oauth:request_uri:abc"

	if _, _, err := svc.HandlePar(params, client.wia, client.pop(t), ""); err == nil {
		t.Fatal("expected a PAR request carrying request_uri to be rejected")
	}
}

func TestHandleAuthorizeInvalidRequestURI(t *testing.T) {
	svc, _ := newTestService(t)
	if _, err := svc.HandleAuthorize(t.Context(), "urn:ietf:params:oauth:request_uri:does-not-exist", "", ""); err == nil {
		t.Fatal("expected an unknown request_uri to be rejected")
	}
}

func TestHandleAuthorizeMissingRequestURI(t *testing.T) {
	svc, _ := newTestService(t)
	if _, err := svc.HandleAuthorize(t.Context(), "", "", ""); err == nil {
		t.Fatal("expected a missing request_uri to be rejected")
	}
}

func TestHandleAuthorizeFirstVisitDefersToIdentification(t *testing.T) {
	svc, _ := newTestService(t)
	client := newTestClient(t, "client-1")
	params := validPARParams()
	requestURI, _, err := svc.HandlePar(params, client.wia, client.pop(t), "")
	if err != nil {
		t.Fatalf("HandlePar: %v", err)
	}

	result, err := svc.HandleAuthorize(t.Context(), requestURI, "", "")
	if err != nil {
		t.Fatalf("HandleAuthorize: %v", err)
	}
	if result.IdentifyRedirect == "" {
		t.Fatal("expected the first visit to defer to identification")
	}
	if result.Code != "" {
		t.Fatal("expected no authorization code to be minted on a first visit")
	}

	// The request_uri must still be usable — a first visit is
	// non-destructive (see HandleAuthorize's doc comment).
	result2, err := svc.HandleAuthorize(t.Context(), requestURI, "", "")
	if err != nil {
		t.Fatalf("second HandleAuthorize call: %v", err)
	}
	if result2.IdentifyRedirect == "" {
		t.Fatal("expected request_uri to still be usable after a first, unidentified visit")
	}
}

func TestHandleAuthorizeSecondVisitWithIdentifiedCookieMintsCode(t *testing.T) {
	svc, _ := newTestService(t)
	client := newTestClient(t, "client-1")
	params := validPARParams()
	requestURI, _, err := svc.HandlePar(params, client.wia, client.pop(t), "")
	if err != nil {
		t.Fatalf("HandlePar: %v", err)
	}

	first, err := svc.HandleAuthorize(t.Context(), requestURI, "", "")
	if err != nil {
		t.Fatalf("first HandleAuthorize: %v", err)
	}
	if first.IdentifyRedirect == "" {
		t.Fatal("expected the first visit to defer to identification")
	}

	sessionToken := extractSessionToken(t, first.IdentifyRedirect)
	redirect, cookieValue, err := svc.CompleteIdentification(t.Context(), sessionToken, map[string]any{"given_name": "Ada"}, "manual", "")
	if err != nil {
		t.Fatalf("CompleteIdentification: %v", err)
	}
	if cookieValue == "" {
		t.Fatal("expected a fresh identified cookie to be minted")
	}
	if redirect == "" {
		t.Fatal("expected a redirect back to /authorize")
	}

	second, err := svc.HandleAuthorize(t.Context(), requestURI, "", cookieValue)
	if err != nil {
		t.Fatalf("second HandleAuthorize: %v", err)
	}
	if second.Code == "" {
		t.Fatal("expected the second, identified visit to mint an authorization code")
	}
	if second.RedirectURI != params["redirect_uri"] {
		t.Errorf("RedirectURI = %q, want %q", second.RedirectURI, params["redirect_uri"])
	}
}

func TestHandleAuthorizeIssuerStateFastPath(t *testing.T) {
	svc, _ := newTestServiceWithRecords(t, map[string]string{"issuer-state-1": "record-42"})
	client := newTestClient(t, "client-1")
	params := validPARParams()
	params["issuer_state"] = "issuer-state-1"
	requestURI, _, err := svc.HandlePar(params, client.wia, client.pop(t), "")
	if err != nil {
		t.Fatalf("HandlePar: %v", err)
	}

	result, err := svc.HandleAuthorize(t.Context(), requestURI, "", "")
	if err != nil {
		t.Fatalf("HandleAuthorize: %v", err)
	}
	if result.Code == "" {
		t.Fatal("expected the issuer_state fast path to mint a code on the first visit")
	}
	if result.IdentifyRedirect != "" {
		t.Fatal("expected the issuer_state fast path to skip identification entirely")
	}
}

// extractSessionToken pulls the "?session=" query value CompleteIdentification's
// counterpart, HandleAuthorize's identify-redirect, appends — see
// Service.HandleAuthorize's IdentifyRedirect field.
func extractSessionToken(t *testing.T, identifyRedirect string) string {
	t.Helper()
	u, err := url.Parse(identifyRedirect)
	if err != nil {
		t.Fatalf("parsing identify redirect: %v", err)
	}
	token := u.Query().Get("session")
	if token == "" {
		t.Fatalf("no session token in identify redirect: %s", identifyRedirect)
	}
	return token
}

// fullAuthorizationFlow drives a client through PAR -> deferred
// identification -> completed identification -> second /authorize visit,
// returning the resulting authorization code and the PKCE verifier that
// must accompany it at /token.
func fullAuthorizationFlow(t *testing.T, svc *Service, client testClient) (code, verifier string) {
	t.Helper()
	verifier = "verifier-1234567890123456789012345678901234567890123"
	params := validPARParams()
	params["code_challenge"] = computeChallenge(verifier)
	requestURI, _, err := svc.HandlePar(params, client.wia, client.pop(t), "")
	if err != nil {
		t.Fatalf("HandlePar: %v", err)
	}

	first, err := svc.HandleAuthorize(t.Context(), requestURI, "", "")
	if err != nil {
		t.Fatalf("first HandleAuthorize: %v", err)
	}
	sessionToken := extractSessionToken(t, first.IdentifyRedirect)

	_, cookieValue, err := svc.CompleteIdentification(t.Context(), sessionToken, map[string]any{"given_name": "Ada"}, "manual", "")
	if err != nil {
		t.Fatalf("CompleteIdentification: %v", err)
	}

	second, err := svc.HandleAuthorize(t.Context(), requestURI, "", cookieValue)
	if err != nil {
		t.Fatalf("second HandleAuthorize: %v", err)
	}
	return second.Code, verifier
}

func TestHandleAuthCodeTokenHappyPathEndToEnd(t *testing.T) {
	svc, _ := newTestService(t)
	client := newTestClient(t, "client-1")
	code, verifier := fullAuthorizationFlow(t, svc, client)

	req := oauth2.TokenRequest{
		GrantType:    oauth2.AuthorizationCodeGrantType,
		Code:         code,
		CodeVerifier: verifier,
	}
	dpopProof := client.dpopProof(t, "POST", testBaseURL+"/oid4vci/v1/token")

	resp, err := svc.HandleAuthCodeToken(req, dpopProof, client.wia, client.pop(t))
	if err != nil {
		t.Fatalf("HandleAuthCodeToken: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("expected a non-empty access token")
	}
	if resp.TokenType != "DPoP" {
		t.Errorf("TokenType = %q, want DPoP", resp.TokenType)
	}
}

func TestHandleAuthCodeTokenPKCEMismatch(t *testing.T) {
	svc, _ := newTestService(t)
	client := newTestClient(t, "client-1")
	code, _ := fullAuthorizationFlow(t, svc, client)

	req := oauth2.TokenRequest{
		GrantType:    oauth2.AuthorizationCodeGrantType,
		Code:         code,
		CodeVerifier: "wrong-verifier-1234567890123456789012345678901234",
	}
	dpopProof := client.dpopProof(t, "POST", testBaseURL+"/oid4vci/v1/token")

	if _, err := svc.HandleAuthCodeToken(req, dpopProof, client.wia, client.pop(t)); err == nil {
		t.Fatal("expected a PKCE verifier mismatch to be rejected")
	}
}

func TestHandleAuthCodeTokenCodeReuse(t *testing.T) {
	svc, _ := newTestService(t)
	client := newTestClient(t, "client-1")
	code, verifier := fullAuthorizationFlow(t, svc, client)

	req := oauth2.TokenRequest{
		GrantType:    oauth2.AuthorizationCodeGrantType,
		Code:         code,
		CodeVerifier: verifier,
	}
	dpopProof1 := client.dpopProof(t, "POST", testBaseURL+"/oid4vci/v1/token")
	if _, err := svc.HandleAuthCodeToken(req, dpopProof1, client.wia, client.pop(t)); err != nil {
		t.Fatalf("first HandleAuthCodeToken: %v", err)
	}

	dpopProof2 := client.dpopProof(t, "POST", testBaseURL+"/oid4vci/v1/token")
	if _, err := svc.HandleAuthCodeToken(req, dpopProof2, client.wia, client.pop(t)); err == nil {
		t.Fatal("expected a reused authorization code to be rejected")
	}

	revoked := svc.RevokedJTIs()
	if len(revoked) == 0 {
		t.Fatal("expected the token minted from the reused code to be revoked")
	}
}

func TestHandleAuthCodeTokenClientBindingMismatch(t *testing.T) {
	svc, _ := newTestService(t)
	client := newTestClient(t, "client-1")
	code, verifier := fullAuthorizationFlow(t, svc, client)

	otherClient := newTestClient(t, "client-2")
	req := oauth2.TokenRequest{
		GrantType:    oauth2.AuthorizationCodeGrantType,
		Code:         code,
		CodeVerifier: verifier,
	}
	dpopProof := otherClient.dpopProof(t, "POST", testBaseURL+"/oid4vci/v1/token")

	if _, err := svc.HandleAuthCodeToken(req, dpopProof, otherClient.wia, otherClient.pop(t)); err == nil {
		t.Fatal("expected a code presented by a different client to be rejected")
	}
}

func TestRejectIdentification(t *testing.T) {
	svc, _ := newTestService(t)
	client := newTestClient(t, "client-1")
	params := validPARParams()
	requestURI, _, err := svc.HandlePar(params, client.wia, client.pop(t), "")
	if err != nil {
		t.Fatalf("HandlePar: %v", err)
	}

	first, err := svc.HandleAuthorize(t.Context(), requestURI, "", "")
	if err != nil {
		t.Fatalf("HandleAuthorize: %v", err)
	}
	sessionToken := extractSessionToken(t, first.IdentifyRedirect)

	redirect, err := svc.RejectIdentification(sessionToken)
	if err != nil {
		t.Fatalf("RejectIdentification: %v", err)
	}
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatalf("parsing reject redirect: %v", err)
	}
	if got := u.Query().Get("error"); got != "access_denied" {
		t.Errorf("error = %q, want access_denied", got)
	}
}
