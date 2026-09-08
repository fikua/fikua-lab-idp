package oidcserver

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/op"

	fikuacrypto "github.com/fikua/fikua-lab-idp/internal/crypto"
	"github.com/fikua/fikua-lab-idp/internal/session"
	"github.com/fikua/fikua-lab-idp/internal/verifier"
)

// oidcS256Challenge computes an RFC 7636 §4.2 S256 code_challenge from a
// code_verifier: base64url(SHA-256(verifier)), no padding.
func oidcS256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// newTestVerifierService builds a real verifier.Service (not a mock) —
// exercising the actual CreateSession/Session code paths this bridge
// depends on — backed by a throwaway self-signed request-signing key and
// the given session.Store, so a test can later inject a verified result
// into that same store without needing a real wallet.
func newTestVerifierService(t *testing.T, sessions *session.Store) *verifier.Service {
	t.Helper()
	signingKey := fikuacrypto.NewTestRequestSigningKey(t)
	return verifier.NewService("https://verifier.test.fikua.internal", signingKey, sessions, verifier.ResponseModeDirectPost)
}

// testBridge bundles a full oidcserver.Server (op.Provider + LoginHandler)
// wired the same way cmd/idp/main.go wires it, plus the pieces a test
// needs to inject a verification result and observe the sessions
// login.go started.
type testBridge struct {
	srv      *httptest.Server
	sessions *session.Store
	storage  *Storage
}

func newTestBridge(t *testing.T) *testBridge {
	t.Helper()
	registry := testRegistry(t)
	signingKey := testSigningKey(t)
	sessions := session.NewStore()
	verifierService := newTestVerifierService(t, sessions)

	// The issuer (and so LoginURL/AuthCallbackURL) must be the test
	// server's own real origin — op.AuthCallbackURL builds an absolute
	// URL from it, and a placeholder host would produce a redirect this
	// test's http.Client cannot follow. NewUnstartedServer gives out its
	// listener address before the handler exists, so the issuer-dependent
	// pieces (Storage, Provider, LoginHandler) can be built first and
	// wired into the mux before Start().
	lis := httptest.NewUnstartedServer(nil)
	baseURL := "http://" + lis.Listener.Addr().String()

	storage := NewStorage(registry, signingKey, baseURL+LoginPath)
	var cryptoKey [32]byte
	provider, err := op.NewProvider(
		&op.Config{CryptoKey: cryptoKey, CodeMethodS256: true, GrantTypeRefreshToken: true, SupportedScopes: []string{"openid", "offline_access"}},
		storage,
		op.StaticIssuer(baseURL+BasePath),
		op.WithAllowInsecure(),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	login := NewLoginHandler(storage, registry, verifierService, op.AuthCallbackURL(provider), baseURL+BasePath)

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+LoginPath, login.ServeHTTP)
	mux.HandleFunc("GET "+LoginPath+"/poll", login.PollHandler)
	mux.Handle(BasePath+"/", http.StripPrefix(BasePath, provider))
	lis.Config.Handler = mux
	lis.Start()
	t.Cleanup(lis.Close)

	return &testBridge{srv: lis, sessions: sessions, storage: storage}
}

func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// startAuthorize drives a real PKCE-bearing /authorize request through to
// the login redirect and returns the authRequest id the query carries,
// plus the code_verifier the eventual /token call needs.
func startAuthorize(t *testing.T, b *testBridge) (authRequestID, codeVerifier string) {
	t.Helper()
	return startAuthorizeWithScope(t, b, "openid offline_access padro_barcelona")
}

// startAuthorizeWithScope is startAuthorize with an explicit scope — for
// tests exercising OpenID4VP 1.0 §5.5's model directly: the SAME
// registered client selecting a DIFFERENT credential per login purely by
// varying its own scope, with no separate client registration per
// credential (see TestSameClientDifferentCredentialScopePerLogin).
func startAuthorizeWithScope(t *testing.T, b *testBridge, scope string) (authRequestID, codeVerifier string) {
	t.Helper()
	codeVerifier = "test-code-verifier-0123456789-abcdefghijklmno"
	challenge := oidcS256Challenge(codeVerifier)

	authorizeURL := b.srv.URL + BasePath + "/authorize?" + url.Values{
		"client_id":             {"decidim-barcelona"},
		"response_type":         {"code"},
		"scope":                 {scope},
		"redirect_uri":          {"https://decidim.example.org/callback"},
		"state":                 {"xyz"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp, err := noRedirectClient().Get(authorizeURL)
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("authorize status = %d, want 302; body=%s", resp.StatusCode, body)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parsing Location: %v", err)
	}
	authRequestID = loc.Query().Get("id")
	if authRequestID == "" {
		t.Fatalf("login redirect %q carries no id", loc.String())
	}
	return authRequestID, codeVerifier
}

// TestLoginPageStartsVerificationSession exercises LoginHandler.ServeHTTP
// against a real verifier.Service: the first page load must start an
// OID4VP session, and a second load for the same AuthRequest must reuse
// it rather than starting a second one (see verificationSessionFor's doc
// comment).
func TestLoginPageStartsVerificationSession(t *testing.T) {
	b := newTestBridge(t)
	authRequestID, _ := startAuthorize(t, b)

	resp1, err := http.Get(b.srv.URL + LoginPath + "?id=" + authRequestID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first login page load: status = %d", resp1.StatusCode)
	}

	sessID1, ok := b.storageFor(t).internalStore().getVerificationSession(authRequestID)
	if !ok {
		t.Fatal("expected a verification session to be linked after first load")
	}

	resp2, err := http.Get(b.srv.URL + LoginPath + "?id=" + authRequestID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("second login page load: status = %d", resp2.StatusCode)
	}
	sessID2, _ := b.storageFor(t).internalStore().getVerificationSession(authRequestID)
	if sessID1 != sessID2 {
		t.Errorf("a second page load must not start a second verification session: %q != %q", sessID1, sessID2)
	}
}

// TestSameClientDifferentCredentialScopePerLogin is the direct
// demonstration of OpenID4VP 1.0 §5.5's model this bridge implements:
// ONE registered client_id (decidim-barcelona in testRegistry, standing
// in for a single Decidim installation) requests a DIFFERENT credential
// per login purely by naming a different scope — no separate client
// registration, and nothing about the client's own oidcclients.Client
// entry changes between the two logins. This is what makes a single
// Relying Party able to ask for a Barcelona padró for one participatory
// process and a Girona padró for another, entirely by what its own
// /authorize call sends.
func TestSameClientDifferentCredentialScopePerLogin(t *testing.T) {
	b := newTestBridge(t)

	barcelonaAuthReqID, _ := startAuthorizeWithScope(t, b, "openid padro_barcelona")
	if resp, err := http.Get(b.srv.URL + LoginPath + "?id=" + barcelonaAuthReqID); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
	}
	barcelonaSessID, ok := b.storage.internalStore().getVerificationSession(barcelonaAuthReqID)
	if !ok {
		t.Fatal("expected a verification session for the Barcelona login")
	}
	barcelonaSession, _ := b.sessions.FindVerification(barcelonaSessID)
	if got := barcelonaSession.DCQLQuery.Credentials[0].Meta.VCTValues[0]; got != "urn:fikua:padro:barcelona:1" {
		t.Errorf("Barcelona login requested credential type %q", got)
	}

	gironaAuthReqID, _ := startAuthorizeWithScope(t, b, "openid padro_girona")
	if resp, err := http.Get(b.srv.URL + LoginPath + "?id=" + gironaAuthReqID); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
	}
	gironaSessID, ok := b.storage.internalStore().getVerificationSession(gironaAuthReqID)
	if !ok {
		t.Fatal("expected a verification session for the Girona login")
	}
	gironaSession, _ := b.sessions.FindVerification(gironaSessID)
	if got := gironaSession.DCQLQuery.Credentials[0].Meta.VCTValues[0]; got != "urn:fikua:padro:girona:1" {
		t.Errorf("Girona login requested credential type %q", got)
	}

	if barcelonaSessID == gironaSessID {
		t.Error("the two logins must not share a verification session")
	}
}

// TestLoginRejectsUnknownScope covers the case a login's scope names no
// registered credential at all — must fail rather than silently
// proceeding with no credential requested.
func TestLoginRejectsUnknownScope(t *testing.T) {
	b := newTestBridge(t)
	authRequestID, _ := startAuthorizeWithScope(t, b, "openid")

	resp, err := http.Get(b.srv.URL + LoginPath + "?id=" + authRequestID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (no credential scope requested)", resp.StatusCode)
	}
}

// TestFullLoginToTokenFlow drives the whole bridge end to end: /authorize
// (PKCE) -> login page (real OID4VP session creation) -> a simulated
// wallet presentation (injected directly into session.Store, the same
// state verifier.Service.HandleResponse would produce) -> poll (which
// must complete the AuthRequest and redirect to op's callback) ->
// AuthorizeCallback (mints the code) -> /token (authorization_code grant
// with PKCE, requesting offline_access) -> a working refresh_token grant.
// This is the one test that exercises Storage's token-minting methods,
// the refresh token path, and the JWKS/SigningKey wiring together.
func TestFullLoginToTokenFlow(t *testing.T) {
	b := newTestBridge(t)
	authRequestID, codeVerifier := startAuthorize(t, b)

	// First load starts the verification session — same as
	// TestLoginPageStartsVerificationSession, just as a means to an end
	// here.
	loginResp, err := http.Get(b.srv.URL + LoginPath + "?id=" + authRequestID)
	if err != nil {
		t.Fatal(err)
	}
	loginResp.Body.Close()

	sessID, ok := b.storageFor(t).internalStore().getVerificationSession(authRequestID)
	if !ok {
		t.Fatal("expected a verification session to exist")
	}

	// Simulate a wallet having presented a valid credential: this is
	// exactly the state verifier.Service.HandleResponse leaves behind on
	// success (see its own UpdateVerificationResult call), reached here
	// without a real wallet round trip since that round trip is
	// internal/verifier's own test surface, not this bridge's.
	b.sessions.UpdateVerificationResult(sessID, "verified", map[string]string{"requested_credential": "vp-token"}, map[string]map[string]any{}, "subject-pseudonym-1", "")

	pollResp, err := http.Get(b.srv.URL + LoginPath + "/poll?id=" + authRequestID)
	if err != nil {
		t.Fatal(err)
	}
	defer pollResp.Body.Close()
	var pollBody struct {
		Status   string `json:"status"`
		Redirect string `json:"redirect"`
	}
	if err := json.NewDecoder(pollResp.Body).Decode(&pollBody); err != nil {
		t.Fatalf("decoding poll response: %v", err)
	}
	if pollBody.Status != "done" || pollBody.Redirect == "" {
		t.Fatalf("poll response = %+v, want status=done with a redirect", pollBody)
	}

	// Follow the poll's redirect (op.AuthorizeCallback) — this is where
	// op mints the actual authorization code and redirects on to the
	// Relying Party's own redirect_uri.
	callbackResp, err := noRedirectClient().Get(pollBody.Redirect)
	if err != nil {
		t.Fatal(err)
	}
	defer callbackResp.Body.Close()
	if callbackResp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(callbackResp.Body)
		t.Fatalf("callback status = %d, want 302; body=%s", callbackResp.StatusCode, body)
	}
	finalLoc, err := url.Parse(callbackResp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := finalLoc.Query().Get("code")
	if code == "" {
		t.Fatalf("callback redirected to %q with no code", finalLoc.String())
	}

	// Exchange the code at /token with PKCE — this is what actually
	// exercises CreateAuthRequest's stored code_challenge,
	// AuthRequestByCode, CreateAccessAndRefreshTokens (offline_access was
	// requested), SigningKey and KeySet (op signs the ID Token with
	// them).
	tokenResp, err := http.PostForm(b.srv.URL+BasePath+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://decidim.example.org/callback"},
		"client_id":     {"decidim-barcelona"},
		"code_verifier": {codeVerifier},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("token status = %d, want 200; body=%s", tokenResp.StatusCode, body)
	}
	var tokenBody struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenBody); err != nil {
		t.Fatalf("decoding token response: %v", err)
	}
	if tokenBody.AccessToken == "" || tokenBody.IDToken == "" {
		t.Fatalf("token response = %+v, want a non-empty access_token and id_token", tokenBody)
	}
	if tokenBody.RefreshToken == "" {
		t.Fatal("expected a refresh_token since offline_access was requested")
	}

	// The refresh_token grant must also work, minting a fresh access
	// token (and, per this bridge's rotation policy, a fresh refresh
	// token too — see Storage.CreateAccessAndRefreshTokens).
	refreshResp, err := http.PostForm(b.srv.URL+BasePath+"/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokenBody.RefreshToken},
		"client_id":     {"decidim-barcelona"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer refreshResp.Body.Close()
	if refreshResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(refreshResp.Body)
		t.Fatalf("refresh status = %d, want 200; body=%s", refreshResp.StatusCode, body)
	}
}

// storageFor exposes testBridge's internal *Storage for tests that need
// to inspect state (e.g. verification-session linking) beyond what the
// HTTP surface itself reveals.
func (b *testBridge) storageFor(t *testing.T) *Storage {
	t.Helper()
	return b.storage
}
