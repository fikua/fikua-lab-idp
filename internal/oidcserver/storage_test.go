package oidcserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	fikuacrypto "github.com/fikua/fikua-lab-idp/internal/crypto"
	"github.com/fikua/fikua-lab-idp/internal/oidcclients"
)

// testSigningKey is this package's own name for
// fikuacrypto.NewTestSigningKey, kept as a thin wrapper so every test
// file in this package (already written against "testSigningKey")
// didn't need a rename when the underlying constructor moved to
// internal/crypto to stop being duplicated per test package (see
// internal/crypto/testkeys.go's doc comment).
func testSigningKey(t *testing.T) *fikuacrypto.SigningKey {
	t.Helper()
	return fikuacrypto.NewTestSigningKey(t)
}

func testRegistry(t *testing.T) *oidcclients.Registry {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "clients.yaml")
	content := `
clients:
  - client_id: decidim-barcelona
    token_endpoint_auth_method: none
    redirect_uris:
      - "https://decidim.example.org/callback"
    scope: "openid"

credential_scopes:
  - name: padro_barcelona
    credential_type: "urn:fikua:padro:barcelona:1"
    claims: []
  - name: padro_girona
    credential_type: "urn:fikua:padro:girona:1"
    claims: []
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing test registry: %v", err)
	}
	reg, err := oidcclients.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return reg
}

// TestDiscoveryAndAuthorizeRedirectToLogin exercises this bridge's
// op.Storage wiring against real op HTTP handlers (via op.NewProvider,
// the same construction cmd/idp/main.go uses) end to end for the two
// steps that need no OID4VP Verifier at all: discovery (proves
// SigningKey/KeySet/client registration are wired correctly) and the
// start of /authorize (proves CreateAuthRequest + mandatory-PKCE
// enforcement + the LoginURL redirect this bridge depends on for its
// QR/poll page to ever be reached).
func TestDiscoveryAndAuthorizeRedirectToLogin(t *testing.T) {
	registry := testRegistry(t)
	signingKey := testSigningKey(t)
	storage := NewStorage(registry, signingKey, "http://as.example.org"+LoginPath)

	var cryptoKey [32]byte
	provider, err := op.NewProvider(
		&op.Config{CryptoKey: cryptoKey, CodeMethodS256: true},
		storage,
		op.StaticIssuer("http://as.example.org"+BasePath),
		op.WithAllowInsecure(),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	srv := httptest.NewServer(http.StripPrefix(BasePath, provider))
	defer srv.Close()

	// Discovery must advertise this AS's own endpoints and succeed —
	// proves Storage.KeySet/SigningKey and the provider's own config are
	// wired correctly, with no dependency on the Verifier. Requested at
	// BasePath+"/.well-known/..." (not the bare path) because this
	// mirrors cmd/idp/main.go's actual mount — http.StripPrefix(BasePath,
	// provider) — under which an external caller always includes
	// BasePath; RFC 8414/OIDC Discovery 1.0 requires exactly this shape
	// for an issuer whose identifier itself has a path component
	// (BasePath here).
	resp, err := http.Get(srv.URL + BasePath + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status = %d, want 200", resp.StatusCode)
	}
	var disc oidc.DiscoveryConfiguration
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		t.Fatalf("decoding discovery document: %v", err)
	}
	if disc.Issuer != "http://as.example.org"+BasePath {
		t.Errorf("issuer = %q", disc.Issuer)
	}

	// A well-formed /authorize request for the registered client, WITH
	// PKCE, must redirect toward this bridge's own login page (not fail,
	// not silently skip PKCE).
	authorizeURL := srv.URL + BasePath + "/authorize?" +
		"client_id=decidim-barcelona&response_type=code&scope=openid&" +
		"redirect_uri=" + "https%3A%2F%2Fdecidim.example.org%2Fcallback" +
		"&state=xyz&code_challenge=abc123&code_challenge_method=S256"

	noRedirectClient := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	authResp, err := noRedirectClient.Get(authorizeURL)
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302 (redirect to login)", authResp.StatusCode)
	}
	location := authResp.Header.Get("Location")
	if !strings.Contains(location, LoginPath) {
		t.Errorf("authorize redirected to %q, want it to contain %q", location, LoginPath)
	}

	// A request missing code_challenge must be rejected — PKCE is
	// mandatory, not merely validated when present (see
	// authRequest.codeChallenge's doc comment).
	noPKCEURL := srv.URL + BasePath + "/authorize?" +
		"client_id=decidim-barcelona&response_type=code&scope=openid&" +
		"redirect_uri=https%3A%2F%2Fdecidim.example.org%2Fcallback&state=xyz"
	noPKCEResp, err := noRedirectClient.Get(noPKCEURL)
	if err != nil {
		t.Fatalf("GET authorize (no PKCE): %v", err)
	}
	defer noPKCEResp.Body.Close()
	// op reports auth-request validation errors as a redirect back to
	// redirect_uri carrying error=... (RFC 6749 §4.1.2.1), not a raw
	// 4xx — assert on that redirect's query rather than the status code.
	noPKCELocation := noPKCEResp.Header.Get("Location")
	if !strings.Contains(noPKCELocation, "error=") {
		t.Errorf("authorize without code_challenge should redirect with an error, got status=%d location=%q", noPKCEResp.StatusCode, noPKCELocation)
	}
}
