package oidcclients

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTestRegistry(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "clients.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing test registry: %v", err)
	}
	return path
}

func TestLoadValidRegistry(t *testing.T) {
	path := writeTestRegistry(t, `
clients:
  - client_id: decidim-barcelona
    token_endpoint_auth_method: none
    redirect_uris:
      - "https://decidim.fikua.com/users/auth/fikua_verifier/callback"
    scope: "openid"
    verifier_credential_type: "urn:fikua:padro:barcelona:1"
    verifier_claims: []
`)
	reg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	c, ok := reg.Lookup("decidim-barcelona")
	if !ok {
		t.Fatal("expected decidim-barcelona to be registered")
	}
	if c.VerifierCredentialType != "urn:fikua:padro:barcelona:1" {
		t.Errorf("VerifierCredentialType = %q", c.VerifierCredentialType)
	}
	if len(c.VerifierClaims) != 0 {
		t.Errorf("VerifierClaims = %v, want empty (zero-knowledge)", c.VerifierClaims)
	}
	if _, ok := reg.Lookup("unknown-client"); ok {
		t.Error("Lookup should not find an unregistered client")
	}
}

func TestLoadRejectsConfidentialAuthMethod(t *testing.T) {
	path := writeTestRegistry(t, `
clients:
  - client_id: bad-client
    token_endpoint_auth_method: client_secret_basic
    redirect_uris: ["https://example.com/callback"]
    scope: "openid"
    verifier_credential_type: "urn:fikua:padro:barcelona:1"
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected Load to reject a non-\"none\" token_endpoint_auth_method")
	}
}

func TestLoadRejectsMissingOpenIDScope(t *testing.T) {
	path := writeTestRegistry(t, `
clients:
  - client_id: bad-client
    token_endpoint_auth_method: none
    redirect_uris: ["https://example.com/callback"]
    scope: "profile"
    verifier_credential_type: "urn:fikua:padro:barcelona:1"
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected Load to reject a scope missing \"openid\"")
	}
}

func TestLoadRejectsDuplicateClientID(t *testing.T) {
	path := writeTestRegistry(t, `
clients:
  - client_id: dup
    token_endpoint_auth_method: none
    redirect_uris: ["https://example.com/a"]
    scope: "openid"
    verifier_credential_type: "urn:fikua:padro:barcelona:1"
  - client_id: dup
    token_endpoint_auth_method: none
    redirect_uris: ["https://example.com/b"]
    scope: "openid"
    verifier_credential_type: "urn:fikua:padro:barcelona:1"
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected Load to reject a duplicate client_id")
	}
}
