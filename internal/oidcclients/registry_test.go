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

credential_scopes:
  - name: padro_barcelona
    credential_type: "urn:fikua:padro:barcelona:1"
    claims: []
`)
	reg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := reg.Lookup("decidim-barcelona"); !ok {
		t.Fatal("expected decidim-barcelona to be registered")
	}
	if _, ok := reg.Lookup("unknown-client"); ok {
		t.Error("Lookup should not find an unregistered client")
	}

	cs, ok := reg.ResolveCredentialScope([]string{"openid", "padro_barcelona"})
	if !ok {
		t.Fatal("expected padro_barcelona to resolve")
	}
	if cs.CredentialType != "urn:fikua:padro:barcelona:1" {
		t.Errorf("CredentialType = %q", cs.CredentialType)
	}
	if len(cs.Claims) != 0 {
		t.Errorf("Claims = %v, want empty (zero-knowledge)", cs.Claims)
	}

	if _, ok := reg.ResolveCredentialScope([]string{"openid"}); ok {
		t.Error("ResolveCredentialScope should not match a scope list with no registered credential scope")
	}
}

func TestResolveCredentialScopePicksFirstMatch(t *testing.T) {
	path := writeTestRegistry(t, `
clients:
  - client_id: multi-scope-client
    token_endpoint_auth_method: none
    redirect_uris: ["https://example.com/callback"]
    scope: "openid"

credential_scopes:
  - name: padro_barcelona
    credential_type: "urn:fikua:padro:barcelona:1"
    claims: []
  - name: padro_girona
    credential_type: "urn:fikua:padro:girona:1"
    claims: []
`)
	reg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cs, ok := reg.ResolveCredentialScope([]string{"openid", "padro_girona", "padro_barcelona"})
	if !ok {
		t.Fatal("expected a match")
	}
	if cs.Name != "padro_girona" {
		t.Errorf("resolved %q, want the first matching scope in request order (padro_girona)", cs.Name)
	}
}

func TestLoadRejectsConfidentialAuthMethod(t *testing.T) {
	path := writeTestRegistry(t, `
clients:
  - client_id: bad-client
    token_endpoint_auth_method: client_secret_basic
    redirect_uris: ["https://example.com/callback"]
    scope: "openid"
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
  - client_id: dup
    token_endpoint_auth_method: none
    redirect_uris: ["https://example.com/b"]
    scope: "openid"
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected Load to reject a duplicate client_id")
	}
}

func TestLoadRejectsDuplicateCredentialScopeName(t *testing.T) {
	path := writeTestRegistry(t, `
clients:
  - client_id: some-client
    token_endpoint_auth_method: none
    redirect_uris: ["https://example.com/a"]
    scope: "openid"

credential_scopes:
  - name: padro_barcelona
    credential_type: "urn:fikua:padro:barcelona:1"
    claims: []
  - name: padro_barcelona
    credential_type: "urn:fikua:padro:barcelona:2"
    claims: []
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected Load to reject a duplicate credential scope name")
	}
}

func TestLoadRejectsCredentialScopeCollidingWithStandardScope(t *testing.T) {
	path := writeTestRegistry(t, `
clients:
  - client_id: some-client
    token_endpoint_auth_method: none
    redirect_uris: ["https://example.com/a"]
    scope: "openid"

credential_scopes:
  - name: openid
    credential_type: "urn:fikua:padro:barcelona:1"
    claims: []
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected Load to reject a credential scope named \"openid\"")
	}
}

func TestLoadRejectsCredentialScopeMissingCredentialType(t *testing.T) {
	path := writeTestRegistry(t, `
clients:
  - client_id: some-client
    token_endpoint_auth_method: none
    redirect_uris: ["https://example.com/a"]
    scope: "openid"

credential_scopes:
  - name: padro_barcelona
    claims: []
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected Load to reject a credential scope with no credential_type")
	}
}
