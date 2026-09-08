package oidcserver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fikua/fikua-lab-idp/internal/session"
)

func writeExampleClientsYAML(t *testing.T) string {
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
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing clients.yaml: %v", err)
	}
	return path
}

func TestNewDisabledWithoutClientsPath(t *testing.T) {
	signingKey := testSigningKey(t)
	srv, err := New("", signingKey, nil, "https://idp.example.org")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if srv != nil {
		t.Error("New with an empty clientsPath must return a nil Server — the bridge is entirely disabled")
	}
}

func TestNewRequiresVerifierWhenClientsConfigured(t *testing.T) {
	signingKey := testSigningKey(t)
	path := writeExampleClientsYAML(t)
	if _, err := New(path, signingKey, nil, "https://idp.example.org"); err == nil {
		t.Fatal("New must fail when OIDC_CLIENTS_PATH is set but no OID4VP Verifier is configured")
	}
}

func TestNewBuildsAWorkingServer(t *testing.T) {
	sessions := session.NewStore()
	verifierService := newTestVerifierService(t, sessions)
	signingKey := testSigningKey(t)
	path := writeExampleClientsYAML(t)

	srv, err := New(path, signingKey, verifierService, "https://idp.example.org")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if srv == nil || srv.Provider == nil || srv.Login == nil {
		t.Fatalf("New = %+v, want a fully populated Server", srv)
	}
}

func TestNewRejectsMalformedClientsFile(t *testing.T) {
	signingKey := testSigningKey(t)
	sessions := session.NewStore()
	verifierService := newTestVerifierService(t, sessions)
	if _, err := New(filepath.Join(t.TempDir(), "does-not-exist.yaml"), signingKey, verifierService, "https://idp.example.org"); err == nil {
		t.Fatal("New must fail when clientsPath does not exist")
	}
}
