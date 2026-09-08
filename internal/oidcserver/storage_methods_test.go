package oidcserver

import (
	"context"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// TestStorageMethodsNotBackedByHTTP exercises the op.Storage methods
// this bridge implements but that no HTTP-level test above happens to
// reach — every unsupported grant/flow's storage method still has to
// answer correctly (not panic, and either succeed or fail the way its
// doc comment says) since op itself may probe them via interface
// assertions (e.g. GrantTypeClientCredentialsSupported).
func TestStorageMethodsNotBackedByHTTP(t *testing.T) {
	registry := testRegistry(t)
	signingKey := testSigningKey(t)
	storage := NewStorage(registry, signingKey, "https://as.example.org"+LoginPath)
	ctx := context.Background()

	t.Run("CreateAccessToken", func(t *testing.T) {
		id, exp, err := storage.CreateAccessToken(ctx, &authRequest{id: "ar-1", clientID: "decidim-barcelona"})
		if err != nil {
			t.Fatalf("CreateAccessToken: %v", err)
		}
		if id == "" || exp.IsZero() {
			t.Errorf("CreateAccessToken = %q, %v", id, exp)
		}
	})

	t.Run("AuthorizeClientIDSecret always rejects", func(t *testing.T) {
		if err := storage.AuthorizeClientIDSecret(ctx, "decidim-barcelona", "any-secret"); err == nil {
			t.Error("AuthorizeClientIDSecret must reject every public client — there are no client secrets")
		}
	})

	t.Run("TerminateSession is a no-op success", func(t *testing.T) {
		if err := storage.TerminateSession(ctx, "subject-1", "decidim-barcelona"); err != nil {
			t.Errorf("TerminateSession: %v", err)
		}
	})

	t.Run("RevokeToken deletes a refresh token and is idempotent", func(t *testing.T) {
		storage.internalStore().putRefreshToken("rt-1", "subject-1", "decidim-barcelona", []string{"openid"})
		if oidcErr := storage.RevokeToken(ctx, "rt-1", "subject-1", "decidim-barcelona"); oidcErr != nil {
			t.Errorf("RevokeToken: %v", oidcErr)
		}
		if _, ok := storage.internalStore().getRefreshToken("rt-1"); ok {
			t.Error("RevokeToken should have deleted the refresh token")
		}
		// Revoking an already-gone / never-issued token must not error —
		// RFC 7009 treats this as a success, not a failure.
		if oidcErr := storage.RevokeToken(ctx, "never-issued", "subject-1", "decidim-barcelona"); oidcErr != nil {
			t.Errorf("RevokeToken on an unknown token should not error: %v", oidcErr)
		}
	})

	t.Run("GetRefreshTokenInfo", func(t *testing.T) {
		storage.internalStore().putRefreshToken("rt-2", "subject-2", "decidim-barcelona", []string{"openid"})
		userID, tokenID, err := storage.GetRefreshTokenInfo(ctx, "decidim-barcelona", "rt-2")
		if err != nil || userID != "subject-2" || tokenID != "rt-2" {
			t.Fatalf("GetRefreshTokenInfo = %q, %q, %v", userID, tokenID, err)
		}
		// A client_id that does not match the token's own must be
		// rejected — a refresh token is only usable by the client it was
		// issued to.
		if _, _, err := storage.GetRefreshTokenInfo(ctx, "some-other-client", "rt-2"); err == nil {
			t.Error("GetRefreshTokenInfo must reject a client_id mismatch")
		}
		if _, _, err := storage.GetRefreshTokenInfo(ctx, "decidim-barcelona", "never-issued"); err == nil {
			t.Error("GetRefreshTokenInfo must reject an unknown token")
		}
	})

	t.Run("KeySet returns this AS's public signing key", func(t *testing.T) {
		keys, err := storage.KeySet(ctx)
		if err != nil || len(keys) != 1 {
			t.Fatalf("KeySet = %v, %v", keys, err)
		}
		if keys[0].ID() != signingKey.KID() {
			t.Errorf("KeySet()[0].ID() = %q, want %q", keys[0].ID(), signingKey.KID())
		}
	})

	t.Run("SetUserinfoFromToken sets only sub", func(t *testing.T) {
		var info oidc.UserInfo
		if err := storage.SetUserinfoFromToken(ctx, &info, "token-id", "subject-3", "origin"); err != nil {
			t.Fatalf("SetUserinfoFromToken: %v", err)
		}
		if info.Subject != "subject-3" {
			t.Errorf("Subject = %q", info.Subject)
		}
	})

	t.Run("SetIntrospectionFromToken", func(t *testing.T) {
		var introspection oidc.IntrospectionResponse
		if err := storage.SetIntrospectionFromToken(ctx, &introspection, "token-id", "subject-4", "decidim-barcelona"); err != nil {
			t.Fatalf("SetIntrospectionFromToken: %v", err)
		}
		if introspection.Subject != "subject-4" || introspection.ClientID != "decidim-barcelona" || !introspection.Active {
			t.Errorf("introspection = %+v", introspection)
		}
	})

	t.Run("GetPrivateClaimsFromScopes returns nothing", func(t *testing.T) {
		claims, err := storage.GetPrivateClaimsFromScopes(ctx, "subject-1", "decidim-barcelona", []string{"openid"})
		if err != nil || claims != nil {
			t.Errorf("GetPrivateClaimsFromScopes = %v, %v, want nil, nil", claims, err)
		}
	})

	t.Run("GetKeyByIDAndClientID is unsupported", func(t *testing.T) {
		if _, err := storage.GetKeyByIDAndClientID(ctx, "some-key", "decidim-barcelona"); err == nil {
			t.Error("GetKeyByIDAndClientID should report no per-client keys are registered")
		}
	})

	t.Run("ValidateJWTProfileScopes is unsupported", func(t *testing.T) {
		if _, err := storage.ValidateJWTProfileScopes(ctx, "subject-1", []string{"openid"}); err == nil {
			t.Error("ValidateJWTProfileScopes should report the JWT Profile grant is unsupported")
		}
	})

	t.Run("Health", func(t *testing.T) {
		if err := storage.Health(ctx); err != nil {
			t.Errorf("Health: %v", err)
		}
	})

	t.Run("GetClientByClientID rejects an unknown client", func(t *testing.T) {
		if _, err := storage.GetClientByClientID(ctx, "unknown-client"); err == nil {
			t.Error("GetClientByClientID should reject an unregistered client_id")
		}
	})

	t.Run("AuthRequestByID and AuthRequestByCode reject unknown ids", func(t *testing.T) {
		if _, err := storage.AuthRequestByID(ctx, "does-not-exist"); err == nil {
			t.Error("AuthRequestByID should reject an unknown id")
		}
		if _, err := storage.AuthRequestByCode(ctx, "does-not-exist"); err == nil {
			t.Error("AuthRequestByCode should reject an unknown code")
		}
	})

	t.Run("notFoundError satisfies op.StorageNotFoundError", func(t *testing.T) {
		err := errAuthRequestNotFound
		if err.Error() == "" {
			t.Error("notFoundError.Error() must not be empty")
		}
		err.IsNotFound() // must not panic; marker method only
	})
}

// TestCreateAuthRequestRejectsUnsupportedChallengeMethod covers the
// branch CreateAuthRequest's PKCE validation takes for a
// code_challenge_method other than S256 or plain — the HTTP-level tests
// only exercise "missing" and "S256".
func TestCreateAuthRequestRejectsUnsupportedChallengeMethod(t *testing.T) {
	registry := testRegistry(t)
	signingKey := testSigningKey(t)
	storage := NewStorage(registry, signingKey, "https://as.example.org"+LoginPath)

	_, err := storage.CreateAuthRequest(context.Background(), &oidc.AuthRequest{
		ClientID:            "decidim-barcelona",
		RedirectURI:         "https://decidim.example.org/callback",
		CodeChallenge:       "abc123",
		CodeChallengeMethod: "unsupported-method",
	}, "")
	if err == nil {
		t.Fatal("CreateAuthRequest must reject a code_challenge_method other than S256")
	}
}

// TestClientIDFromTokenRequestUnknownType covers
// clientIDFromTokenRequest's fallback for a TokenRequest type with no
// GetClientID method — a case op itself never actually constructs for
// this Storage (see clientIDFromTokenRequest's own doc comment) but the
// function must still degrade to an empty string rather than panic.
type bareTokenRequest struct{}

func (bareTokenRequest) GetSubject() string    { return "s" }
func (bareTokenRequest) GetAudience() []string { return nil }
func (bareTokenRequest) GetScopes() []string   { return nil }

func TestClientIDFromTokenRequestUnknownType(t *testing.T) {
	if got := clientIDFromTokenRequest(bareTokenRequest{}); got != "" {
		t.Errorf("clientIDFromTokenRequest(bareTokenRequest{}) = %q, want empty", got)
	}
}
