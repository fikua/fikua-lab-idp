package oidcserver

import (
	"crypto/rand"
	"fmt"

	"github.com/zitadel/oidc/v3/pkg/op"

	fikuacrypto "github.com/fikua/fikua-lab-idp/internal/crypto"
	"github.com/fikua/fikua-lab-idp/internal/oidcclients"
	"github.com/fikua/fikua-lab-idp/internal/verifier"
)

// BasePath is where this bridge's endpoints are mounted — a namespace of
// its own, distinct from /oid4vci/v1 (internal/authz's wallet-facing
// OAuth2 surface) and /oid4vp/v1 (the Verifier's own wallet/frontend
// endpoints). See internal/authz's package doc for why these two OAuth2
// surfaces are not merged into one.
const BasePath = "/oidc/v1"

// LoginPath is BasePath's own login bridge — see login.go.
const LoginPath = BasePath + "/login"

// Server bundles everything cmd/idp/main.go needs to mount this bridge:
// the op.Provider (an http.Handler covering /authorize, /token,
// discovery, JWKS, userinfo, etc. under BasePath) and the LoginHandler
// (mounted separately at LoginPath, since op has no concept of it).
type Server struct {
	Provider *op.Provider
	Login    *LoginHandler
}

// New wires up the whole OpenID Connect bridge: loads the client
// registry from clientsPath, builds the op.Storage over it and
// signingKey, constructs the op.Provider (issuer = baseURL+BasePath —
// see op.NewProvider's contract that the issuer is exactly where the
// provider's own endpoints are rooted), and the LoginHandler that
// bridges op's login step to verifierService.
//
// Returns (nil, nil) when clientsPath is empty — no OpenID Connect
// Relying Parties are configured, so nothing under BasePath is
// registered at all (see cmd/idp/main.go), the same "absent config means
// absent feature, not a degraded one" stance internal/verifier's own
// loadVerifier already takes for FIKUA_DSS_URL.
func New(clientsPath string, signingKey *fikuacrypto.SigningKey, verifierService *verifier.Service, baseURL string) (*Server, error) {
	if clientsPath == "" {
		return nil, nil
	}
	if verifierService == nil {
		return nil, fmt.Errorf("oidcserver: OIDC_CLIENTS_PATH is set but no OID4VP Verifier is configured (FIKUA_DSS_URL) — this bridge has no login method without one")
	}

	registry, err := oidcclients.Load(clientsPath)
	if err != nil {
		return nil, err
	}

	storage := NewStorage(registry, signingKey, baseURL+LoginPath)

	var cryptoKey [32]byte
	if _, err := rand.Read(cryptoKey[:]); err != nil {
		return nil, fmt.Errorf("oidcserver: generating access-token encryption key: %w", err)
	}

	provider, err := op.NewProvider(
		&op.Config{
			CryptoKey:             cryptoKey,
			CodeMethodS256:        true,
			GrantTypeRefreshToken: true,
			SupportedScopes:       []string{"openid", "offline_access"},
		},
		storage,
		op.StaticIssuer(baseURL+BasePath),
	)
	if err != nil {
		return nil, fmt.Errorf("oidcserver: building OpenID Connect provider: %w", err)
	}

	login := NewLoginHandler(storage, registry, verifierService, op.AuthCallbackURL(provider), baseURL+BasePath)
	return &Server{Provider: provider, Login: login}, nil
}
