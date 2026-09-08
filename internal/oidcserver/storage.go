package oidcserver

import (
	"context"
	"errors"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	fikuacrypto "github.com/fikua/fikua-lab-idp/internal/crypto"
	"github.com/fikua/fikua-lab-idp/internal/oidcclients"
)

// Storage implements op.Storage over this bridge's own store and
// oidcclients' static registry. Deliberately does NOT implement
// op.ClientCredentialsStorage, op.TokenExchangeStorage or
// op.DeviceAuthorizationStorage — this bridge exists for exactly one
// flow (a browser Relying Party's authorization_code login, optionally
// refreshed), and op's own capability checks (e.g.
// GrantTypeClientCredentialsSupported) already turn "interface not
// implemented" into a clean unsupported_grant_type response rather than
// a confusing failure — there is nothing to gain by stubbing those out.
type Storage struct {
	store      *store
	clients    *oidcclients.Registry
	signingKey *fikuacrypto.SigningKey
	// loginBasePath is threaded through to every client() call — see
	// client.LoginURL.
	loginBasePath string
}

var _ op.Storage = (*Storage)(nil)

// NewStorage builds a Storage. signingKey is this AS's existing
// access-token key (internal/crypto.SigningKey) — see signingkey.go's
// doc comment for why ID Tokens are signed with the same key rather than
// a new one. loginBasePath is this service's own /oidc/v1/login path
// (see login.go's LoginPath), passed through rather than hardcoded so
// the top-level New (provider.go) stays the one place that URL is
// assembled.
func NewStorage(clients *oidcclients.Registry, signingKey *fikuacrypto.SigningKey, loginBasePath string) *Storage {
	return &Storage{store: newStore(), clients: clients, signingKey: signingKey, loginBasePath: loginBasePath}
}

// InternalStore exposes the AuthRequest store to login.go, which lives in
// the same package but is kept in its own file for readability — not
// exported beyond this package.
func (s *Storage) internalStore() *store { return s.store }

func (s *Storage) client(clientID string) (*client, error) {
	cfg, ok := s.clients.Lookup(clientID)
	if !ok {
		return nil, oidc.ErrInvalidClient().WithDescription("unknown client_id")
	}
	return &client{cfg: cfg, loginBasePath: s.loginBasePath, registry: s.clients}, nil
}

// --- AuthStorage ---

func (s *Storage) CreateAuthRequest(ctx context.Context, req *oidc.AuthRequest, _ string) (op.AuthRequest, error) {
	if req.CodeChallenge == "" {
		// Mandatory PKCE, enforced here rather than left to
		// AuthorizeCodeChallenge's nil-tolerant check — see
		// authRequest.codeChallenge's doc comment for why a bare
		// authRequest must never represent "PKCE optional".
		return nil, oidc.ErrInvalidRequest().WithDescription("code_challenge is required")
	}
	method := oidc.CodeChallengeMethodPlain
	if req.CodeChallengeMethod == oidc.CodeChallengeMethodS256 {
		method = oidc.CodeChallengeMethodS256
	} else if req.CodeChallengeMethod != "" && req.CodeChallengeMethod != oidc.CodeChallengeMethodPlain {
		return nil, oidc.ErrInvalidRequest().WithDescription("only S256 code_challenge_method is supported")
	}
	if method != oidc.CodeChallengeMethodS256 {
		return nil, oidc.ErrInvalidRequest().WithDescription("only S256 code_challenge_method is supported")
	}

	ar := &authRequest{
		id:           randomToken(16),
		clientID:     req.ClientID,
		redirectURI:  req.RedirectURI,
		state:        req.State,
		nonce:        req.Nonce,
		scopes:       req.Scopes,
		responseType: req.ResponseType,
		codeChallenge: &oidc.CodeChallenge{
			Challenge: req.CodeChallenge,
			Method:    method,
		},
		createdAt: time.Now(),
	}
	s.store.putAuthRequest(ar)
	return ar, nil
}

func (s *Storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	ar, ok := s.store.getAuthRequest(id)
	if !ok {
		return nil, errAuthRequestNotFound
	}
	return ar, nil
}

func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	id, ok := s.store.consumeAuthCode(code)
	if !ok {
		return nil, oidc.ErrInvalidGrant().WithDescription("invalid or expired authorization code")
	}
	ar, ok := s.store.getAuthRequest(id)
	if !ok {
		return nil, oidc.ErrInvalidGrant().WithDescription("authorization request expired")
	}
	return ar, nil
}

func (s *Storage) SaveAuthCode(ctx context.Context, id, code string) error {
	s.store.putAuthCode(code, id)
	return nil
}

func (s *Storage) DeleteAuthRequest(ctx context.Context, id string) error {
	s.store.deleteAuthRequest(id)
	return nil
}

func (s *Storage) CreateAccessToken(ctx context.Context, req op.TokenRequest) (accessTokenID string, expiration time.Time, err error) {
	// Bearer tokens (see client.AccessTokenType) are minted by
	// op.CreateBearerToken from an opaque ID this method returns, not by
	// this Storage — an ID with no separate lookup entry is fine, since
	// nothing here ever needs to resolve a bearer token ID back to a
	// request; op.CreateBearerToken already encodes tokenID+subject into
	// the token string itself.
	return randomToken(16), time.Now().Add(5 * time.Minute), nil
}

func (s *Storage) CreateAccessAndRefreshTokens(ctx context.Context, req op.TokenRequest, currentRefreshToken string) (accessTokenID, newRefreshToken string, expiration time.Time, err error) {
	accessTokenID = randomToken(16)
	expiration = time.Now().Add(5 * time.Minute)

	// currentRefreshToken is non-empty on a refresh_token grant
	// (rotation) and empty on the initial authorization_code grant that
	// requested offline_access. Either way this bridge always issues a
	// FRESH refresh token rather than reusing one — RFC 6749 §10.4
	// recommends rotation, and there is no reason to special-case the
	// no-rotation path here.
	if currentRefreshToken != "" {
		s.store.deleteRefreshToken(currentRefreshToken)
	}
	newRefreshToken = randomToken(32)
	s.store.putRefreshToken(newRefreshToken, req.GetSubject(), clientIDFromTokenRequest(req), req.GetScopes())
	return accessTokenID, newRefreshToken, expiration, nil
}

// clientIDFromTokenRequest recovers the client_id a TokenRequest was
// made for. op.TokenRequest itself carries no GetClientID — only the
// wider AuthRequest/RefreshTokenRequest interfaces this bridge's own
// concrete types satisfy do — but every TokenRequest CreateAccessToken/
// CreateAccessAndRefreshTokens is ever called with here IS one of those,
// since this Storage implements neither ClientCredentialsStorage nor
// TokenExchangeStorage (the only other sources of a bare TokenRequest).
func clientIDFromTokenRequest(req op.TokenRequest) string {
	type hasClientID interface{ GetClientID() string }
	if c, ok := req.(hasClientID); ok {
		return c.GetClientID()
	}
	return ""
}

func (s *Storage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	entry, ok := s.store.getRefreshToken(refreshToken)
	if !ok {
		return nil, op.ErrInvalidRefreshToken
	}
	return &refreshTokenRequest{subject: entry.subject, clientID: entry.clientID, scopes: entry.scopes}, nil
}

func (s *Storage) TerminateSession(ctx context.Context, userID, clientID string) error {
	// No server-side session beyond the refresh token itself exists to
	// terminate — RevokeToken (below) is what actually invalidates
	// tokens. A no-op here matches op's own contract: TerminateSession
	// exists for providers with a persistent browser session (e.g. a
	// session cookie) to also clear, which this bridge never sets — its
	// only state per login is the one-shot authRequest, already gone by
	// the time any session would be terminated.
	return nil
}

func (s *Storage) RevokeToken(ctx context.Context, tokenOrTokenID, userID, clientID string) *oidc.Error {
	// Only refresh tokens are revocable here — the bearer access tokens
	// this Storage mints carry no separate stored record (see
	// CreateAccessToken's doc comment), so there is nothing to delete for
	// one; op's RFC 7009 handler still returns 200 either way per spec
	// (revoking an already-invalid/unknown token is not an error).
	s.store.deleteRefreshToken(tokenOrTokenID)
	return nil
}

func (s *Storage) GetRefreshTokenInfo(ctx context.Context, clientID, token string) (userID, tokenID string, err error) {
	entry, ok := s.store.getRefreshToken(token)
	if !ok || entry.clientID != clientID {
		return "", "", op.ErrInvalidRefreshToken
	}
	return entry.subject, token, nil
}

func (s *Storage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	return signingKey{k: s.signingKey}, nil
}

func (s *Storage) SignatureAlgorithms(ctx context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.ES256}, nil
}

func (s *Storage) KeySet(ctx context.Context) ([]op.Key, error) {
	return []op.Key{publicKey{k: s.signingKey}}, nil
}

// --- OPStorage ---

func (s *Storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	return s.client(clientID)
}

func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	// Every registered client is token_endpoint_auth_method "none" (see
	// oidcclients.Client's doc comment) — there is no client_secret to
	// check. op only calls this for confidential-client flows this
	// bridge does not support (client_credentials, RFC 7009 revocation
	// with Basic auth), so returning "unauthorized" here is correct: a
	// public client is never authorized by secret, by definition.
	return errors.New("oidcserver: this AS has no confidential OpenID Connect clients")
}

// SetUserinfoFromScopes is deprecated by op itself in favor of
// CanSetUserinfoFromRequest (implemented below) — left empty per op's
// own doc comment on the interface.
func (s *Storage) SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, userID, clientID string, scopes []string) error {
	return nil
}

// SetUserinfoFromRequest is where the whole point of
// oidcclients.Client.VerifierClaims takes effect: the ONLY claim ever set
// is sub (the SubjectID pseudonym), for every client, regardless of
// scope. This bridge's Verifier-derived claims (name, residency, or
// nothing at all — see VerifierClaims's doc comment) never flow into an
// ID Token or /userinfo response: the disclosed claims exist only to let
// the Verifier confirm the presentation matched the DCQL query, and stop
// there. A future client that legitimately needs a Verifier-disclosed
// claim exposed to itself would need a deliberate, separate mechanism —
// not scope-based access to whatever the Verifier happened to see, which
// would silently leak claims info-per-scope-request has no other reason
// to restrict.
func (s *Storage) SetUserinfoFromRequest(ctx context.Context, userinfo *oidc.UserInfo, request op.IDTokenRequest, scopes []string) error {
	userinfo.Subject = request.GetSubject()
	return nil
}

func (s *Storage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error {
	// /userinfo (bearer-token-authenticated) — subject is already the
	// SubjectID pseudonym baked into the access token by op.
	// CreateBearerToken, so this mirrors SetUserinfoFromRequest above:
	// sub only, nothing else, for the same reason.
	userinfo.Subject = subject
	return nil
}

func (s *Storage) SetIntrospectionFromToken(ctx context.Context, introspection *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	introspection.Subject = subject
	introspection.ClientID = clientID
	introspection.Active = true
	return nil
}

func (s *Storage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error) {
	// No private (access-token JWT) claims — this bridge's access tokens
	// are opaque Bearer tokens (client.AccessTokenType), so this is only
	// ever consulted for a JWT-typed request this Storage never produces;
	// an empty map is the correct "no additional claims" answer either way.
	return nil, nil
}

func (s *Storage) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	return nil, fmt.Errorf("oidcserver: no per-client keys are registered")
}

func (s *Storage) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	return nil, fmt.Errorf("oidcserver: the JWT Profile grant is not supported")
}

func (s *Storage) Health(ctx context.Context) error { return nil }

var errAuthRequestNotFound = notFoundError{}

// notFoundError implements op.StorageNotFoundError so op's own
// not-found-vs-server-error branching (used at least by
// AuthorizeCallback's error rendering) sees this as the specific case it
// is, rather than an opaque failure.
type notFoundError struct{}

func (notFoundError) Error() string { return "auth request not found" }

// IsNotFound is a marker method (op.StorageNotFoundError) — its presence,
// not any body, is what op checks for.
func (notFoundError) IsNotFound() {}
