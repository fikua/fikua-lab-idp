// Package oidcserver implements this AS's OpenID Connect Core 1.0
// endpoints for classic web Relying Parties (e.g. Decidim's own
// omniauth-openid-connect login) — a separate protocol surface from
// internal/authz.Service's HAIP-only, ATCA-attested, wallet-facing OAuth2
// flow. See internal/oidcclients's package doc for why the two client
// models are kept apart rather than merged.
//
// Built on github.com/zitadel/oidc/v3's pkg/op, an OpenID
// Foundation-certified OP implementation: this package supplies op.Client
// and op.Storage: op itself owns request parsing, response encoding,
// and RFC/OIDC-conformant edge-case handling for /authorize, /token,
// discovery, JWKS and userinfo, so those do not need re-deriving from the
// specs here. The one endpoint op does not provide — the actual login
// step — is this package's own bridge into the OID4VP Verifier (see
// login.go): op.Client.LoginURL points at it, and it completes the
// AuthRequest once the Verifier reports a successful presentation.
package oidcserver

import (
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/fikua/fikua-lab-idp/internal/oidcclients"
)

// client adapts an oidcclients.Client to op.Client. Every registered
// client here is a public, PKCE-only Relying Party — see
// oidcclients.Client.TokenEndpointAuthMethod's doc comment for why no
// confidential-client method is implemented.
type client struct {
	cfg oidcclients.Client
	// loginBasePath is where LoginURL sends the browser — this AS's own
	// /oidc/v1/login page (see login.go), never the RP's own UI.
	loginBasePath string
}

var _ op.Client = (*client)(nil)

func (c *client) GetID() string                       { return c.cfg.ClientID }
func (c *client) RedirectURIs() []string              { return c.cfg.RedirectURIs }
func (c *client) PostLogoutRedirectURIs() []string    { return nil }
func (c *client) ApplicationType() op.ApplicationType { return op.ApplicationTypeWeb }
func (c *client) AuthMethod() oidc.AuthMethod         { return oidc.AuthMethodNone }
func (c *client) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}

func (c *client) GrantTypes() []oidc.GrantType {
	// refresh_token is only offered to a client that actually requested
	// offline_access — op's own needsRefreshToken check gates on that
	// scope already, so every registered client can safely advertise
	// both grant types without over-promising a refresh token nobody
	// asked for.
	return []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken}
}

func (c *client) LoginURL(authRequestID string) string {
	return c.loginBasePath + "?id=" + authRequestID
}

// AccessTokenType is Bearer, not the JWT variant: this AS's OpenID
// Connect surface exists to hand a Relying Party an ID Token it decodes
// itself, not an access token any resource server needs to verify
// offline — unlike internal/oauth2.Minter's RFC 9068 tokens, which
// fikua-lab-issuer does verify offline via this AS's JWKS. A future RP
// that calls back into a Fikua resource server with its access token
// would be the reason to revisit this.
func (c *client) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeBearer }

// IDTokenLifetime matches internal/verifier's own verification session
// TTL family (single-digit minutes) — this ID Token attests to a
// presentation just made, not a long-lived credential; a long lifetime
// would only widen a stolen-token window without buying anything, since
// the RP is expected to consume it immediately at its callback.
func (c *client) IDTokenLifetime() time.Duration { return 5 * time.Minute }

func (c *client) DevMode() bool { return false }

func (c *client) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}

func (c *client) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}

func (c *client) IsScopeAllowed(scope string) bool {
	// op.ValidateAuthReqScopes already always allows openid/profile/
	// email/phone/address/offline_access — this only gates any
	// *additional* scope a client might request, and this bridge has no
	// concept of one, so nothing beyond the standard scopes is ever
	// allowed.
	return false
}

// IDTokenUserinfoClaimsAssertion is false: userinfo-sourced claims are
// not duplicated into the ID Token, since a Relying Party configured
// with an empty VerifierClaims (the Decidim case — see
// oidcclients.Client.VerifierClaims's doc comment) must not receive any
// claim through either channel.
func (c *client) IDTokenUserinfoClaimsAssertion() bool { return false }

func (c *client) ClockSkew() time.Duration { return 0 }
