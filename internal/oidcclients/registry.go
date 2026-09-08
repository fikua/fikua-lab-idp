// Package oidcclients loads the static registry of OpenID Connect
// Relying Parties allowed to use this Verifier as their login method.
//
// This is deliberately separate from the ATCA client-attestation model
// internal/oauth2.ClientAttestationValidator uses for the /oid4vci/v1/*
// wallet-facing endpoints: a wallet proves its identity cryptographically
// on every request and needs no registry entry at all, but a classic web
// Relying Party (a Rails app doing browser-based OpenID Connect login,
// the case this package exists for) has no attestation to present — it
// authenticates the ordinary way, by being a known client_id with
// registered redirect_uris. Confusing the two models, or trying to make
// one RP registry serve both, would weaken the guarantee ATCA gives
// wallets today.
//
// Field names and shapes follow RFC 7591 (OAuth 2.0 Dynamic Client
// Registration Protocol) §2, which is also the vocabulary OpenID Connect
// Dynamic Client Registration builds on — chosen as the standard
// reference rather than mirroring any one vendor's own registry file
// format.
//
// Which credential a login requests is NOT part of a Client's own
// registration — it is resolved from the AuthRequest's own `scope`
// parameter, per OpenID4VP 1.0 §5.5 ("Using Scope Parameter to Request
// Presentations"): "Such a scope parameter value MUST be an alias for a
// well-defined DCQL query" and "the mapping between a certain scope
// value and the respective DCQL query [is] out of scope of this
// specification" — i.e. this bridge IS that mapping, published here as
// CredentialScope, not baked into a Client. This is a correction from an
// earlier version of this package, which fixed one credential type per
// registered client — that could not express a Relying Party (e.g.
// Decidim) needing a *different* credential per login depending on which
// of its own instances/processes is asking (a Barcelona padró for one
// participatory process, a Girona padró for another), all under the same
// client_id. §5.5 explicitly anticipates exactly this: an RP names the
// scope appropriate to what it's asking for in each individual
// authorization request, and the OP resolves it against a
// pre-established catalogue — never dynamically-supplied DCQL from the
// RP itself, which would let a compromised or misconfigured RP request
// undisclosed claims. See CredentialScope below.
package oidcclients

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Client is one Relying Party allowed to use this AS's OpenID Connect
// endpoints (internal/oidcserver). Every field maps to an RFC 7591 §2
// client-metadata property of the same meaning.
type Client struct {
	// ClientID identifies this RP in every OAuth2/OIDC request it makes.
	// Public per RFC 7591 §2 — this is not a place secrets live.
	ClientID string `yaml:"client_id"`

	// TokenEndpointAuthMethod is RFC 7591 §2's token_endpoint_auth_method.
	// Only "none" is supported today — a public client authenticated by
	// PKCE alone (RFC 7636), never a shared client_secret. This AS holds
	// no OIDC RP secrets by design: PKCE already binds the authorization
	// code to whoever generated the code_verifier, which is exactly the
	// property a client_secret would otherwise exist to provide, and a
	// static secret an operator must additionally protect (rotate, keep
	// out of a Rails app's committed config) buys this ecosystem nothing
	// a public client + mandatory PKCE doesn't already give it. A
	// confidential-client method may be added later for an RP that
	// specifically needs one, but is not implemented today — Load
	// rejects any other value rather than silently accepting a value it
	// cannot enforce.
	TokenEndpointAuthMethod string `yaml:"token_endpoint_auth_method"`

	// RedirectURIs is RFC 7591 §2's redirect_uris — the exhaustive
	// allowlist an authorization response's redirect is validated
	// against. At least one is required.
	RedirectURIs []string `yaml:"redirect_uris"`

	// Scope is RFC 7591 §2's space-delimited scope string — the RP's own
	// registered DEFAULT/allowed scopes. Must include "openid" — this
	// registry exists for OpenID Connect clients, not bare OAuth2 ones
	// (see internal/authz.Service for the latter, which this registry is
	// not involved in at all). Per-request, the RP may name any ONE of
	// this bridge's registered CredentialScope aliases (see LookupCredential
	// Scope) in its actual /authorize scope parameter to select which
	// credential that particular login presents — that choice is not
	// constrained to what is listed here; this field is about the client's
	// OWN registration metadata (RFC 7591), not an allowlist of which
	// credential scopes it may use. Restricting which credential scopes a
	// given client may request is not implemented — every registered
	// client may use any registered CredentialScope today.
	Scope string `yaml:"scope"`
}

// CredentialScope is one OpenID4VP §5.5 scope-to-DCQL alias this bridge
// publishes: a Relying Party names Name (e.g. "padro_barcelona") in its
// own AuthRequest's scope parameter, and internal/oidcserver's login
// bridge resolves it to CredentialType/Claims to build the OID4VP
// session with. Collision-resistant naming (§5.5's own
// RECOMMENDED) is this catalogue's job, not each RP's — a scope name
// only has to be unique across this one AS's registered scopes, not
// globally.
type CredentialScope struct {
	// Name is the OIDC scope value a Relying Party's /authorize request
	// carries to select this credential — e.g. "padro_barcelona".
	Name string `yaml:"name"`

	// CredentialType names the DCQL credential this scope resolves to —
	// e.g. "urn:fikua:padro:barcelona:1".
	CredentialType string `yaml:"credential_type"`

	// Claims lists which of that credential's claims are requested. An
	// empty list is a deliberate, first-class configuration — it means a
	// login using this scope only ever learns a stable pseudonymous
	// subject identifier and nothing about who presented it (see
	// internal/verifier's SubjectID derivation) — not an omission to fill
	// in later.
	Claims []string `yaml:"claims"`
}

// Registry looks up registered clients and credential scopes.
type Registry struct {
	clients          map[string]Client
	credentialScopes map[string]CredentialScope
}

// Load reads and validates the client registry from a YAML file shaped
// as {clients: [...], credential_scopes: [...]}. Every entry is
// validated at load time — a misconfigured client or scope should fail
// this service's startup, not surface as a confusing 400 the first time
// someone tries to log in through it.
func Load(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("oidcclients: reading %s: %w", path, err)
	}

	var doc struct {
		Clients          []Client          `yaml:"clients"`
		CredentialScopes []CredentialScope `yaml:"credential_scopes"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("oidcclients: parsing %s: %w", path, err)
	}

	clients := make(map[string]Client, len(doc.Clients))
	for _, c := range doc.Clients {
		if err := validateClient(c); err != nil {
			return nil, fmt.Errorf("oidcclients: client %q: %w", c.ClientID, err)
		}
		if _, dup := clients[c.ClientID]; dup {
			return nil, fmt.Errorf("oidcclients: duplicate client_id %q", c.ClientID)
		}
		clients[c.ClientID] = c
	}

	credentialScopes := make(map[string]CredentialScope, len(doc.CredentialScopes))
	for _, cs := range doc.CredentialScopes {
		if err := validateCredentialScope(cs); err != nil {
			return nil, fmt.Errorf("oidcclients: credential scope %q: %w", cs.Name, err)
		}
		if _, dup := credentialScopes[cs.Name]; dup {
			return nil, fmt.Errorf("oidcclients: duplicate credential scope name %q", cs.Name)
		}
		if cs.Name == "openid" || cs.Name == "offline_access" || cs.Name == "profile" || cs.Name == "email" {
			return nil, fmt.Errorf("oidcclients: credential scope %q collides with a standard OIDC scope name", cs.Name)
		}
		credentialScopes[cs.Name] = cs
	}

	return &Registry{clients: clients, credentialScopes: credentialScopes}, nil
}

func validateClient(c Client) error {
	if c.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}
	if c.TokenEndpointAuthMethod != "none" {
		return fmt.Errorf("token_endpoint_auth_method must be \"none\" (public client + PKCE) — %q is not supported", c.TokenEndpointAuthMethod)
	}
	if len(c.RedirectURIs) == 0 {
		return fmt.Errorf("redirect_uris must list at least one URI")
	}
	if !containsScope(c.Scope, "openid") {
		return fmt.Errorf("scope must include \"openid\"")
	}
	return nil
}

func validateCredentialScope(cs CredentialScope) error {
	if cs.Name == "" {
		return fmt.Errorf("name is required")
	}
	if cs.CredentialType == "" {
		return fmt.Errorf("credential_type is required")
	}
	return nil
}

func containsScope(scope, want string) bool {
	start := 0
	for i := 0; i <= len(scope); i++ {
		if i == len(scope) || scope[i] == ' ' {
			if scope[start:i] == want {
				return true
			}
			start = i + 1
		}
	}
	return false
}

// Lookup returns the registered client for clientID, or false if none is
// registered — the caller (internal/oidcserver's op.Storage.
// GetClientByClientID) must treat that as "unknown client", never fall
// back to a default.
func (r *Registry) Lookup(clientID string) (Client, bool) {
	c, ok := r.clients[clientID]
	return c, ok
}

// ResolveCredentialScope finds the one registered CredentialScope named
// among scopes (an AuthRequest's own scope list), per OpenID4VP 1.0
// §5.5's model of a scope value as a DCQL-query alias. Returns false if
// none of scopes names a registered credential scope — the caller
// (internal/oidcserver's LoginHandler) must treat that as "this login
// has no credential to present" rather than falling back to a default,
// since defaulting silently would let a login proceed while requesting
// something the RP never actually asked for.
//
// At most one credential scope may ever match (see this package's own
// doc comment on the "exactly one credential scope per request" design
// decision) — if an AuthRequest's scopes somehow name more than one
// registered CredentialScope, the first match found is used and the
// rest are silently ignored, matching how an unknown/unregistered scope
// is already treated elsewhere (RFC 6749 §3.3: a server MAY ignore
// scope values it does not understand or support).
func (r *Registry) ResolveCredentialScope(scopes []string) (CredentialScope, bool) {
	for _, s := range scopes {
		if cs, ok := r.credentialScopes[s]; ok {
			return cs, true
		}
	}
	return CredentialScope{}, false
}

// IsCredentialScope reports whether scope names a registered
// CredentialScope — used by op.Client.IsScopeAllowed (see
// internal/oidcserver's client type) to admit a credential-selecting
// scope value into an AuthRequest alongside the standard OIDC scopes
// op.ValidateAuthReqScopes always allows on its own.
func (r *Registry) IsCredentialScope(scope string) bool {
	_, ok := r.credentialScopes[scope]
	return ok
}
