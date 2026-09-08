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
// format. verifierCredentialType/verifierClaims are the one addition
// beyond RFC 7591: they are not an OIDC concept, they are this bridge's
// own configuration of what the Verifier asks the wallet for on this
// client's behalf.
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

	// Scope is RFC 7591 §2's space-delimited scope string. Must include
	// "openid" — this registry exists for OpenID Connect clients, not
	// bare OAuth2 ones (see internal/authz.Service for the latter, which
	// this registry is not involved in at all).
	Scope string `yaml:"scope"`

	// VerifierCredentialType names the DCQL credential this client's
	// login flow requests — e.g. "urn:fikua:padro:barcelona:1". Not an
	// OIDC or RFC 7591 concept: this is the configuration that decides,
	// per Relying Party, what internal/oidcserver asks the OID4VP
	// Verifier for on that RP's behalf.
	VerifierCredentialType string `yaml:"verifier_credential_type"`

	// VerifierClaims lists which of that credential's claims are
	// requested. An empty list is a deliberate, first-class
	// configuration — it means this client only ever learns a stable
	// pseudonymous subject identifier and nothing about who presented
	// it (see internal/verifier's SubjectID derivation and PadroBarcelona
	// docs) — not an omission to fill in later.
	VerifierClaims []string `yaml:"verifier_claims"`
}

// Registry looks up registered clients by ID.
type Registry struct {
	clients map[string]Client
}

// Load reads and validates the client registry from a YAML file shaped
// as {clients: [...]}. Every entry is validated at load time — a
// misconfigured client should fail this service's startup, not surface
// as a confusing 400 the first time someone tries to log in through it.
func Load(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("oidcclients: reading %s: %w", path, err)
	}

	var doc struct {
		Clients []Client `yaml:"clients"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("oidcclients: parsing %s: %w", path, err)
	}

	clients := make(map[string]Client, len(doc.Clients))
	for _, c := range doc.Clients {
		if err := validate(c); err != nil {
			return nil, fmt.Errorf("oidcclients: client %q: %w", c.ClientID, err)
		}
		if _, dup := clients[c.ClientID]; dup {
			return nil, fmt.Errorf("oidcclients: duplicate client_id %q", c.ClientID)
		}
		clients[c.ClientID] = c
	}
	return &Registry{clients: clients}, nil
}

func validate(c Client) error {
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
	if c.VerifierCredentialType == "" {
		return fmt.Errorf("verifier_credential_type is required")
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
