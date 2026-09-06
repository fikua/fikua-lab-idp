// Package config loads this service's configuration from environment
// variables.
package config

import (
	"os"
	"strings"
	"time"
)

// Config holds the identity provider's runtime configuration.
type Config struct {
	Addr     string
	BasePath string
	// BaseURL is this authorization server's own issuer identifier — the
	// `iss` of every access token it mints, the expected `aud` of every
	// client-attestation PoP, and the `htu` every DPoP proof presented
	// here must be bound to.
	BaseURL string
	// CredentialIssuerURL is the Credential Issuer this AS mints access
	// tokens for: the `aud` of every RFC 9068 access token, and the
	// `authorization_servers` entry pointing back at us. Single-issuer
	// setup — when a second Credential Issuer appears, this becomes a
	// resource-indicator (RFC 8707) lookup rather than one fixed value.
	CredentialIssuerURL string
	// AttestationRegistryURL is where the identification UI's claim
	// metadata comes from — the same catalogue the Credential Issuer
	// builds its credential_configurations_supported from, so the form
	// asks for exactly the claims that end up in the credential. Nothing
	// about claims is hardcoded here.
	AttestationRegistryURL  string
	RegistryRefreshInterval time.Duration
	// IssuableSchemes is the allowlist of attestation-registry scheme ids
	// whose claim metadata the identification form may render. Mirrors
	// the Credential Issuer's own FIKUA_ISSUABLE_SCHEMES — the two must
	// agree, or the form collects claims the issuer won't issue.
	IssuableSchemes []string
	// CertsDir holds idp-cert.pem + idp-key.pem, the EC P-256 key this AS
	// signs access tokens with. If either is missing, the service fails
	// to start (see internal/crypto.LoadFromPEM) — there is no ephemeral
	// fallback. This is deliberately a plain local key, not a Fikua DSS
	// credential: DSS-held keys are for eIDAS-relevant credential
	// signing, not for an OAuth2 access token nobody outside this
	// ecosystem ever validates.
	CertsDir string
}

// Load reads configuration from environment variables, applying defaults
// where unset.
func Load() Config {
	return Config{
		Addr:                    getenv("ADDR", ":8080"),
		BasePath:                getenv("BASE_PATH", ""),
		BaseURL:                 getenv("FIKUA_BASE_URL", "https://idp.fikua.com"),
		CredentialIssuerURL:     getenv("FIKUA_CREDENTIAL_ISSUER_URL", "https://issuer.fikua.com"),
		AttestationRegistryURL:  getenv("FIKUA_ATTESTATION_REGISTRY_URL", "https://attestation-registry.fikua.com"),
		RegistryRefreshInterval: 5 * time.Minute,
		IssuableSchemes:         splitCSV(getenv("FIKUA_ISSUABLE_SCHEMES", "urn:eudi:pid:1,urn:fikua:padro:barcelona:1")),
		CertsDir:                getenv("FIKUA_CERTS_DIR", "./certs"),
	}
}

func splitCSV(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
