package oidcserver

import (
	jose "github.com/go-jose/go-jose/v4"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/zitadel/oidc/v3/pkg/op"

	fikuacrypto "github.com/fikua/fikua-lab-idp/internal/crypto"
)

// signingKey adapts fikuacrypto.SigningKey — this AS's existing EC P-256
// key, already used to sign RFC 9068 access tokens for
// internal/oauth2.Minter — to op.SigningKey/op.Key, so ID Tokens minted
// through this bridge are signed by the same key and published on the
// same JWK Set the Credential Issuer already fetches. A second signing
// key here would mean a second key an operator has to provision, back
// up, and eventually rotate for no isolation benefit: nothing outside
// this AS's own JWKS response ever needs to tell "was this an OAuth2
// access token or an OpenID Connect ID Token" apart by which key signed
// it.
type signingKey struct{ k *fikuacrypto.SigningKey }

var _ op.SigningKey = signingKey{}
var _ op.Key = signingKey{}

func (s signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.ES256 }
func (s signingKey) Key() any                                    { return s.k.Signer() }
func (s signingKey) ID() string                                  { return s.k.KID() }
func (s signingKey) Algorithm() jose.SignatureAlgorithm          { return jose.ES256 }
func (s signingKey) Use() string                                 { return "sig" }

// publicKey adapts the same fikuacrypto.SigningKey's public half for
// op.Storage.KeySet — the JWKS this OpenID Connect surface serves at its
// own discovery-advertised jwks_uri (see discovery.go), kept separate
// from /oid4vci/v1/jwks (httpapi.Handler.jwks) even though the key
// material is identical, since the two are unrelated specs' endpoints
// and a Relying Party has no reason to know about the OAuth2 one.
type publicKey struct{ k *fikuacrypto.SigningKey }

var _ op.Key = publicKey{}

func (p publicKey) ID() string                         { return p.k.KID() }
func (p publicKey) Algorithm() jose.SignatureAlgorithm { return jose.ES256 }
func (p publicKey) Use() string                        { return "sig" }
func (p publicKey) Key() any {
	var pub any
	_ = jwk.Export(p.k.PublicJWK(), &pub)
	return pub
}
