// Package crypto provides the authorization server's EC P-256/ES256
// access-token signing key, loaded from local PEM files.
//
// Deliberately simpler than fikua-lab-issuer's package of the same name:
// there is no remote (Fikua DSS / CSC) signing backend here, and no x5c
// chain. Those exist for the issuer's *credential* signing key, whose
// trust chains back to an eIDAS-relevant trust anchor relying parties
// check. This key signs RFC 9068 access tokens, which only ever travel
// between this AS and the Credential Issuer that fetches this key from
// /oid4vci/v1/jwks — a plain key with a thumbprint kid is exactly the
// right amount of ceremony, and paying for a DSS round-trip on every
// /token call would not buy any trust nobody was asking for.
package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Algorithm is the JWS algorithm this authorization server signs access
// tokens with — ES256 throughout, matching every other signature in this
// ecosystem.
var Algorithm = jwa.ES256()

// SigningKey is the AS's local EC P-256 access-token signing key, paired
// with the public JWK served at /oid4vci/v1/jwks.
type SigningKey struct {
	kid     string
	private *ecdsa.PrivateKey
	public  jwk.Key
}

// LoadFromPEM loads the access-token signing key from
// <certsDir>/idp-key.pem, with <certsDir>/idp-cert.pem alongside it.
// There is no ephemeral fallback: a key regenerated on every restart
// would silently invalidate every access token already in flight and
// every JWKS response the Credential Issuer has cached, which fails as a
// mystery 401 rather than as a startup error somebody can read.
func LoadFromPEM(certsDir string) (*SigningKey, error) {
	keyPath := filepath.Join(certsDir, "idp-key.pem")
	if !fileExists(keyPath) {
		return nil, fmt.Errorf("crypto: no access-token signing key configured — place idp-key.pem in %s", certsDir)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("crypto: reading %s: %w", keyPath, err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("crypto: %s: no PEM block found", keyPath)
	}
	private, err := parseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("crypto: parsing %s: %w", keyPath, err)
	}

	return newSigningKey(private)
}

// parseECPrivateKey accepts both PKCS#8 ("BEGIN PRIVATE KEY") and SEC 1
// ("BEGIN EC PRIVATE KEY") encodings, since `openssl ecparam -genkey`
// still emits the latter by default and requiring a conversion step
// before the service will start is a needless trap.
func parseECPrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an EC private key")
		}
		return ecKey, nil
	}
	return x509.ParseECPrivateKey(der)
}

func newSigningKey(private *ecdsa.PrivateKey) (*SigningKey, error) {
	public, err := jwk.Import(private.Public())
	if err != nil {
		return nil, err
	}
	thumbprint, err := public.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	// kid is the RFC 7638 thumbprint, never a random UUID: the Credential
	// Issuer caches this JWK Set, so a kid that changes across restarts
	// for the same key material would look like a key rotation and force
	// a needless refetch.
	kid := base64.RawURLEncoding.EncodeToString(thumbprint)
	if err := public.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, err
	}
	if err := public.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		return nil, err
	}
	if err := public.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return nil, err
	}
	return &SigningKey{kid: kid, private: private, public: public}, nil
}

// KID returns the key's id — the RFC 7638 SHA-256 JWK thumbprint.
func (k *SigningKey) KID() string {
	return k.kid
}

// Signer returns the crypto.Signer backing this key, for jws.Sign /
// jwt.Sign's WithKey option.
func (k *SigningKey) Signer() crypto.Signer {
	return k.private
}

// PublicJWK returns the key's public JWK (kid/alg/use already set).
func (k *SigningKey) PublicJWK() jwk.Key {
	return k.public
}

// JWKSetJSON returns the public JWK Set as served at /oid4vci/v1/jwks:
// {"keys": [<public JWK>]}. This is what the Credential Issuer fetches
// to verify the access tokens this AS mints.
func (k *SigningKey) JWKSetJSON() ([]byte, error) {
	set := jwk.NewSet()
	if err := set.AddKey(k.public); err != nil {
		return nil, err
	}
	return json.Marshal(set)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
