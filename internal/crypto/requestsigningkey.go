package crypto

import (
	"crypto"
	"encoding/base64"

	joseCert "github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// RequestSigningKey is the OID4VP Verifier's Request Object (JAR, RFC 9101)
// signing key: a crypto.Signer — in every real deployment a
// cscclient.Signer delegating to the Fikua DSS — plus the leaf certificate
// that goes into the JWS x5c header.
//
// The Go counterpart of the Java verifier's crypto.SigningKey interface
// (kid()/x5cChain()/signJwt()), narrowed to what the OID4VP Verifier
// actually needs.
//
// Deliberately a separate type from SigningKey above, and the one place in
// this service where a remote (DSS) key is the *only* supported option.
// The distinction is who checks the signature: SigningKey signs access
// tokens the Credential Issuer verifies against a JWK Set we publish
// ourselves, so a plain local key is enough trust. This key signs
// Authorization Requests a *wallet* checks before releasing a holder's
// attributes, against the certificate's SAN and its chain — trust that
// only exists if the private key lives in the DSS's HSM behind a real
// certificate, not in a PEM file next to the binary. Hence no
// LoadFromPEM sibling here: there is nothing a self-signed local key
// could prove to a wallet.
type RequestSigningKey struct {
	kid      string
	signer   crypto.Signer
	x5cChain [][]byte // leaf-first DER, trust anchor excluded (HAIP §6.1.1)
}

// NewRequestSigningKey builds a RequestSigningKey from signer and its
// leaf-first DER certificate chain (which must exclude the trust anchor,
// per HAIP §6.1.1 — see cscclient.Signer.LeafDER). The kid is the RFC 7638
// SHA-256 thumbprint of the public key, never a random value, so the same
// credential always presents the same kid across restarts.
func NewRequestSigningKey(signer crypto.Signer, certChainDER [][]byte) (*RequestSigningKey, error) {
	pub, err := jwk.Import(signer.Public())
	if err != nil {
		return nil, err
	}
	thumbprint, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return &RequestSigningKey{
		kid:      base64.RawURLEncoding.EncodeToString(thumbprint),
		signer:   signer,
		x5cChain: certChainDER,
	}, nil
}

// KID returns the key's id — the RFC 7638 SHA-256 JWK thumbprint.
func (k *RequestSigningKey) KID() string {
	return k.kid
}

// Signer returns the crypto.Signer backing this key, for jws.Sign /
// jwt.Sign's WithKey option.
func (k *RequestSigningKey) Signer() crypto.Signer {
	return k.signer
}

// Algorithm is the JWS algorithm Request Objects are signed with. HAIP
// fixes this at ES256, like every other signature in this ecosystem.
func (k *RequestSigningKey) Algorithm() jwa.SignatureAlgorithm {
	return jwa.ES256()
}

// LeafDER returns the signing certificate's raw DER bytes, or nil if this
// key has no certificate. The OID4VP `x509_hash:` client identifier prefix
// is base64url(SHA-256(this)) — see verifier.Service.
func (k *RequestSigningKey) LeafDER() []byte {
	if len(k.x5cChain) == 0 {
		return nil
	}
	return k.x5cChain[0]
}

// X5CChain returns the leaf-first DER certificate chain (trust anchor
// excluded) backing this key, or nil if it has none.
func (k *RequestSigningKey) X5CChain() [][]byte {
	return k.x5cChain
}

// JOSEX5CChain builds this key's chain in the JOSE x5c wire format
// (base64-encoded DER per entry), ready for a jws protected header.
// Returns nil when the key carries no certificate.
func (k *RequestSigningKey) JOSEX5CChain() (*joseCert.Chain, error) {
	if len(k.x5cChain) == 0 {
		return nil, nil
	}
	var chain joseCert.Chain
	for _, der := range k.x5cChain {
		// cert.Chain.Add expects PEM or a base64-encoded DER string (the
		// JOSE x5c wire format), so raw DER must be encoded first.
		if err := chain.AddString(base64.StdEncoding.EncodeToString(der)); err != nil {
			return nil, err
		}
	}
	return &chain, nil
}
