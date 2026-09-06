package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// ResponseEncryptionKey is the OID4VP Verifier's response-encryption key
// (ECDH-ES, P-256) for response_mode=direct_post.jwt. The public half is
// published in the Authorization Request's client_metadata.jwks; the wallet
// encrypts its response to it, and the private half decrypts the JWE that
// comes back.
//
// Ephemeral by design, unlike every other key in this service: it is not an
// identity, it authenticates nothing, and it is only ever advertised inside
// a Request Object that lives as long as one verification session. Rotating
// it on restart invalidates nothing that was not already dead — a wallet
// holding a stale Request Object would fail at the session TTL anyway (see
// session.verificationSessionTTL). That reasoning does *not* extend to the
// signing keys in this package, which are load-or-fail for exactly the
// opposite reason.
type ResponseEncryptionKey struct {
	private *ecdsa.PrivateKey
	public  jwk.Key
	kid     string
}

// ResponseEncryptionAlg is the JWE key-agreement algorithm this Verifier
// advertises and accepts. HAIP §5 fixes it at ECDH-ES.
const ResponseEncryptionAlg = "ECDH-ES"

// ResponseEncryptionEncValues are the content-encryption methods advertised
// in client_metadata.encrypted_response_enc_values_supported. HAIP §5
// requires both A128GCM and A256GCM; decryption picks the method from the
// JWE `enc` header, so either works regardless of order here.
var ResponseEncryptionEncValues = []string{"A128GCM", "A256GCM"}

// GenerateResponseEncryptionKey generates a fresh P-256 ECDH-ES key whose
// kid is its own RFC 7638 SHA-256 thumbprint.
func GenerateResponseEncryptionKey() (*ResponseEncryptionKey, error) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("crypto: generating response encryption key: %w", err)
	}
	public, err := jwk.Import(private.Public())
	if err != nil {
		return nil, err
	}
	thumbprint, err := public.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	kid := base64.RawURLEncoding.EncodeToString(thumbprint)
	if err := public.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, err
	}
	if err := public.Set(jwk.AlgorithmKey, jwa.ECDH_ES()); err != nil {
		return nil, err
	}
	if err := public.Set(jwk.KeyUsageKey, "enc"); err != nil {
		return nil, err
	}
	return &ResponseEncryptionKey{private: private, public: public, kid: kid}, nil
}

// KID returns the key's id, matching the published JWK.
func (k *ResponseEncryptionKey) KID() string {
	return k.kid
}

// ThumbprintSHA256 returns the raw 32-byte RFC 7638 SHA-256 thumbprint of
// the public encryption key. OID4VP 1.0 Final §B.2.6 binds the mdoc
// OpenID4VPHandoverInfo to this thumbprint (as a CBOR byte string) whenever
// the response is encrypted, so a third party cannot re-encrypt a captured
// response to its own key and have the device signature still verify.
func (k *ResponseEncryptionKey) ThumbprintSHA256() ([]byte, error) {
	return k.public.Thumbprint(crypto.SHA256)
}

// PublicJWK returns the public JWK as a plain map for embedding in
// client_metadata.jwks.keys. Carries kid, use=enc and alg=ECDH-ES; never
// the private half.
func (k *ResponseEncryptionKey) PublicJWK() (map[string]any, error) {
	raw, err := json.Marshal(k.public)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// PeekResponseEncryptionKID reads the `kid` a wallet's direct_post.jwt JWE
// names, without decrypting it — each verification session now has its own
// response-encryption key (see GenerateResponseEncryptionKey's callers), so
// the session has to be identified before it is known which private key to
// even attempt decryption with.
func PeekResponseEncryptionKID(compactJWE string) (string, error) {
	msg, err := jwe.ParseString(compactJWE)
	if err != nil {
		return "", fmt.Errorf("crypto: parsing direct_post.jwt response: %w", err)
	}
	kid, _ := msg.ProtectedHeaders().KeyID()
	return kid, nil
}

// Decrypt decrypts a compact JWE produced by a wallet for direct_post.jwt,
// returning the plaintext payload (the JSON carrying vp_token, state, …).
func (k *ResponseEncryptionKey) Decrypt(compactJWE string) ([]byte, error) {
	// jwx wants an ecdh.PrivateKey for ECDH-ES, while the JWK/thumbprint
	// side of this type is expressed as an ecdsa key (the two are the same
	// P-256 scalar, differently typed in the standard library).
	ecdhKey, err := k.private.ECDH()
	if err != nil {
		return nil, fmt.Errorf("crypto: converting response encryption key: %w", err)
	}
	plaintext, err := jwe.Decrypt([]byte(compactJWE), jwe.WithKey(jwa.ECDH_ES(), ecdhKey))
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypting direct_post.jwt response: %w", err)
	}
	return plaintext, nil
}
