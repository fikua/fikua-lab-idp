package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	joseCert "github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"

	fikuacrypto "github.com/fikua/fikua-lab-idp/internal/crypto"
)

// testSigningKey is this package's own name for
// fikuacrypto.NewTestRequestSigningKey — see that constructor's doc
// comment (internal/crypto/testkeys.go) for why it lives there instead
// of being duplicated per test package.
func testSigningKey(t *testing.T) *fikuacrypto.RequestSigningKey {
	t.Helper()
	return fikuacrypto.NewTestRequestSigningKey(t)
}

// testHolderKey generates a fresh ECDSA P-256 keypair for a credential
// holder (the wallet side of a presentation), returned as both the raw
// private key (to sign a KB-JWT) and its public jwk.Key (to embed in an
// issuer JWT's cnf.jwk).
func testHolderKey(t *testing.T) (*ecdsa.PrivateKey, jwk.Key) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jwk.Import(priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

// testIssuerKey is a throwaway issuer signing keypair plus its self-signed
// certificate — the counterpart of testSigningKey, but for the credential
// issuer side of a presentation (whoever signed the SD-JWT VC being
// presented), entirely independent of this Verifier's own signing key.
type testIssuerKey struct {
	priv     *ecdsa.PrivateKey
	leafDER  []byte
	x5cChain *joseCert.Chain
}

func newTestIssuerKey(t *testing.T) testIssuerKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-issuer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	var chain joseCert.Chain
	if err := chain.AddString(base64.StdEncoding.EncodeToString(der)); err != nil {
		t.Fatal(err)
	}
	return testIssuerKey{priv: priv, leafDER: der, x5cChain: &chain}
}

// sdJWTPresentationOpts configures buildSDJWTPresentation.
type sdJWTPresentationOpts struct {
	vct             string
	claims          map[string]any // becomes selectively-disclosable disclosures
	holderPublicJWK jwk.Key        // embedded as the issuer JWT's cnf.jwk
	holderPrivKey   *ecdsa.PrivateKey
	audience        string // KB-JWT aud — should match the Verifier's client_id
	nonce           string // KB-JWT nonce — should match the session nonce
	// Overrides for negative-path tests; zero value means "correct".
	badKBJWTAud   string
	badKBJWTNonce string
	skipKBJWT     bool
	tamperClaim   string // if set, this claim's disclosure is dropped from the presentation after signing, without removing it from _sd
}

// buildSDJWTPresentation assembles a full "<issuer-jwt>~<disclosure>~...~<kb-jwt>"
// SD-JWT VC presentation, byte-compatible with what sdjwtverify.VerifyWithStatus
// expects — the same shape fikua-lab-issuer's internal/sdjwt.Builder produces
// (not importable here directly; repos share no Go module by this project's
// convention), reimplemented minimally for test purposes only.
func buildSDJWTPresentation(t *testing.T, issuer testIssuerKey, opts sdJWTPresentationOpts) string {
	t.Helper()

	type disclosure struct {
		claimName string
		encoded   string
	}
	var disclosures []disclosure
	var sdDigests []string
	for name, value := range opts.claims {
		saltBytes := make([]byte, 16)
		if _, err := rand.Read(saltBytes); err != nil {
			t.Fatal(err)
		}
		salt := base64.RawURLEncoding.EncodeToString(saltBytes)
		arr, err := json.Marshal([]any{salt, name, value})
		if err != nil {
			t.Fatal(err)
		}
		encoded := base64.RawURLEncoding.EncodeToString(arr)
		sum := sha256.Sum256([]byte(encoded))
		digest := base64.RawURLEncoding.EncodeToString(sum[:])
		disclosures = append(disclosures, disclosure{claimName: name, encoded: encoded})
		sdDigests = append(sdDigests, digest)
	}

	now := time.Now()
	builder := jwt.NewBuilder().
		Issuer("https://test-issuer.example").
		IssuedAt(now).
		Expiration(now.Add(time.Hour)).
		Claim("vct", opts.vct)
	if len(sdDigests) > 0 {
		builder = builder.Claim("_sd", sdDigests).Claim("_sd_alg", "sha-256")
	}
	if opts.holderPublicJWK != nil {
		holderJWKJSON, err := json.Marshal(opts.holderPublicJWK)
		if err != nil {
			t.Fatal(err)
		}
		var holderJWKMap map[string]any
		if err := json.Unmarshal(holderJWKJSON, &holderJWKMap); err != nil {
			t.Fatal(err)
		}
		builder = builder.Claim("cnf", map[string]any{"jwk": holderJWKMap})
	}
	token, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}

	headers := jws.NewHeaders()
	if err := headers.Set(jws.X509CertChainKey, issuer.x5cChain); err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256(), issuer.priv, jws.WithProtectedHeaders(headers)))
	if err != nil {
		t.Fatal(err)
	}

	var sb []byte
	sb = append(sb, signed...)
	for _, d := range disclosures {
		if d.claimName == opts.tampeMatch(opts.tamperClaim) {
			continue
		}
		sb = append(sb, '~')
		sb = append(sb, []byte(d.encoded)...)
	}
	sb = append(sb, '~')

	if opts.skipKBJWT {
		return string(sb)
	}

	sdHashSum := sha256.Sum256(sb)
	sdHash := base64.RawURLEncoding.EncodeToString(sdHashSum[:])

	aud := opts.audience
	if opts.badKBJWTAud != "" {
		aud = opts.badKBJWTAud
	}
	nonce := opts.nonce
	if opts.badKBJWTNonce != "" {
		nonce = opts.badKBJWTNonce
	}

	kbBuilder := jwt.NewBuilder().
		Audience([]string{aud}).
		IssuedAt(now).
		Claim("nonce", nonce).
		Claim("sd_hash", sdHash)
	kbToken, err := kbBuilder.Build()
	if err != nil {
		t.Fatal(err)
	}
	kbHeaders := jws.NewHeaders()
	if err := kbHeaders.Set(jws.TypeKey, "kb+jwt"); err != nil {
		t.Fatal(err)
	}
	kbSigned, err := jwt.Sign(kbToken, jwt.WithKey(jwa.ES256(), opts.holderPrivKey, jws.WithProtectedHeaders(kbHeaders)))
	if err != nil {
		t.Fatal(err)
	}

	return string(sb) + string(kbSigned)
}

// tampeMatch is a tiny helper so the zero-value ("") tamperClaim never
// accidentally matches a disclosure whose own claim name is empty.
func (o sdJWTPresentationOpts) tampeMatch(name string) string {
	if name == "" {
		return "\x00unused\x00"
	}
	return name
}
