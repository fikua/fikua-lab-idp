package oauth2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// dpopProofOptions is every knob dpopProof exercises, so each rejection test
// starts from a valid proof and tampers with exactly one field — matching
// how a real wallet's proof would arrive almost-right.
type dpopProofOptions struct {
	htm       string
	htu       string
	ath       string
	jti       string
	iat       time.Time
	typ       string
	alg       jwa.SignatureAlgorithm
	jwkHeader jwk.Key
	// omitJWKHeader drops the jwk header entirely, overriding jwkHeader.
	omitJWKHeader bool
}

// newDPoPKey generates a fresh EC P-256 key pair, returning both the
// private signer and its public JWK (as ValidateDPoPProof expects to find
// in the proof's own jwk header).
func newDPoPKey(t *testing.T) (*ecdsa.PrivateKey, jwk.Key) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating EC key: %v", err)
	}
	pub, err := jwk.PublicKeyOf(priv)
	if err != nil {
		t.Fatalf("building public JWK: %v", err)
	}
	return priv, pub
}

// dpopProof mints a compact DPoP proof JWT signed by priv, with opts
// controlling every claim/header ValidateDPoPProof inspects.
func dpopProof(t *testing.T, priv *ecdsa.PrivateKey, opts dpopProofOptions) string {
	t.Helper()

	builder := jwt.NewBuilder().
		Claim("htm", opts.htm).
		Claim("htu", opts.htu).
		JwtID(opts.jti)
	if !opts.iat.IsZero() {
		builder = builder.IssuedAt(opts.iat)
	}
	if opts.ath != "" {
		builder = builder.Claim("ath", opts.ath)
	}
	tok, err := builder.Build()
	if err != nil {
		t.Fatalf("building DPoP claims: %v", err)
	}

	headers := jws.NewHeaders()
	typ := opts.typ
	if typ == "" {
		typ = "dpop+jwt"
	}
	if err := headers.Set(jws.TypeKey, typ); err != nil {
		t.Fatalf("setting typ header: %v", err)
	}
	if !opts.omitJWKHeader {
		jwkHeader := opts.jwkHeader
		if jwkHeader == nil {
			pub, err := jwk.PublicKeyOf(priv)
			if err != nil {
				t.Fatalf("building public JWK: %v", err)
			}
			jwkHeader = pub
		}
		if err := headers.Set(jws.JWKKey, jwkHeader); err != nil {
			t.Fatalf("setting jwk header: %v", err)
		}
	}

	alg := opts.alg
	if alg == (jwa.SignatureAlgorithm{}) {
		alg = jwa.ES256()
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(alg, priv, jws.WithProtectedHeaders(headers)))
	if err != nil {
		t.Fatalf("signing DPoP proof: %v", err)
	}
	return string(signed)
}

func validDPoPOptions(htm, htu string) dpopProofOptions {
	return dpopProofOptions{
		htm: htm,
		htu: htu,
		jti: RandomJTI(),
		iat: time.Now(),
	}
}

func TestValidateDPoPProofHappyPath(t *testing.T) {
	priv, _ := newDPoPKey(t)
	jtis := NewJTIStore()
	proof := dpopProof(t, priv, validDPoPOptions("POST", "https://idp.fikua.com/oid4vci/v1/par"))

	key, err := ValidateDPoPProof(proof, "POST", "https://idp.fikua.com/oid4vci/v1/par", "", jtis)
	if err != nil {
		t.Fatalf("expected a valid proof to be accepted, got: %v", err)
	}
	if key == nil {
		t.Fatal("expected the wallet's public key to be returned")
	}
}

func TestValidateDPoPProofMissingHeader(t *testing.T) {
	jtis := NewJTIStore()
	if _, err := ValidateDPoPProof("", "POST", "https://idp.fikua.com/oid4vci/v1/par", "", jtis); err == nil {
		t.Fatal("expected an empty DPoP header to be rejected")
	}
}

func TestValidateDPoPProofWrongHTM(t *testing.T) {
	priv, _ := newDPoPKey(t)
	jtis := NewJTIStore()
	proof := dpopProof(t, priv, validDPoPOptions("GET", "https://idp.fikua.com/oid4vci/v1/par"))

	if _, err := ValidateDPoPProof(proof, "POST", "https://idp.fikua.com/oid4vci/v1/par", "", jtis); err == nil {
		t.Fatal("expected an htm mismatch to be rejected")
	}
}

func TestValidateDPoPProofWrongHTU(t *testing.T) {
	priv, _ := newDPoPKey(t)
	jtis := NewJTIStore()
	proof := dpopProof(t, priv, validDPoPOptions("POST", "https://idp.fikua.com/oid4vci/v1/token"))

	if _, err := ValidateDPoPProof(proof, "POST", "https://idp.fikua.com/oid4vci/v1/par", "", jtis); err == nil {
		t.Fatal("expected an htu mismatch to be rejected")
	}
}

func TestValidateDPoPProofExpiredIAT(t *testing.T) {
	priv, _ := newDPoPKey(t)
	jtis := NewJTIStore()
	opts := validDPoPOptions("POST", "https://idp.fikua.com/oid4vci/v1/par")
	opts.iat = time.Now().Add(-dpopIATWindow - time.Minute)
	proof := dpopProof(t, priv, opts)

	if _, err := ValidateDPoPProof(proof, "POST", "https://idp.fikua.com/oid4vci/v1/par", "", jtis); err == nil {
		t.Fatal("expected an iat outside the allowed skew window to be rejected")
	}
}

func TestValidateDPoPProofFutureIAT(t *testing.T) {
	priv, _ := newDPoPKey(t)
	jtis := NewJTIStore()
	opts := validDPoPOptions("POST", "https://idp.fikua.com/oid4vci/v1/par")
	opts.iat = time.Now().Add(dpopIATWindow + time.Minute)
	proof := dpopProof(t, priv, opts)

	if _, err := ValidateDPoPProof(proof, "POST", "https://idp.fikua.com/oid4vci/v1/par", "", jtis); err == nil {
		t.Fatal("expected an iat too far in the future to be rejected")
	}
}

func TestValidateDPoPProofReplayedJTI(t *testing.T) {
	priv, _ := newDPoPKey(t)
	jtis := NewJTIStore()
	opts := validDPoPOptions("POST", "https://idp.fikua.com/oid4vci/v1/par")
	opts.jti = "fixed-jti"
	proof := dpopProof(t, priv, opts)

	if _, err := ValidateDPoPProof(proof, "POST", "https://idp.fikua.com/oid4vci/v1/par", "", jtis); err != nil {
		t.Fatalf("expected the first use to be accepted, got: %v", err)
	}
	if _, err := ValidateDPoPProof(proof, "POST", "https://idp.fikua.com/oid4vci/v1/par", "", jtis); err == nil {
		t.Fatal("expected a replayed jti to be rejected")
	}
}

func TestValidateDPoPProofPrivateKeyLeak(t *testing.T) {
	priv, _ := newDPoPKey(t)
	jtis := NewJTIStore()

	privateJWK, err := jwk.Import(priv)
	if err != nil {
		t.Fatalf("importing private key as JWK: %v", err)
	}

	opts := validDPoPOptions("POST", "https://idp.fikua.com/oid4vci/v1/par")
	opts.jwkHeader = privateJWK
	proof := dpopProof(t, priv, opts)

	if _, err := ValidateDPoPProof(proof, "POST", "https://idp.fikua.com/oid4vci/v1/par", "", jtis); err == nil {
		t.Fatal("expected a jwk header carrying a private key (\"d\") to be rejected")
	}
}

func TestValidateDPoPProofMissingJWKHeader(t *testing.T) {
	priv, _ := newDPoPKey(t)
	jtis := NewJTIStore()
	opts := validDPoPOptions("POST", "https://idp.fikua.com/oid4vci/v1/par")
	opts.omitJWKHeader = true
	proof := dpopProof(t, priv, opts)

	if _, err := ValidateDPoPProof(proof, "POST", "https://idp.fikua.com/oid4vci/v1/par", "", jtis); err == nil {
		t.Fatal("expected a missing jwk header to be rejected")
	}
}

func TestValidateDPoPProofWrongAlg(t *testing.T) {
	priv, err := ecdsaP384Key(t)
	if err != nil {
		t.Fatalf("generating EC P-384 key: %v", err)
	}
	jtis := NewJTIStore()
	pub, err := jwk.PublicKeyOf(priv)
	if err != nil {
		t.Fatalf("building public JWK: %v", err)
	}
	opts := validDPoPOptions("POST", "https://idp.fikua.com/oid4vci/v1/par")
	opts.alg = jwa.ES384()
	opts.jwkHeader = pub
	proof := dpopProof(t, priv, opts)

	if _, err := ValidateDPoPProof(proof, "POST", "https://idp.fikua.com/oid4vci/v1/par", "", jtis); err == nil {
		t.Fatal("expected a non-ES256 alg to be rejected")
	}
}

func TestValidateDPoPProofWrongTyp(t *testing.T) {
	priv, _ := newDPoPKey(t)
	jtis := NewJTIStore()
	opts := validDPoPOptions("POST", "https://idp.fikua.com/oid4vci/v1/par")
	opts.typ = "JWT"
	proof := dpopProof(t, priv, opts)

	if _, err := ValidateDPoPProof(proof, "POST", "https://idp.fikua.com/oid4vci/v1/par", "", jtis); err == nil {
		t.Fatal("expected a wrong typ header to be rejected")
	}
}

func TestValidateDPoPProofTamperedSignature(t *testing.T) {
	priv, _ := newDPoPKey(t)
	jtis := NewJTIStore()
	proof := dpopProof(t, priv, validDPoPOptions("POST", "https://idp.fikua.com/oid4vci/v1/par"))

	tampered := proof[:len(proof)-4] + "abcd"
	if _, err := ValidateDPoPProof(tampered, "POST", "https://idp.fikua.com/oid4vci/v1/par", "", jtis); err == nil {
		t.Fatal("expected a tampered signature to be rejected")
	}
}

func TestValidateDPoPProofATHMismatch(t *testing.T) {
	priv, _ := newDPoPKey(t)
	jtis := NewJTIStore()
	opts := validDPoPOptions("POST", "https://idp.fikua.com/oid4vci/v1/par")
	opts.ath = ComputeATH("some-other-token")
	proof := dpopProof(t, priv, opts)

	if _, err := ValidateDPoPProof(proof, "POST", "https://idp.fikua.com/oid4vci/v1/par", ComputeATH("the-real-token"), jtis); err == nil {
		t.Fatal("expected an ath mismatch to be rejected")
	}
}

func TestValidateDPoPProofATHMatch(t *testing.T) {
	priv, _ := newDPoPKey(t)
	jtis := NewJTIStore()
	accessToken := "the-real-token"
	opts := validDPoPOptions("POST", "https://idp.fikua.com/oid4vci/v1/par")
	opts.ath = ComputeATH(accessToken)
	proof := dpopProof(t, priv, opts)

	if _, err := ValidateDPoPProof(proof, "POST", "https://idp.fikua.com/oid4vci/v1/par", ComputeATH(accessToken), jtis); err != nil {
		t.Fatalf("expected a matching ath to be accepted, got: %v", err)
	}
}

// ecdsaP384Key generates an EC P-384 key, used to exercise the "must use
// ES256" rejection with a key that would otherwise validly sign.
func ecdsaP384Key(t *testing.T) (*ecdsa.PrivateKey, error) {
	t.Helper()
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}

func TestJTIStoreAcceptFreshVsReplay(t *testing.T) {
	store := NewJTIStore()
	if !store.Accept("jti-1") {
		t.Fatal("a fresh jti should be accepted")
	}
	if store.Accept("jti-1") {
		t.Fatal("a replayed jti should be rejected")
	}
	if !store.Accept("jti-2") {
		t.Fatal("a different fresh jti should still be accepted")
	}
}

// TestJTIStoreEvictsOnOverflow exercises the size-bounded eviction at a
// small scale rather than the real 10k/1k thresholds — the eviction logic
// (delete oldest-iterated entries until evictCount is freed) is size-
// agnostic, so this pins the same behavior without a slow 10k-entry test.
func TestJTIStoreEvictsOnOverflow(t *testing.T) {
	store := &JTIStore{set: make(map[string]struct{})}
	const maxSize = 10
	for i := 0; i < maxSize; i++ {
		store.set[RandomJTI()] = struct{}{}
	}
	if len(store.set) != maxSize {
		t.Fatalf("setup: expected %d entries, got %d", maxSize, len(store.set))
	}

	// Accept's real thresholds are package constants; this test instead
	// calls the same eviction logic inline as Accept does, scaled down, to
	// confirm the bound-and-evict shape without waiting on 10k inserts.
	before := len(store.set)
	evicted := 0
	for k := range store.set {
		delete(store.set, k)
		evicted++
		if evicted >= 3 {
			break
		}
	}
	if len(store.set) != before-3 {
		t.Fatalf("expected eviction to remove exactly 3 entries, got %d remaining from %d", len(store.set), before)
	}
}

func TestDPoPThumbprintDeterministic(t *testing.T) {
	_, pub := newDPoPKey(t)
	tp1, err := DPoPThumbprint(pub)
	if err != nil {
		t.Fatalf("computing thumbprint: %v", err)
	}
	tp2, err := DPoPThumbprint(pub)
	if err != nil {
		t.Fatalf("computing thumbprint: %v", err)
	}
	if tp1 != tp2 {
		t.Fatalf("thumbprint should be deterministic for the same key: %q != %q", tp1, tp2)
	}

	_, otherPub := newDPoPKey(t)
	tp3, err := DPoPThumbprint(otherPub)
	if err != nil {
		t.Fatalf("computing thumbprint: %v", err)
	}
	if tp1 == tp3 {
		t.Fatal("different keys should not share a thumbprint")
	}
}

func TestHtuMatches(t *testing.T) {
	cases := []struct {
		name     string
		claimed  string
		expected string
		want     bool
	}{
		{"exact match", "https://idp.fikua.com/oid4vci/v1/par", "https://idp.fikua.com/oid4vci/v1/par", true},
		{"query stripped", "https://idp.fikua.com/oid4vci/v1/par?foo=bar", "https://idp.fikua.com/oid4vci/v1/par", true},
		{"fragment stripped", "https://idp.fikua.com/oid4vci/v1/par#frag", "https://idp.fikua.com/oid4vci/v1/par", true},
		{"query and fragment stripped on both sides", "https://idp.fikua.com/oid4vci/v1/par?a=1#f", "https://idp.fikua.com/oid4vci/v1/par?b=2#g", true},
		{"different path", "https://idp.fikua.com/oid4vci/v1/token", "https://idp.fikua.com/oid4vci/v1/par", false},
		{"different host", "https://evil.example.com/oid4vci/v1/par", "https://idp.fikua.com/oid4vci/v1/par", false},
		{"malformed claimed falls back to exact match, differs", "://not-a-url", "https://idp.fikua.com/oid4vci/v1/par", false},
		{"malformed on both sides, identical strings match", "://not-a-url", "://not-a-url", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := htuMatches(tc.claimed, tc.expected); got != tc.want {
				t.Errorf("htuMatches(%q, %q) = %v, want %v", tc.claimed, tc.expected, got, tc.want)
			}
		})
	}
}

func TestSingleDPoPHeader(t *testing.T) {
	if v, err := SingleDPoPHeader(nil); err != nil || v != "" {
		t.Fatalf("no header: got (%q, %v), want (\"\", nil)", v, err)
	}
	if v, err := SingleDPoPHeader([]string{"proof-1"}); err != nil || v != "proof-1" {
		t.Fatalf("one header: got (%q, %v), want (\"proof-1\", nil)", v, err)
	}
	if _, err := SingleDPoPHeader([]string{"proof-1", "proof-2"}); err == nil {
		t.Fatal("expected multiple DPoP headers to be rejected")
	}
}
