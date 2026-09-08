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

const testAudience = "https://idp.fikua.com"

// wiaOptions controls every WIA claim/header the tests tamper with, one
// field at a time, starting from a valid attestation.
type wiaOptions struct {
	clientID   string
	expiration time.Time
	cnfJWK     jwk.Key
	cnfJKT     string
	// omitCnf drops the cnf claim entirely.
	omitCnf bool
}

// popOptions controls every PoP claim the tests tamper with.
type popOptions struct {
	audience   []string
	issuedAt   time.Time
	expiration time.Time
}

// signCompact builds+signs tok with signingKey (ES256), embedding pubJWK in
// the protected header's jwk field so ClientAttestationValidator can
// recover the verification key from the header (the no-x5c fallback path
// in resolveWiaKey).
func signCompact(t *testing.T, tok jwt.Token, signingKey *ecdsa.PrivateKey, pubJWK jwk.Key) string {
	t.Helper()
	headers := jws.NewHeaders()
	if pubJWK != nil {
		if err := headers.Set(jws.JWKKey, pubJWK); err != nil {
			t.Fatalf("setting jwk header: %v", err)
		}
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), signingKey, jws.WithProtectedHeaders(headers)))
	if err != nil {
		t.Fatalf("signing JWT: %v", err)
	}
	return string(signed)
}

// mintWIA builds a self-signed Wallet Instance Attestation JWT: signingKey
// signs it, and its own public key rides in the header's jwk field (the
// "no x5c" fallback in resolveWiaKey), so no CA chain is required to
// validate it.
func mintWIA(t *testing.T, signingKey *ecdsa.PrivateKey, opts wiaOptions) string {
	t.Helper()
	pub, err := jwk.PublicKeyOf(signingKey)
	if err != nil {
		t.Fatalf("building public JWK: %v", err)
	}

	exp := opts.expiration
	if exp.IsZero() {
		exp = time.Now().Add(time.Hour)
	}
	clientID := opts.clientID
	if clientID == "" {
		clientID = "wallet-client-1"
	}

	builder := jwt.NewBuilder().
		Subject(clientID).
		IssuedAt(time.Now()).
		Expiration(exp)

	if !opts.omitCnf {
		cnf := map[string]any{}
		switch {
		case opts.cnfJWK != nil:
			cnf["jwk"] = opts.cnfJWK
		case opts.cnfJKT != "":
			cnf["jkt"] = opts.cnfJKT
		}
		builder = builder.Claim("cnf", cnf)
	}

	tok, err := builder.Build()
	if err != nil {
		t.Fatalf("building WIA claims: %v", err)
	}
	return signCompact(t, tok, signingKey, pub)
}

// mintPoP builds a Proof-of-Possession JWT signed by cnfKey (the key the
// WIA's cnf claim binds), with cnfKey's own public JWK in the header so a
// cnf.jkt-based WIA can resolve it.
func mintPoP(t *testing.T, cnfKey *ecdsa.PrivateKey, opts popOptions) string {
	t.Helper()
	pub, err := jwk.PublicKeyOf(cnfKey)
	if err != nil {
		t.Fatalf("building public JWK: %v", err)
	}

	iat := opts.issuedAt
	if iat.IsZero() {
		iat = time.Now()
	}
	exp := opts.expiration
	if exp.IsZero() {
		exp = time.Now().Add(time.Hour)
	}
	aud := opts.audience
	if aud == nil {
		aud = []string{testAudience}
	}

	tok, err := jwt.NewBuilder().
		Audience(aud).
		IssuedAt(iat).
		Expiration(exp).
		JwtID(RandomJTI()).
		Build()
	if err != nil {
		t.Fatalf("building PoP claims: %v", err)
	}
	return signCompact(t, tok, cnfKey, pub)
}

func newECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating EC key: %v", err)
	}
	return priv
}

func TestClientAttestationValidateHeadersHappyPathCnfJWK(t *testing.T) {
	walletKey := newECKey(t)
	cnfKey := newECKey(t)
	cnfPub, err := jwk.PublicKeyOf(cnfKey)
	if err != nil {
		t.Fatalf("building cnf public JWK: %v", err)
	}

	wia := mintWIA(t, walletKey, wiaOptions{clientID: "wallet-client-1", cnfJWK: cnfPub})
	pop := mintPoP(t, cnfKey, popOptions{})

	v := NewClientAttestationValidator(nil, testAudience)
	clientID, err := v.ValidateHeaders(wia, pop)
	if err != nil {
		t.Fatalf("expected a valid WIA+PoP to be accepted, got: %v", err)
	}
	if clientID != "wallet-client-1" {
		t.Fatalf("clientID = %q, want %q", clientID, "wallet-client-1")
	}
}

func TestClientAttestationValidateHeadersHappyPathCnfJKT(t *testing.T) {
	walletKey := newECKey(t)
	cnfKey := newECKey(t)
	cnfPub, err := jwk.PublicKeyOf(cnfKey)
	if err != nil {
		t.Fatalf("building cnf public JWK: %v", err)
	}
	jkt, err := DPoPThumbprint(cnfPub)
	if err != nil {
		t.Fatalf("computing thumbprint: %v", err)
	}

	wia := mintWIA(t, walletKey, wiaOptions{clientID: "wallet-client-1", cnfJKT: jkt})
	pop := mintPoP(t, cnfKey, popOptions{})

	v := NewClientAttestationValidator(nil, testAudience)
	clientID, err := v.ValidateHeaders(wia, pop)
	if err != nil {
		t.Fatalf("expected a valid WIA(cnf.jkt)+PoP to be accepted, got: %v", err)
	}
	if clientID != "wallet-client-1" {
		t.Fatalf("clientID = %q, want %q", clientID, "wallet-client-1")
	}
}

func TestClientAttestationValidateHeadersBothAbsent(t *testing.T) {
	v := NewClientAttestationValidator(nil, testAudience)
	clientID, err := v.ValidateHeaders("", "")
	if err != nil {
		t.Fatalf("expected no error when both headers are absent, got: %v", err)
	}
	if clientID != "" {
		t.Fatalf("clientID = %q, want empty", clientID)
	}
}

func TestClientAttestationValidateHeadersMissingWIA(t *testing.T) {
	v := NewClientAttestationValidator(nil, testAudience)
	if _, err := v.ValidateHeaders("", "some-pop"); err == nil {
		t.Fatal("expected a missing WIA (with PoP present) to be rejected")
	}
}

func TestClientAttestationValidateHeadersMissingPoP(t *testing.T) {
	v := NewClientAttestationValidator(nil, testAudience)
	if _, err := v.ValidateHeaders("some-wia", ""); err == nil {
		t.Fatal("expected a missing PoP (with WIA present) to be rejected")
	}
}

func TestClientAttestationExpiredWIA(t *testing.T) {
	walletKey := newECKey(t)
	cnfKey := newECKey(t)
	cnfPub, _ := jwk.PublicKeyOf(cnfKey)

	wia := mintWIA(t, walletKey, wiaOptions{cnfJWK: cnfPub, expiration: time.Now().Add(-time.Hour)})
	pop := mintPoP(t, cnfKey, popOptions{})

	v := NewClientAttestationValidator(nil, testAudience)
	if _, err := v.ValidateHeaders(wia, pop); err == nil {
		t.Fatal("expected an expired WIA to be rejected")
	}
}

func TestClientAttestationExpiredPoP(t *testing.T) {
	walletKey := newECKey(t)
	cnfKey := newECKey(t)
	cnfPub, _ := jwk.PublicKeyOf(cnfKey)

	wia := mintWIA(t, walletKey, wiaOptions{cnfJWK: cnfPub})
	pop := mintPoP(t, cnfKey, popOptions{expiration: time.Now().Add(-time.Hour)})

	v := NewClientAttestationValidator(nil, testAudience)
	if _, err := v.ValidateHeaders(wia, pop); err == nil {
		t.Fatal("expected an expired PoP to be rejected")
	}
}

func TestClientAttestationPoPIATTooOld(t *testing.T) {
	walletKey := newECKey(t)
	cnfKey := newECKey(t)
	cnfPub, _ := jwk.PublicKeyOf(cnfKey)

	wia := mintWIA(t, walletKey, wiaOptions{cnfJWK: cnfPub})
	pop := mintPoP(t, cnfKey, popOptions{issuedAt: time.Now().Add(-clientAttestationIATWindow - time.Minute)})

	v := NewClientAttestationValidator(nil, testAudience)
	if _, err := v.ValidateHeaders(wia, pop); err == nil {
		t.Fatal("expected a PoP with iat outside the allowed skew window to be rejected")
	}
}

func TestClientAttestationWrongAudience(t *testing.T) {
	walletKey := newECKey(t)
	cnfKey := newECKey(t)
	cnfPub, _ := jwk.PublicKeyOf(cnfKey)

	wia := mintWIA(t, walletKey, wiaOptions{cnfJWK: cnfPub})
	pop := mintPoP(t, cnfKey, popOptions{audience: []string{"https://someone-else.example.com"}})

	v := NewClientAttestationValidator(nil, testAudience)
	if _, err := v.ValidateHeaders(wia, pop); err == nil {
		t.Fatal("expected a PoP audience mismatch to be rejected")
	}
}

func TestClientAttestationTamperedWIASignature(t *testing.T) {
	walletKey := newECKey(t)
	cnfKey := newECKey(t)
	cnfPub, _ := jwk.PublicKeyOf(cnfKey)

	wia := mintWIA(t, walletKey, wiaOptions{cnfJWK: cnfPub})
	pop := mintPoP(t, cnfKey, popOptions{})

	tamperedWIA := wia[:len(wia)-4] + "abcd"

	v := NewClientAttestationValidator(nil, testAudience)
	if _, err := v.ValidateHeaders(tamperedWIA, pop); err == nil {
		t.Fatal("expected a tampered WIA signature to be rejected")
	}
}

func TestClientAttestationTamperedPoPSignature(t *testing.T) {
	walletKey := newECKey(t)
	cnfKey := newECKey(t)
	cnfPub, _ := jwk.PublicKeyOf(cnfKey)

	wia := mintWIA(t, walletKey, wiaOptions{cnfJWK: cnfPub})
	pop := mintPoP(t, cnfKey, popOptions{})

	tamperedPoP := pop[:len(pop)-4] + "abcd"

	v := NewClientAttestationValidator(nil, testAudience)
	if _, err := v.ValidateHeaders(wia, tamperedPoP); err == nil {
		t.Fatal("expected a tampered PoP signature to be rejected")
	}
}

func TestClientAttestationCnfJKTMismatch(t *testing.T) {
	walletKey := newECKey(t)
	cnfKey := newECKey(t)
	otherKey := newECKey(t)
	cnfPub, _ := jwk.PublicKeyOf(cnfKey)
	jkt, err := DPoPThumbprint(cnfPub)
	if err != nil {
		t.Fatalf("computing thumbprint: %v", err)
	}

	wia := mintWIA(t, walletKey, wiaOptions{cnfJKT: jkt})
	// Signed by a key whose thumbprint doesn't match the WIA's cnf.jkt.
	pop := mintPoP(t, otherKey, popOptions{})

	v := NewClientAttestationValidator(nil, testAudience)
	if _, err := v.ValidateHeaders(wia, pop); err == nil {
		t.Fatal("expected a PoP key thumbprint not matching cnf.jkt to be rejected")
	}
}

func TestClientAttestationMissingCnf(t *testing.T) {
	walletKey := newECKey(t)
	cnfKey := newECKey(t)

	wia := mintWIA(t, walletKey, wiaOptions{omitCnf: true})
	pop := mintPoP(t, cnfKey, popOptions{})

	v := NewClientAttestationValidator(nil, testAudience)
	if _, err := v.ValidateHeaders(wia, pop); err == nil {
		t.Fatal("expected a WIA with no cnf claim to be rejected")
	}
}

func TestClientAttestationValidateFormHappyPath(t *testing.T) {
	walletKey := newECKey(t)
	cnfKey := newECKey(t)
	cnfPub, _ := jwk.PublicKeyOf(cnfKey)

	wia := mintWIA(t, walletKey, wiaOptions{clientID: "wallet-client-1", cnfJWK: cnfPub})
	pop := mintPoP(t, cnfKey, popOptions{})

	v := NewClientAttestationValidator(nil, testAudience)
	clientID, err := v.ValidateForm(ClientAssertionType, wia+"~"+pop)
	if err != nil {
		t.Fatalf("expected a valid form assertion to be accepted, got: %v", err)
	}
	if clientID != "wallet-client-1" {
		t.Fatalf("clientID = %q, want %q", clientID, "wallet-client-1")
	}
}

func TestClientAttestationValidateFormBothAbsent(t *testing.T) {
	v := NewClientAttestationValidator(nil, testAudience)
	clientID, err := v.ValidateForm("", "")
	if err != nil {
		t.Fatalf("expected no error when both form fields are absent, got: %v", err)
	}
	if clientID != "" {
		t.Fatalf("clientID = %q, want empty", clientID)
	}
}

func TestClientAttestationValidateFormWrongAssertionType(t *testing.T) {
	v := NewClientAttestationValidator(nil, testAudience)
	if _, err := v.ValidateForm("urn:some:other:type", "wia~pop"); err == nil {
		t.Fatal("expected an unsupported client_assertion_type to be rejected")
	}
}

func TestClientAttestationValidateFormMalformedAssertion(t *testing.T) {
	v := NewClientAttestationValidator(nil, testAudience)
	if _, err := v.ValidateForm(ClientAssertionType, "not-two-parts"); err == nil {
		t.Fatal("expected a client_assertion with no '~' separator to be rejected")
	}
}

func TestClientAttestationResolvePrefersHeaders(t *testing.T) {
	walletKey := newECKey(t)
	cnfKey := newECKey(t)
	cnfPub, _ := jwk.PublicKeyOf(cnfKey)

	wia := mintWIA(t, walletKey, wiaOptions{clientID: "header-client", cnfJWK: cnfPub})
	pop := mintPoP(t, cnfKey, popOptions{})

	v := NewClientAttestationValidator(nil, testAudience)
	clientID, err := v.Resolve(wia, pop, "", "")
	if err != nil {
		t.Fatalf("expected header-based resolution to succeed, got: %v", err)
	}
	if clientID != "header-client" {
		t.Fatalf("clientID = %q, want %q", clientID, "header-client")
	}
}

func TestClientAttestationResolveFallsBackToForm(t *testing.T) {
	walletKey := newECKey(t)
	cnfKey := newECKey(t)
	cnfPub, _ := jwk.PublicKeyOf(cnfKey)

	wia := mintWIA(t, walletKey, wiaOptions{clientID: "form-client", cnfJWK: cnfPub})
	pop := mintPoP(t, cnfKey, popOptions{})

	v := NewClientAttestationValidator(nil, testAudience)
	clientID, err := v.Resolve("", "", ClientAssertionType, wia+"~"+pop)
	if err != nil {
		t.Fatalf("expected form-based resolution to succeed, got: %v", err)
	}
	if clientID != "form-client" {
		t.Fatalf("clientID = %q, want %q", clientID, "form-client")
	}
}
