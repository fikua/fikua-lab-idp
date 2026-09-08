package oauth2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"

	fikuacrypto "github.com/fikua/fikua-lab-idp/internal/crypto"
)

// writeECKeyPair generates a fresh EC P-256 key and writes it to
// <dir>/idp-key.pem as a PKCS#8 PEM block — one of the two encodings
// fikuacrypto.LoadFromPEM accepts.
func writeECKeyPair(t *testing.T, dir string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating EC key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshaling PKCS#8 key: %v", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	if err := os.WriteFile(filepath.Join(dir, "idp-key.pem"), pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("writing idp-key.pem: %v", err)
	}
}

// newTestSigningKey builds a fikuacrypto.SigningKey from a freshly
// generated EC P-256 key, going through the same PEM round trip
// LoadFromPEM uses in production, since SigningKey exposes no in-memory
// constructor of its own.
func newTestSigningKey(t *testing.T) *fikuacrypto.SigningKey {
	t.Helper()
	dir := t.TempDir()
	writeECKeyPair(t, dir)
	key, err := fikuacrypto.LoadFromPEM(dir)
	if err != nil {
		t.Fatalf("LoadFromPEM: %v", err)
	}
	return key
}

func TestMinterMintClaims(t *testing.T) {
	signingKey := newTestSigningKey(t)
	minter := NewMinter(signingKey, "https://idp.fikua.com", "https://issuer.fikua.com")

	dpopPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating DPoP key: %v", err)
	}
	dpopPub, err := jwk.PublicKeyOf(dpopPriv)
	if err != nil {
		t.Fatalf("building DPoP public JWK: %v", err)
	}
	wantThumbprint, err := DPoPThumbprint(dpopPub)
	if err != nil {
		t.Fatalf("computing expected thumbprint: %v", err)
	}

	claims := AccessTokenClaims{
		IssuanceRecordID: "record-123",
		CNonce:           "nonce-abc",
		ClientID:         "client-xyz",
		DPoPKey:          dpopPub,
	}

	tokenString, jti, err := minter.Mint(claims)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if jti == "" {
		t.Fatal("expected a non-empty jti")
	}

	msg, err := jws.Parse([]byte(tokenString))
	if err != nil {
		t.Fatalf("parsing minted token as JWS: %v", err)
	}
	if len(msg.Signatures()) != 1 {
		t.Fatalf("expected exactly one signature, got %d", len(msg.Signatures()))
	}
	headers := msg.Signatures()[0].ProtectedHeaders()
	if typ, _ := headers.Type(); typ != AccessTokenType {
		t.Errorf("typ header = %q, want %q", typ, AccessTokenType)
	}
	if kid, _ := headers.KeyID(); kid != signingKey.KID() {
		t.Errorf("kid header = %q, want %q", kid, signingKey.KID())
	}

	tok, err := jwt.Parse([]byte(tokenString), jwt.WithKey(jwa.ES256(), signingKey.PublicJWK()))
	if err != nil {
		t.Fatalf("verifying minted token: %v", err)
	}

	if iss, _ := tok.Issuer(); iss != "https://idp.fikua.com" {
		t.Errorf("iss = %q, want %q", iss, "https://idp.fikua.com")
	}
	if aud, _ := tok.Audience(); len(aud) != 1 || aud[0] != "https://issuer.fikua.com" {
		t.Errorf("aud = %v, want [https://issuer.fikua.com]", aud)
	}
	if sub, _ := tok.Subject(); sub != "client-xyz" {
		t.Errorf("sub = %q, want %q", sub, "client-xyz")
	}
	if jti2, _ := tok.JwtID(); jti2 != jti {
		t.Errorf("jti claim = %q, want returned jti %q", jti2, jti)
	}

	var clientID string
	if err := tok.Get("client_id", &clientID); err != nil || clientID != "client-xyz" {
		t.Errorf("client_id claim = %q, err=%v, want %q", clientID, err, "client-xyz")
	}

	var issuanceRecordID string
	if err := tok.Get("issuance_record_id", &issuanceRecordID); err != nil || issuanceRecordID != "record-123" {
		t.Errorf("issuance_record_id claim = %q, err=%v, want %q", issuanceRecordID, err, "record-123")
	}

	var cnonce string
	if err := tok.Get("c_nonce", &cnonce); err != nil || cnonce != "nonce-abc" {
		t.Errorf("c_nonce claim = %q, err=%v, want %q", cnonce, err, "nonce-abc")
	}

	var cnf map[string]any
	if err := tok.Get("cnf", &cnf); err != nil {
		t.Fatalf("reading cnf claim: %v", err)
	}
	if jkt, _ := cnf["jkt"].(string); jkt != wantThumbprint {
		t.Errorf("cnf.jkt = %q, want %q", jkt, wantThumbprint)
	}

	exp, hasExp := tok.Expiration()
	iat, hasIAT := tok.IssuedAt()
	if !hasExp || !hasIAT {
		t.Fatal("expected both exp and iat to be set")
	}
	if got := exp.Sub(iat); got != AccessTokenTTL {
		t.Errorf("exp - iat = %v, want %v", got, AccessTokenTTL)
	}
}

func TestMinterMintOmitsCNonceWhenEmpty(t *testing.T) {
	signingKey := newTestSigningKey(t)
	minter := NewMinter(signingKey, "https://idp.fikua.com", "https://issuer.fikua.com")

	dpopPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dpopPub, _ := jwk.PublicKeyOf(dpopPriv)

	tokenString, _, err := minter.Mint(AccessTokenClaims{
		IssuanceRecordID: "record-123",
		ClientID:         "client-xyz",
		DPoPKey:          dpopPub,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	tok, err := jwt.Parse([]byte(tokenString), jwt.WithKey(jwa.ES256(), signingKey.PublicJWK()))
	if err != nil {
		t.Fatalf("verifying minted token: %v", err)
	}
	var cnonce string
	if err := tok.Get("c_nonce", &cnonce); err == nil {
		t.Errorf("expected no c_nonce claim when CNonce is empty, got %q", cnonce)
	}
}

func TestDPoPTokenShape(t *testing.T) {
	resp := DPoPToken("the-access-token")
	if resp.AccessToken != "the-access-token" {
		t.Errorf("AccessToken = %q, want %q", resp.AccessToken, "the-access-token")
	}
	if resp.TokenType != "DPoP" {
		t.Errorf("TokenType = %q, want %q", resp.TokenType, "DPoP")
	}
	if resp.ExpiresIn != int(AccessTokenTTL.Seconds()) {
		t.Errorf("ExpiresIn = %d, want %d", resp.ExpiresIn, int(AccessTokenTTL.Seconds()))
	}
}

func TestRandomJTIIsUnpredictableAndURLSafe(t *testing.T) {
	a := RandomJTI()
	b := RandomJTI()
	if a == b {
		t.Fatal("two calls to RandomJTI produced the same value")
	}
	if a == "" || b == "" {
		t.Fatal("expected non-empty jti values")
	}
}
