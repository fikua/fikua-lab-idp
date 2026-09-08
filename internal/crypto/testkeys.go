package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// tHelper is the subset of *testing.T this file needs. Defined locally
// rather than importing "testing" so this file can live outside a
// _test.go — it is meant to be called FROM other packages' tests (see
// NewTestSigningKey/NewTestRequestSigningKey's own doc comments on why
// duplicating key-generation boilerplate per test package was the
// problem this exists to fix), which a _test.go file cannot be imported
// across package boundaries to do.
type tHelper interface {
	Helper()
	Fatal(args ...any)
}

// NewTestSigningKey builds a *SigningKey backed by a fresh EC P-256 key
// written to a temp dir — the only way LoadFromPEM constructs one (see
// its own doc comment on why there is no in-memory constructor:
// production deliberately has no ephemeral-key fallback, so tests go
// through the same file-loading path rather than a separate code path
// that could drift from it). Shared by internal/httpapi and
// internal/oidcserver's test suites, which both need an AS signing key
// with no real production key material.
func NewTestSigningKey(t tHelper) *SigningKey {
	t.Helper()
	dir, err := os.MkdirTemp("", "fikua-test-signingkey-*")
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, "idp-key.pem"), pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := LoadFromPEM(dir)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// NewTestRequestSigningKey builds a *RequestSigningKey backed by a fresh
// in-memory ECDSA P-256 key and a self-signed leaf certificate — the
// Verifier's Algorithm() is fixed at ES256 (ECDSA/P-256/SHA-256), so this
// is the only key shape it accepts. Stands in for the DSS-issued key
// every real deployment uses (see RequestSigningKey's own doc comment on
// why there is no local-PEM alternative in production). Shared by
// internal/httpapi and internal/oidcserver's test suites, both of which
// need a Verifier request-signing key with no real DSS involved.
func NewTestRequestSigningKey(t tHelper) *RequestSigningKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-verifier"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewRequestSigningKey(priv, [][]byte{der})
	if err != nil {
		t.Fatal(err)
	}
	return key
}
