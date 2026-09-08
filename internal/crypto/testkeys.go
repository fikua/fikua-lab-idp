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

// mustNoError fails t immediately if err is non-nil — every step in this
// file's two constructors is one of these, so factoring the check out
// (rather than repeating `if err != nil { t.Fatal(err) }` at each step)
// is what keeps NewTestSigningKey and NewTestRequestSigningKey from
// looking like near-duplicates of each other despite building different
// key types.
func mustNoError(t tHelper, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// generateTestECKey generates a fresh EC P-256 key — the one property
// both constructors below need in common, and the only step that would
// otherwise be duplicated between them.
func generateTestECKey(t tHelper) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mustNoError(t, err)
	return priv
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
	priv := generateTestECKey(t)

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	mustNoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	dir, err := os.MkdirTemp("", "fikua-test-signingkey-*")
	mustNoError(t, err)
	mustNoError(t, os.WriteFile(filepath.Join(dir, "idp-key.pem"), pemBytes, 0o600))

	key, err := LoadFromPEM(dir)
	mustNoError(t, err)
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
	priv := generateTestECKey(t)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-verifier"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	mustNoError(t, err)

	key, err := NewRequestSigningKey(priv, [][]byte{der})
	mustNoError(t, err)
	return key
}
