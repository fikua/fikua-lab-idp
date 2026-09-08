package crypto

import "testing"

// TestNewTestSigningKey exercises this file's own constructors directly
// — every other package that calls NewTestSigningKey/
// NewTestRequestSigningKey does so as test *infrastructure*, not to
// verify these functions themselves, so this is the one place their own
// correctness (and every branch of mustNoError's happy path) actually
// gets covered.
func TestNewTestSigningKey(t *testing.T) {
	key := NewTestSigningKey(t)
	if key == nil {
		t.Fatal("NewTestSigningKey returned nil")
	}
	if key.KID() == "" {
		t.Error("expected a non-empty key id")
	}
	if key.Signer() == nil {
		t.Error("expected a non-nil Signer")
	}
}

func TestNewTestSigningKeyProducesDistinctKeys(t *testing.T) {
	a := NewTestSigningKey(t)
	b := NewTestSigningKey(t)
	if a.KID() == b.KID() {
		t.Error("two calls to NewTestSigningKey must not produce the same key")
	}
}

func TestNewTestRequestSigningKey(t *testing.T) {
	key := NewTestRequestSigningKey(t)
	if key == nil {
		t.Fatal("NewTestRequestSigningKey returned nil")
	}
	if len(key.LeafDER()) == 0 {
		t.Error("expected a non-empty leaf certificate")
	}
	if key.KID() == "" {
		t.Error("expected a non-empty key id")
	}
}

func TestNewTestRequestSigningKeyProducesDistinctKeys(t *testing.T) {
	a := NewTestRequestSigningKey(t)
	b := NewTestRequestSigningKey(t)
	if a.KID() == b.KID() {
		t.Error("two calls to NewTestRequestSigningKey must not produce the same key")
	}
}

func TestGenerateTestECKey(t *testing.T) {
	priv := generateTestECKey(t)
	if priv == nil {
		t.Fatal("generateTestECKey returned nil")
	}
	if priv.Curve.Params().Name != "P-256" {
		t.Errorf("curve = %s, want P-256", priv.Curve.Params().Name)
	}
}

// fakeT is a minimal tHelper that records whether Fatal was called,
// instead of actually failing the enclosing test — used to exercise
// mustNoError's error branch, which no real error path in this package
// otherwise reaches (ecdsa.GenerateKey, x509 marshaling, and
// os.WriteFile against a fresh temp dir do not fail under normal test
// conditions).
type fakeT struct {
	fataled bool
}

func (f *fakeT) Helper()           {}
func (f *fakeT) Fatal(args ...any) { f.fataled = true }

func TestMustNoErrorFatalsOnError(t *testing.T) {
	f := &fakeT{}
	mustNoError(f, errTest)
	if !f.fataled {
		t.Error("mustNoError should have called Fatal for a non-nil error")
	}
}

func TestMustNoErrorNoOpOnSuccess(t *testing.T) {
	f := &fakeT{}
	mustNoError(f, nil)
	if f.fataled {
		t.Error("mustNoError should not call Fatal for a nil error")
	}
}

var errTest = fakeError("test error")

type fakeError string

func (e fakeError) Error() string { return string(e) }
