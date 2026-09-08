package oidcserver

import "testing"

func TestAuthRequestLifecycle(t *testing.T) {
	s := newStore()
	ar := &authRequest{id: "ar-1", clientID: "client-1"}
	s.putAuthRequest(ar)

	got, ok := s.getAuthRequest("ar-1")
	if !ok || got.id != "ar-1" {
		t.Fatalf("getAuthRequest = %+v, %v", got, ok)
	}

	if _, ok := s.getAuthRequest("unknown"); ok {
		t.Error("getAuthRequest should not find an unregistered id")
	}

	s.deleteAuthRequest("ar-1")
	if _, ok := s.getAuthRequest("ar-1"); ok {
		t.Error("getAuthRequest should not find a deleted AuthRequest")
	}
}

func TestVerificationSessionLinking(t *testing.T) {
	s := newStore()
	ar := &authRequest{id: "ar-1", clientID: "client-1"}
	s.putAuthRequest(ar)

	if _, ok := s.getVerificationSession("ar-1"); ok {
		t.Error("no verification session should be linked yet")
	}

	s.linkVerificationSession("ar-1", "vsess-1")
	got, ok := s.getVerificationSession("ar-1")
	if !ok || got != "vsess-1" {
		t.Fatalf("getVerificationSession = %q, %v", got, ok)
	}

	// Linking against an unknown AuthRequest ID must not panic and must
	// not create a phantom entry.
	s.linkVerificationSession("does-not-exist", "vsess-2")
	if _, ok := s.getVerificationSession("does-not-exist"); ok {
		t.Error("linking against an unknown AuthRequest must not create an entry")
	}
}

func TestAuthCodeLifecycle(t *testing.T) {
	s := newStore()
	s.putAuthCode("code-1", "ar-1")

	id, ok := s.consumeAuthCode("code-1")
	if !ok || id != "ar-1" {
		t.Fatalf("consumeAuthCode = %q, %v", id, ok)
	}

	// Single-use: a second consume of the same code must fail (RFC 6749
	// §4.1.2 — a code must not be usable twice).
	if _, ok := s.consumeAuthCode("code-1"); ok {
		t.Error("consumeAuthCode must not accept a code twice")
	}

	if _, ok := s.consumeAuthCode("never-issued"); ok {
		t.Error("consumeAuthCode must reject an unknown code")
	}
}

func TestRefreshTokenLifecycle(t *testing.T) {
	s := newStore()
	s.putRefreshToken("rt-1", "subject-1", "client-1", []string{"openid", "offline_access"})

	entry, ok := s.getRefreshToken("rt-1")
	if !ok || entry.subject != "subject-1" || entry.clientID != "client-1" {
		t.Fatalf("getRefreshToken = %+v, %v", entry, ok)
	}
	if len(entry.scopes) != 2 {
		t.Errorf("scopes = %v", entry.scopes)
	}

	s.deleteRefreshToken("rt-1")
	if _, ok := s.getRefreshToken("rt-1"); ok {
		t.Error("getRefreshToken should not find a deleted token")
	}

	if _, ok := s.getRefreshToken("never-issued"); ok {
		t.Error("getRefreshToken must reject an unknown token")
	}
}

func TestRandomTokenIsNonEmptyAndUnique(t *testing.T) {
	a := randomToken(16)
	b := randomToken(16)
	if a == "" || b == "" {
		t.Fatal("randomToken must not return an empty string")
	}
	if a == b {
		t.Error("two calls to randomToken must not collide")
	}
}
