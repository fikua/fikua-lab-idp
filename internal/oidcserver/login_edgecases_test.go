package oidcserver

import (
	"net/http"
	"testing"
)

func TestLoginServeHTTPMissingID(t *testing.T) {
	b := newTestBridge(t)
	resp, err := http.Get(b.srv.URL + LoginPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestLoginServeHTTPUnknownID(t *testing.T) {
	b := newTestBridge(t)
	resp, err := http.Get(b.srv.URL + LoginPath + "?id=does-not-exist")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestLoginServeHTTPAlreadyDoneRedirects(t *testing.T) {
	b := newTestBridge(t)
	authRequestID, _ := startAuthorize(t, b)

	ar, ok := b.storage.internalStore().getAuthRequest(authRequestID)
	if !ok {
		t.Fatal("expected the AuthRequest to exist")
	}
	ar.subject = "already-done-subject"

	resp, err := noRedirectClient().Get(b.srv.URL + LoginPath + "?id=" + authRequestID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302 (straight to callback, no second verification session)", resp.StatusCode)
	}
}

func TestPollHandlerUnknownID(t *testing.T) {
	b := newTestBridge(t)
	resp, err := http.Get(b.srv.URL + LoginPath + "/poll?id=does-not-exist")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestPollHandlerPendingBeforeLoginPageLoad(t *testing.T) {
	b := newTestBridge(t)
	authRequestID, _ := startAuthorize(t, b)

	// Polling before the login page's first load (which is what actually
	// starts the OID4VP session) must report "pending", not fail.
	resp, err := http.Get(b.srv.URL + LoginPath + "/poll?id=" + authRequestID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestPollHandlerVerificationFailed(t *testing.T) {
	b := newTestBridge(t)
	authRequestID, _ := startAuthorize(t, b)

	loginResp, err := http.Get(b.srv.URL + LoginPath + "?id=" + authRequestID)
	if err != nil {
		t.Fatal(err)
	}
	loginResp.Body.Close()

	sessID, ok := b.storage.internalStore().getVerificationSession(authRequestID)
	if !ok {
		t.Fatal("expected a verification session to exist")
	}
	b.sessions.UpdateVerificationResult(sessID, "failed", nil, nil, "", "bad signature")

	resp, err := http.Get(b.srv.URL + LoginPath + "/poll?id=" + authRequestID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (a failed verification is still a successful poll)", resp.StatusCode)
	}
}

// TestPollHandlerVerifiedWithNoSubjectID covers PollHandler's own
// defensive check: a "verified" status with an empty SubjectID should
// never happen (internal/verifier always derives one on success), but if
// it somehow did, this bridge must refuse to complete the AuthRequest
// rather than mint an ID Token for an empty subject.
func TestPollHandlerVerifiedWithNoSubjectID(t *testing.T) {
	b := newTestBridge(t)
	authRequestID, _ := startAuthorize(t, b)

	loginResp, err := http.Get(b.srv.URL + LoginPath + "?id=" + authRequestID)
	if err != nil {
		t.Fatal(err)
	}
	loginResp.Body.Close()

	sessID, ok := b.storage.internalStore().getVerificationSession(authRequestID)
	if !ok {
		t.Fatal("expected a verification session to exist")
	}
	b.sessions.UpdateVerificationResult(sessID, "verified", map[string]string{"requested_credential": "vp"}, map[string]map[string]any{}, "", "")

	resp, err := http.Get(b.srv.URL + LoginPath + "/poll?id=" + authRequestID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	ar, _ := b.storage.internalStore().getAuthRequest(authRequestID)
	if ar.Done() {
		t.Error("an AuthRequest must not be completed from a verified result with an empty SubjectID")
	}
}
