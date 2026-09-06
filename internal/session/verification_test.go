package session

import (
	"testing"
	"time"
)

// TestVerificationSessionExpiry pins the lazy-expiry contract the OID4VP
// Verifier depends on: a session is usable up to verificationSessionTTL and
// indistinguishable from a nonexistent one after it, by id and by state
// alike, with the expired entry actually removed rather than left to
// accumulate.
//
// An in-package test because it has to age a session past the TTL, which
// means reaching CreatedAt — production code has no business exposing a
// setter for that, and no exported API can rewind a clock.
func TestVerificationSessionExpiry(t *testing.T) {
	store := NewStore()
	store.StoreVerification(VerificationSession{
		SessionID: "sess-1",
		State:     "state-1",
		Nonce:     "nonce-1",
		Status:    "pending",
	})

	if _, ok := store.FindVerification("sess-1"); !ok {
		t.Fatal("fresh session should be findable by id")
	}
	if _, ok := store.FindVerificationByState("state-1"); !ok {
		t.Fatal("fresh session should be findable by state")
	}

	// Just inside the TTL: still live.
	store.verifications["sess-1"].CreatedAt = time.Now().Add(-verificationSessionTTL + time.Second)
	if _, ok := store.FindVerification("sess-1"); !ok {
		t.Fatal("session just inside the TTL should still be live")
	}

	// Past the TTL: gone, by both lookup paths, and deleted from both maps.
	store.verifications["sess-1"].CreatedAt = time.Now().Add(-verificationSessionTTL - time.Second)
	if _, ok := store.FindVerification("sess-1"); ok {
		t.Fatal("expired session should not be findable by id")
	}
	if len(store.verifications) != 0 || len(store.verificationIDByState) != 0 {
		t.Fatalf("expired session should be deleted on read, got %d/%d entries",
			len(store.verifications), len(store.verificationIDByState))
	}
	if _, ok := store.FindVerificationByState("state-1"); ok {
		t.Fatal("expired session should not be findable by state")
	}
}

// TestVerificationUpdatesRespectExpiry checks the write path applies the
// same expiry as the read path — an expired session must not be revivable
// by an arriving response.
func TestVerificationUpdatesRespectExpiry(t *testing.T) {
	store := NewStore()
	store.StoreVerification(VerificationSession{SessionID: "sess-2", State: "state-2", Status: "pending"})

	store.UpdateVerificationStatus("sess-2", "request_sent")
	v, ok := store.FindVerification("sess-2")
	if !ok || v.Status != "request_sent" {
		t.Fatalf("status update not applied: ok=%v status=%q", ok, v.Status)
	}

	store.verifications["sess-2"].CreatedAt = time.Now().Add(-verificationSessionTTL - time.Second)
	store.UpdateVerificationResult("sess-2", "verified", "vp", map[string]any{"a": 1}, "")
	if _, ok := store.FindVerification("sess-2"); ok {
		t.Fatal("an update must not resurrect an expired session")
	}
}
