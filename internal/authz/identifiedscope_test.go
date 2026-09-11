package authz

import "testing"

func TestIdentifiedScope_UsesTheRequestsOwnScope(t *testing.T) {
	got, err := identifiedScope(map[string]string{"scope": "urn:fikua:padro:barcelona:1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "urn:fikua:padro:barcelona:1" {
		t.Errorf("got %q, want the request's own scope", got)
	}
}

func TestIdentifiedScope_FailsLoudlyWithNoFallback(t *testing.T) {
	// No fallback to a hardcoded credential: a request with no scope must
	// fail loudly, not silently identify the user for some other
	// credential (the exact bug this function exists to prevent — see its
	// own doc comment).
	_, err := identifiedScope(map[string]string{})
	if err == nil {
		t.Fatal("expected an error for a missing scope, got nil")
	}
}

func TestIdentifiedScope_EmptyScopeAlsoFails(t *testing.T) {
	_, err := identifiedScope(map[string]string{"scope": ""})
	if err == nil {
		t.Fatal("expected an error for an empty scope, got nil")
	}
}
