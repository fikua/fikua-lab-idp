package verifier

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/fikua/fikua-lab-idp/internal/session"
)

// newTestService builds a Service wired to a fresh in-memory session.Store
// and a throwaway self-signed signing key (see testSigningKey), using
// direct_post (no response encryption) — the simpler of this Verifier's two
// response modes, sufficient to exercise CreateSession/HandleResponse/
// GetResult end to end without also standing up a JWE round trip.
func newTestService(t *testing.T) *Service {
	t.Helper()
	return NewService("https://verifier.example", testSigningKey(t), session.NewStore(), ResponseModeDirectPost)
}

func TestCreateSessionAndGetRequestObjectSingleCredential(t *testing.T) {
	svc := newTestService(t)

	result, err := svc.CreateSession(CreateSessionRequest{
		Credentials: []CredentialRequest{
			{ID: "requested_credential", CredentialType: "eu.europa.ec.eudi.pid.1", Claims: []string{"given_name"}, Format: FormatSDJWTVC},
		},
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if result.SessionID == "" || result.State == "" || result.RequestURI == "" || result.ClientID == "" {
		t.Fatalf("CreateSession returned an incomplete result: %+v", result)
	}

	requestJWT, err := svc.GetRequestObject(result.SessionID)
	if err != nil {
		t.Fatalf("GetRequestObject: %v", err)
	}
	if requestJWT == "" {
		t.Fatal("expected a non-empty signed Request Object")
	}
}

func TestCreateSessionRejectsNoCredentials(t *testing.T) {
	svc := newTestService(t)
	if _, err := svc.CreateSession(CreateSessionRequest{}); err == nil {
		t.Fatal("expected an error when no credentials are requested")
	}
}

func TestGetRequestObjectUnknownSessionFails(t *testing.T) {
	svc := newTestService(t)
	if _, err := svc.GetRequestObject("does-not-exist"); err == nil {
		t.Fatal("expected an error for an unknown session")
	}
}

// TestHandleResponseSingleCredentialEndToEnd exercises the full
// single-credential path: CreateSession builds the DCQL query and nonce,
// a wallet-shaped SD-JWT VC presentation is built against that exact
// audience (the session's own client_id) and nonce, HandleResponse
// verifies it, and GetResult returns the same claims afterward.
func TestHandleResponseSingleCredentialEndToEnd(t *testing.T) {
	svc := newTestService(t)
	issuer := newTestIssuerKey(t)
	holderPriv, holderPub := testHolderKey(t)

	created, err := svc.CreateSession(CreateSessionRequest{
		Credentials: []CredentialRequest{
			{ID: "requested_credential", CredentialType: "eu.europa.ec.eudi.pid.1", Claims: []string{"given_name"}, Format: FormatSDJWTVC},
		},
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	sess, ok := svc.sessions.FindVerification(created.SessionID)
	if !ok {
		t.Fatal("session not found after creation")
	}

	presentation := buildSDJWTPresentation(t, issuer, sdJWTPresentationOpts{
		vct:             "eu.europa.ec.eudi.pid.1",
		claims:          map[string]any{"given_name": "Alex"},
		holderPublicJWK: holderPub,
		holderPrivKey:   holderPriv,
		audience:        created.ClientID,
		nonce:           sess.Nonce,
	})

	result, respSession, err := svc.HandleResponse(context.Background(), ResponseRequest{
		VPToken: presentation,
		State:   created.State,
	})
	if err != nil {
		t.Fatalf("HandleResponse returned a protocol error: %v", err)
	}
	if result.Status != StatusSuccess {
		t.Fatalf("expected success, got status=%q error=%q description=%q", result.Status, result.Error, result.ErrorDescription)
	}
	if result.Claims["given_name"] != "Alex" {
		t.Fatalf("unexpected claims: %+v", result.Claims)
	}
	if respSession.SessionID != created.SessionID {
		t.Fatalf("HandleResponse returned session %q, want %q", respSession.SessionID, created.SessionID)
	}

	polled, err := svc.GetResult(created.SessionID)
	if err != nil {
		t.Fatalf("GetResult: %v", err)
	}
	if polled.Status != StatusSuccess || polled.Claims["given_name"] != "Alex" {
		t.Fatalf("GetResult mismatch: %+v", polled)
	}
}

// TestHandleResponseMultiCredentialSameHolderSucceeds is this feature's
// central case: a PID and a bound attestation (modeled on the Barcelona
// padró's cryptographically_bound_to relationship), presented together by
// the same holder, must verify and merge both credentials' claims.
func TestHandleResponseMultiCredentialSameHolderSucceeds(t *testing.T) {
	svc := newTestService(t)
	issuer := newTestIssuerKey(t)
	holderPriv, holderPub := testHolderKey(t)

	created, err := svc.CreateSession(CreateSessionRequest{
		Credentials: []CredentialRequest{
			{ID: "pid", CredentialType: "eu.europa.ec.eudi.pid.1", Claims: []string{"given_name"}, Format: FormatSDJWTVC},
			{ID: "padro_attestation", CredentialType: "urn:fikua:padro:barcelona:1", Claims: []string{"resident_municipality"}, Format: FormatSDJWTVC},
		},
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	sess, ok := svc.sessions.FindVerification(created.SessionID)
	if !ok {
		t.Fatal("session not found after creation")
	}

	pidPresentation := buildSDJWTPresentation(t, issuer, sdJWTPresentationOpts{
		vct:             "eu.europa.ec.eudi.pid.1",
		claims:          map[string]any{"given_name": "Alex"},
		holderPublicJWK: holderPub,
		holderPrivKey:   holderPriv,
		audience:        created.ClientID,
		nonce:           sess.Nonce,
	})
	padroPresentation := buildSDJWTPresentation(t, issuer, sdJWTPresentationOpts{
		vct:             "urn:fikua:padro:barcelona:1",
		claims:          map[string]any{"resident_municipality": "Barcelona"},
		holderPublicJWK: holderPub,
		holderPrivKey:   holderPriv,
		audience:        created.ClientID,
		nonce:           sess.Nonce,
	})

	vpTokenJSON := map[string]any{
		"pid":               []any{pidPresentation},
		"padro_attestation": []any{padroPresentation},
	}
	rawBytes, err := json.Marshal(vpTokenJSON)
	if err != nil {
		t.Fatal(err)
	}

	result, _, err := svc.HandleResponse(context.Background(), ResponseRequest{
		VPToken: string(rawBytes),
		State:   created.State,
	})
	if err != nil {
		t.Fatalf("HandleResponse returned a protocol error: %v", err)
	}
	if result.Status != StatusSuccess {
		t.Fatalf("expected success, got status=%q error=%q description=%q", result.Status, result.Error, result.ErrorDescription)
	}
	if result.Claims["given_name"] != "Alex" || result.Claims["resident_municipality"] != "Barcelona" {
		t.Fatalf("expected merged claims from both credentials, got: %+v", result.Claims)
	}
}

// TestHandleResponseMultiCredentialDifferentHolderFails is the negative
// counterpart: two individually-valid credentials from DIFFERENT holders
// must be rejected as a whole — this is the actual security property
// cryptographically_bound_to depends on (see verifyCrossCredentialBinding).
func TestHandleResponseMultiCredentialDifferentHolderFails(t *testing.T) {
	svc := newTestService(t)
	issuer := newTestIssuerKey(t)
	holderAPriv, holderAPub := testHolderKey(t)
	holderBPriv, holderBPub := testHolderKey(t)

	created, err := svc.CreateSession(CreateSessionRequest{
		Credentials: []CredentialRequest{
			{ID: "pid", CredentialType: "eu.europa.ec.eudi.pid.1", Claims: []string{"given_name"}, Format: FormatSDJWTVC},
			{ID: "padro_attestation", CredentialType: "urn:fikua:padro:barcelona:1", Claims: []string{"resident_municipality"}, Format: FormatSDJWTVC},
		},
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	sess, ok := svc.sessions.FindVerification(created.SessionID)
	if !ok {
		t.Fatal("session not found after creation")
	}

	pidPresentation := buildSDJWTPresentation(t, issuer, sdJWTPresentationOpts{
		vct:             "eu.europa.ec.eudi.pid.1",
		claims:          map[string]any{"given_name": "Alex"},
		holderPublicJWK: holderAPub,
		holderPrivKey:   holderAPriv,
		audience:        created.ClientID,
		nonce:           sess.Nonce,
	})
	// A genuine, individually-valid padró attestation — but bound to a
	// DIFFERENT holder key than the PID above.
	padroPresentation := buildSDJWTPresentation(t, issuer, sdJWTPresentationOpts{
		vct:             "urn:fikua:padro:barcelona:1",
		claims:          map[string]any{"resident_municipality": "Barcelona"},
		holderPublicJWK: holderBPub,
		holderPrivKey:   holderBPriv,
		audience:        created.ClientID,
		nonce:           sess.Nonce,
	})

	vpTokenJSON := map[string]any{
		"pid":               []any{pidPresentation},
		"padro_attestation": []any{padroPresentation},
	}
	rawBytes, err := json.Marshal(vpTokenJSON)
	if err != nil {
		t.Fatal(err)
	}

	result, _, err := svc.HandleResponse(context.Background(), ResponseRequest{
		VPToken: string(rawBytes),
		State:   created.State,
	})
	if err != nil {
		t.Fatalf("HandleResponse returned a protocol error: %v", err)
	}
	if result.Status != StatusError {
		t.Fatal("expected the presentation to be rejected for a holder-key mismatch, got success")
	}

	polled, err := svc.GetResult(created.SessionID)
	if err != nil {
		t.Fatalf("GetResult: %v", err)
	}
	if polled.Status != StatusError {
		t.Fatalf("expected GetResult to report the failure, got: %+v", polled)
	}
}

func TestHandleResponseMissingCredentialFails(t *testing.T) {
	svc := newTestService(t)
	issuer := newTestIssuerKey(t)
	holderPriv, holderPub := testHolderKey(t)

	created, err := svc.CreateSession(CreateSessionRequest{
		Credentials: []CredentialRequest{
			{ID: "pid", CredentialType: "eu.europa.ec.eudi.pid.1", Claims: []string{"given_name"}, Format: FormatSDJWTVC},
			{ID: "padro_attestation", CredentialType: "urn:fikua:padro:barcelona:1", Claims: []string{"resident_municipality"}, Format: FormatSDJWTVC},
		},
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	sess, ok := svc.sessions.FindVerification(created.SessionID)
	if !ok {
		t.Fatal("session not found after creation")
	}

	// Only the PID is presented — the wallet withheld the padró attestation.
	pidPresentation := buildSDJWTPresentation(t, issuer, sdJWTPresentationOpts{
		vct:             "eu.europa.ec.eudi.pid.1",
		claims:          map[string]any{"given_name": "Alex"},
		holderPublicJWK: holderPub,
		holderPrivKey:   holderPriv,
		audience:        created.ClientID,
		nonce:           sess.Nonce,
	})
	vpTokenJSON := map[string]any{"pid": []any{pidPresentation}}
	rawBytes, err := json.Marshal(vpTokenJSON)
	if err != nil {
		t.Fatal(err)
	}

	result, _, err := svc.HandleResponse(context.Background(), ResponseRequest{
		VPToken: string(rawBytes),
		State:   created.State,
	})
	if err != nil {
		t.Fatalf("HandleResponse returned a protocol error: %v", err)
	}
	if result.Status != StatusError {
		t.Fatal("expected rejection when a requested credential is missing entirely")
	}
}

func TestHandleResponseWrongStateFails(t *testing.T) {
	svc := newTestService(t)
	// An unknown state is a rejected *verification result* (the frontend
	// must be able to show "that presentation was rejected, and why"), not
	// a Go error — see HandleResponse's doc comment on its two-layer error
	// model.
	result, _, err := svc.HandleResponse(context.Background(), ResponseRequest{
		VPToken: "irrelevant",
		State:   "unknown-state",
	})
	if err != nil {
		t.Fatalf("unexpected protocol error: %v", err)
	}
	if result.Status != StatusError {
		t.Fatalf("expected a rejected result for an unknown state, got: %+v", result)
	}
}

func TestHandleResponseMissingVPTokenFails(t *testing.T) {
	svc := newTestService(t)
	created, err := svc.CreateSession(CreateSessionRequest{
		Credentials: []CredentialRequest{
			{ID: "requested_credential", CredentialType: "eu.europa.ec.eudi.pid.1", Claims: []string{"given_name"}, Format: FormatSDJWTVC},
		},
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	_, _, err = svc.HandleResponse(context.Background(), ResponseRequest{State: created.State})
	if err == nil {
		t.Fatal("expected an error for a missing vp_token")
	}
}

func TestGetResultPendingBeforePresentation(t *testing.T) {
	svc := newTestService(t)
	created, err := svc.CreateSession(CreateSessionRequest{
		Credentials: []CredentialRequest{
			{ID: "requested_credential", CredentialType: "eu.europa.ec.eudi.pid.1", Claims: []string{"given_name"}, Format: FormatSDJWTVC},
		},
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	result, err := svc.GetResult(created.SessionID)
	if err != nil {
		t.Fatalf("GetResult: %v", err)
	}
	if result.Status != StatusError || result.Error != "pending" {
		t.Fatalf("expected a pending status before any presentation, got: %+v", result)
	}
}

func TestGetResultUnknownSessionFails(t *testing.T) {
	svc := newTestService(t)
	if _, err := svc.GetResult("does-not-exist"); err == nil {
		t.Fatal("expected an error for an unknown session")
	}
}

func TestResultURI(t *testing.T) {
	svc := newTestService(t)
	got := svc.ResultURI("abc123")
	want := "https://verifier.example" + APIPrefix + "/result/abc123"
	if got != want {
		t.Fatalf("ResultURI = %q, want %q", got, want)
	}
}
