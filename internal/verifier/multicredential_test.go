package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/fikua/fikua-lab-idp/internal/session"
)

func mustJWK(t *testing.T) jwk.Key {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := jwk.Import(priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestBuildDCQLQueryMultiCredential(t *testing.T) {
	dcql := buildDCQLQuery([]CredentialRequest{
		{ID: "pid", CredentialType: "eu.europa.ec.eudi.pid.1", Claims: []string{"given_name"}, Format: FormatSDJWTVC},
		{ID: "padro_attestation", CredentialType: "urn:fikua:padro:barcelona:1", Claims: []string{"resident_municipality"}, Format: FormatSDJWTVC},
	})

	if len(dcql.Credentials) != 2 {
		t.Fatalf("want 2 credential queries, got %d", len(dcql.Credentials))
	}
	if dcql.Credentials[0].ID != "pid" || dcql.Credentials[1].ID != "padro_attestation" {
		t.Fatalf("credential IDs not preserved: %+v", dcql.Credentials)
	}
	if len(dcql.CredentialSets) != 1 || len(dcql.CredentialSets[0].Options) != 1 {
		t.Fatalf("want exactly one credential_sets entry with one option, got %+v", dcql.CredentialSets)
	}
	got := dcql.CredentialSets[0].Options[0]
	if len(got) != 2 || got[0] != "pid" || got[1] != "padro_attestation" {
		t.Fatalf("credential_sets option should require both IDs, got %v", got)
	}
}

func TestBuildDCQLQuerySingleCredentialHasNoCredentialSets(t *testing.T) {
	dcql := buildDCQLQuery([]CredentialRequest{
		{ID: "requested_credential", CredentialType: "eu.europa.ec.eudi.pid.1", Claims: []string{"given_name"}, Format: FormatSDJWTVC},
	})
	if len(dcql.CredentialSets) != 0 {
		t.Fatalf("single-credential query should have no credential_sets, got %+v", dcql.CredentialSets)
	}
}

func TestAllVPTokensMultiCredentialObject(t *testing.T) {
	query := session.DCQLQuery{Credentials: []session.DCQLCredentialQuery{{ID: "pid"}, {ID: "padro_attestation"}}}
	raw := map[string]any{
		"pid":               []any{"vp-token-pid"},
		"padro_attestation": []any{"vp-token-padro"},
	}
	tokens := allVPTokens(raw, query)
	if tokens["pid"] != "vp-token-pid" || tokens["padro_attestation"] != "vp-token-padro" {
		t.Fatalf("unexpected tokens: %+v", tokens)
	}
}

func TestAllVPTokensSingleCredentialBareString(t *testing.T) {
	query := session.DCQLQuery{Credentials: []session.DCQLCredentialQuery{{ID: "requested_credential"}}}
	tokens := allVPTokens("bare-vp-token", query)
	if tokens["requested_credential"] != "bare-vp-token" {
		t.Fatalf("unexpected tokens: %+v", tokens)
	}
}

func TestParseVPTokenFormEncodedMultiCredentialObject(t *testing.T) {
	// Plain direct_post form fields are always strings — a multi-credential
	// wallet must JSON-serialize the {credential_id: [...]} object into that
	// one form field, per OID4VP §8.1.
	raw := `{"pid":["vp-pid"],"padro_attestation":["vp-padro"]}`
	parsed := parseVPToken(raw)
	obj, ok := parsed.(map[string]any)
	if !ok {
		t.Fatalf("expected parseVPToken to decode a JSON object, got %T: %v", parsed, parsed)
	}
	query := session.DCQLQuery{Credentials: []session.DCQLCredentialQuery{{ID: "pid"}, {ID: "padro_attestation"}}}
	tokens := allVPTokens(obj, query)
	if tokens["pid"] != "vp-pid" || tokens["padro_attestation"] != "vp-padro" {
		t.Fatalf("unexpected tokens: %+v", tokens)
	}
}

func TestParseVPTokenFormEncodedBareString(t *testing.T) {
	// A single-credential presentation is not JSON at all (an SD-JWT VC
	// compact serialization contains '~', not a JSON object) — must be
	// passed through unchanged, not misinterpreted as JSON.
	raw := "issuer-jwt~disclosure1~disclosure2~kbjwt"
	parsed := parseVPToken(raw)
	s, ok := parsed.(string)
	if !ok || s != raw {
		t.Fatalf("expected bare string passthrough, got %T: %v", parsed, parsed)
	}
}

func TestVerifyCrossCredentialBindingSameKeyPasses(t *testing.T) {
	k := mustJWK(t)
	err := verifyCrossCredentialBinding(map[string]jwk.Key{
		"pid":               k,
		"padro_attestation": k,
	})
	if err != nil {
		t.Fatalf("expected same-key binding to pass, got: %v", err)
	}
}

func TestVerifyCrossCredentialBindingDifferentKeyFails(t *testing.T) {
	err := verifyCrossCredentialBinding(map[string]jwk.Key{
		"pid":               mustJWK(t),
		"padro_attestation": mustJWK(t),
	})
	if err == nil {
		t.Fatal("expected different-key binding to fail, got nil error")
	}
}

func TestVerifyCrossCredentialBindingSingleCredentialPasses(t *testing.T) {
	err := verifyCrossCredentialBinding(map[string]jwk.Key{"pid": mustJWK(t)})
	if err != nil {
		t.Fatalf("a single credential has nothing to compare against, should pass: %v", err)
	}
}
