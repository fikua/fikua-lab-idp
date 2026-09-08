package httpapi_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/fikua/fikua-lab-idp/internal/oauth2"
)

// testWalletClient bundles the client-attestation key material a stub
// wallet needs to make an attested PAR/token request.
type testWalletClient struct {
	wia string
	pop func(t *testing.T) string
}

// newTestWalletClient mints a self-signed WIA (cnf.jwk carrying a fresh
// PoP-binding key) for a fixed client_id, matching what
// internal/authz.Service's tests build — kept as a separate, smaller
// helper here since the httpapi layer only ever needs the happy path.
func newTestWalletClient(t *testing.T) testWalletClient {
	t.Helper()
	walletKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating wallet key: %v", err)
	}
	cnfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating cnf key: %v", err)
	}
	walletPub, err := jwk.PublicKeyOf(walletKey)
	if err != nil {
		t.Fatalf("building wallet public JWK: %v", err)
	}
	cnfPub, err := jwk.PublicKeyOf(cnfKey)
	if err != nil {
		t.Fatalf("building cnf public JWK: %v", err)
	}

	wiaTok, err := jwt.NewBuilder().
		Subject("wallet-client-1").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Claim("cnf", map[string]any{"jwk": cnfPub}).
		Build()
	if err != nil {
		t.Fatalf("building WIA claims: %v", err)
	}
	wiaHeaders := jws.NewHeaders()
	_ = wiaHeaders.Set(jws.JWKKey, walletPub)
	wiaSigned, err := jwt.Sign(wiaTok, jwt.WithKey(jwa.ES256(), walletKey, jws.WithProtectedHeaders(wiaHeaders)))
	if err != nil {
		t.Fatalf("signing WIA: %v", err)
	}

	return testWalletClient{
		wia: string(wiaSigned),
		pop: func(t *testing.T) string {
			t.Helper()
			cnfPubForPoP, err := jwk.PublicKeyOf(cnfKey)
			if err != nil {
				t.Fatalf("building cnf public JWK: %v", err)
			}
			popTok, err := jwt.NewBuilder().
				Audience([]string{testBaseURL}).
				IssuedAt(time.Now()).
				Expiration(time.Now().Add(time.Hour)).
				JwtID(oauth2.RandomJTI()).
				Build()
			if err != nil {
				t.Fatalf("building PoP claims: %v", err)
			}
			popHeaders := jws.NewHeaders()
			_ = popHeaders.Set(jws.JWKKey, cnfPubForPoP)
			popSigned, err := jwt.Sign(popTok, jwt.WithKey(jwa.ES256(), cnfKey, jws.WithProtectedHeaders(popHeaders)))
			if err != nil {
				t.Fatalf("signing PoP: %v", err)
			}
			return string(popSigned)
		},
	}
}

// parFormNoAttestation is a PAR request's form body absent any client
// attestation — everything HandlePar otherwise requires (PKCE, response
// type, redirect_uri) is present, so a 400 in a test using this unmodified
// is specifically the missing-attestation rejection.
func parFormNoAttestation() map[string][]string {
	verifier := "verifier-1234567890123456789012345678901234567890123"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	return map[string][]string{
		"response_type":         {"code"},
		"client_id":             {"wallet-client-1"},
		"redirect_uri":          {"https://wallet.example.com/callback"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"xyz"},
	}
}

func formBody(form map[string][]string) io.Reader {
	values := url.Values(form)
	return strings.NewReader(values.Encode())
}

func readAll(resp *http.Response) ([]byte, error) {
	return io.ReadAll(resp.Body)
}

func containsPrefix(s, prefix string) bool {
	return strings.HasPrefix(s, prefix)
}
