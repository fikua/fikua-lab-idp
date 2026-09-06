package oauth2

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"

	fikuacrypto "github.com/fikua/fikua-lab-idp/internal/crypto"
)

const AuthorizationCodeGrantType = "authorization_code"

// AccessTokenTTL is how long a minted access token stays valid. Short by
// OAuth2 standards, and deliberately so: these tokens are stateless JWTs
// the Credential Issuer validates offline, so this window is also the
// only bound on how long a revoked token stays honoured there in the
// worst case — see Minter.Mint's doc comment on revocation.
const AccessTokenTTL = 5 * time.Minute

// AccessTokenType is the RFC 9068 §2.1 media type this AS stamps on the
// access token's `typ` header. It is what tells a resource server it is
// looking at an access token and not, say, an id_token replayed at the
// credential endpoint — the Credential Issuer rejects any other typ.
const AccessTokenType = "at+jwt"

// TokenRequest is the token-endpoint request, parsed from form parameters.
type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	CodeVerifier string
	// ClientID is the (optional) explicit client_id form parameter, per
	// RFC 6749 §5.1 — this AS authenticates the client via its
	// attestation, not this parameter, but if present it must agree with
	// the attested client_id (RFC 6749 §5.2: a token request identifying
	// a client other than the one the attestation authenticates must be
	// rejected).
	ClientID string
	// ClientAssertionType/ClientAssertion carry a form-based client
	// attestation (ATCA draft-07 §3), the token endpoint's counterpart
	// to the OAuth-Client-Attestation/-PoP headers — the PAR endpoint
	// already accepted both transports (HandlePar reads these same form
	// keys), but the token endpoint only ever looked at headers, so a
	// client authenticating here via form-encoded assertion instead of
	// headers had its attestation silently ignored.
	ClientAssertionType string
	ClientAssertion     string
}

// TokenRequestFromForm builds a TokenRequest from parsed form values.
func TokenRequestFromForm(form map[string]string) TokenRequest {
	return TokenRequest{
		GrantType:           form["grant_type"],
		Code:                form["code"],
		RedirectURI:         form["redirect_uri"],
		CodeVerifier:        form["code_verifier"],
		ClientID:            form["client_id"],
		ClientAssertionType: form["client_assertion_type"],
		ClientAssertion:     form["client_assertion"],
	}
}

// IsAuthorizationCode reports whether this request uses the
// authorization_code grant — the only grant this HAIP-only AS supports.
func (r TokenRequest) IsAuthorizationCode() bool {
	return r.GrantType == AuthorizationCodeGrantType
}

// TokenResponse is the token-endpoint success response.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// AccessTokenClaims is everything an access token carries beyond the
// registered JWT claims. It exists because the Credential Issuer is a
// separate process now: it has no shared session store to consult, so
// every fact it needs to complete issuance must survive here.
type AccessTokenClaims struct {
	// IssuanceRecordID is the issuance record the credential endpoint
	// builds its credential from — previously session.Data.Metadata's
	// "issuanceRecordId".
	IssuanceRecordID string
	// CNonce is the c_nonce bound at /token, which the credential
	// endpoint accepts as its proof JWT's nonce. Previously
	// session.Data.CNonce.
	CNonce string
	// ClientID is the attested client this token was issued to.
	ClientID string
	// DPoPKey is the proof-of-possession key presented at /token, whose
	// RFC 7638 thumbprint becomes the token's `cnf.jkt`.
	DPoPKey jwk.Key
}

// Minter signs RFC 9068 JWT access tokens.
type Minter struct {
	key    *fikuacrypto.SigningKey
	issuer string
	// audience is the Credential Issuer these tokens are valid at. RFC
	// 9068 §4 requires the resource server reject a token whose `aud`
	// isn't itself, which is what stops a token minted for one resource
	// being replayed at another.
	audience string
}

// NewMinter builds a Minter signing with key. issuer is this AS's own
// identifier (the `iss` claim); audience is the Credential Issuer's base
// URL (the `aud` claim).
func NewMinter(key *fikuacrypto.SigningKey, issuer, audience string) *Minter {
	return &Minter{key: key, issuer: issuer, audience: audience}
}

// Mint signs an RFC 9068 access token for claims, returning the compact
// JWT and its jti.
//
// The jti is returned rather than discarded because these tokens are
// stateless: nothing to delete when RFC 6749 §4.1.2 says a reused
// authorization code's already-issued token SHOULD be revoked. The
// caller records the jti against the authorization code (see
// session.Store.RecordIssuedJTI) and, on a code reuse, publishes it to
// the denylist this AS serves at /oid4vci/v1/revoked-tokens, which the
// Credential Issuer polls. Combined with AccessTokenTTL, that bounds a
// revoked token's remaining usefulness to one poll interval rather than
// the ~24h the old opaque-token TTL allowed.
func (m *Minter) Mint(claims AccessTokenClaims) (token string, jti string, err error) {
	thumbprint, err := DPoPThumbprint(claims.DPoPKey)
	if err != nil {
		return "", "", err
	}

	now := time.Now()
	jti = RandomJTI()

	builder := jwt.NewBuilder().
		Issuer(m.issuer).
		Audience([]string{m.audience}).
		IssuedAt(now).
		Expiration(now.Add(AccessTokenTTL)).
		JwtID(jti).
		// RFC 9068 §2.2.1 requires a `sub`. There is no end-user account
		// behind an OID4VCI issuance — the "subject" the Credential
		// Issuer actually cares about is the issuance record, and the
		// client is the only authenticated party — so sub is the client
		// id, and the record id rides in its own claim below.
		Subject(claims.ClientID).
		Claim("client_id", claims.ClientID).
		// RFC 9449 §6.1: DPoP sender-constraining is expressed as a cnf
		// claim carrying the RFC 7638 thumbprint of the proof key. This
		// is what replaces the old shared-memory session.Data.DPoPKey —
		// the Credential Issuer compares it against the thumbprint of
		// whatever DPoP proof accompanies the request.
		Claim("cnf", map[string]any{"jkt": thumbprint}).
		Claim("issuance_record_id", claims.IssuanceRecordID)

	if claims.CNonce != "" {
		builder = builder.Claim("c_nonce", claims.CNonce)
	}

	tok, err := builder.Build()
	if err != nil {
		return "", "", err
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), m.key.Signer(),
		jws.WithProtectedHeaders(accessTokenHeaders(m.key.KID()))))
	if err != nil {
		return "", "", err
	}
	return string(signed), jti, nil
}

// accessTokenHeaders builds the JWS protected headers RFC 9068 §2.1
// mandates: `typ` of at+jwt, plus the `kid` that lets the Credential
// Issuer pick the right key out of this AS's JWK Set without trial
// verification.
func accessTokenHeaders(kid string) jws.Headers {
	headers := jws.NewHeaders()
	_ = headers.Set(jws.TypeKey, AccessTokenType)
	_ = headers.Set(jws.KeyIDKey, kid)
	return headers
}

// RandomJTI returns a fresh token identifier: 16 random bytes, base64url
// without padding.
func RandomJTI() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// DPoPToken builds a DPoP-bound TokenResponse — this AS's only token
// type, since HAIP always requires DPoP sender-constraining.
func DPoPToken(accessToken string) TokenResponse {
	return TokenResponse{
		AccessToken: accessToken,
		TokenType:   "DPoP",
		ExpiresIn:   int(AccessTokenTTL.Seconds()),
	}
}
