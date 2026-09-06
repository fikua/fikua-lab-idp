// DUPLICATED FILE: fikua-lab-issuer/internal/oauth2/dpop.go is a near-copy
// of this one. RFC 9449 proofs are presented directly to whichever service
// handles the request and validated locally — this AS needs it at /par and
// /token, the Credential Issuer needs it at /credential and /nonce, and
// neither consults the other at request time. A shared Go module was
// weighed and rejected for this first split: cross-repo version pinning
// costs more than ~200 duplicated lines that track a frozen RFC. Fix bugs
// in both copies; extract a module only if a third consumer appears.
package oauth2

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// dpopIATWindow is the allowed clock skew for a DPoP proof's iat claim
// (RFC 9449), symmetric — past and future both count as "expired" beyond
// this window.
const dpopIATWindow = 5 * time.Minute

// JTIStore tracks DPoP proof jti values to reject replay (RFC 9449 §11.1).
// A plain in-memory, size-bounded set — no persistence, matching the Java
// issuer's bounded ConcurrentHashMap.newKeySet() (10k cap, evicts 1k on
// overflow).
type JTIStore struct {
	mu  sync.Mutex
	set map[string]struct{}
}

const (
	jtiStoreMaxSize    = 10_000
	jtiStoreEvictCount = 1_000
)

// NewJTIStore builds an empty JTIStore.
func NewJTIStore() *JTIStore {
	return &JTIStore{set: make(map[string]struct{})}
}

// Accept reports whether jti is new (true) or a replay (false),
// registering it on success.
func (s *JTIStore) Accept(jti string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, seen := s.set[jti]; seen {
		return false
	}
	if len(s.set) >= jtiStoreMaxSize {
		evicted := 0
		for k := range s.set {
			delete(s.set, k)
			evicted++
			if evicted >= jtiStoreEvictCount {
				break
			}
		}
	}
	s.set[jti] = struct{}{}
	return true
}

// SingleDPoPHeader returns the request's one DPoP header value. RFC 9449
// §7.1 requires "exactly one DPoP HTTP request header field"; net/http's
// Header.Get silently returns only the first of several repeated headers,
// which would let a request with two DPoP headers slip through unnoticed
// instead of being rejected — so callers must use this instead of
// r.Header.Get("DPoP") wherever a DPoP proof is accepted. An absent header
// is not an error here (values is empty, err is nil) since not every
// caller requires DPoP on every request; ValidateDPoPProof itself rejects
// an empty proof.
func SingleDPoPHeader(values []string) (string, error) {
	if len(values) > 1 {
		return "", BadRequest(InvalidRequest, "Multiple DPoP headers are not allowed")
	}
	if len(values) == 0 {
		return "", nil
	}
	return values[0], nil
}

// ValidateDPoPProof validates a DPoP proof JWT per RFC 9449 §4.3, and
// returns the wallet's public key from its `jwk` header. htm/htu are the
// expected HTTP method/URL this proof must be bound to. ath, if non-empty,
// is the expected `ath` claim value (BASE64URL(SHA-256(access_token))) —
// pass "" when validating a proof that carries no access token (e.g. at
// the token endpoint, before an access token exists).
func ValidateDPoPProof(dpopHeader, htm, htu, ath string, jtis *JTIStore) (jwk.Key, error) {
	if dpopHeader == "" {
		return nil, BadRequest(InvalidRequest, "Missing DPoP proof")
	}

	msg, err := jws.Parse([]byte(dpopHeader))
	if err != nil {
		return nil, BadRequest(InvalidRequest, "Invalid DPoP proof: "+err.Error())
	}
	if len(msg.Signatures()) != 1 {
		return nil, BadRequest(InvalidRequest, "Invalid DPoP proof: expected exactly one signature")
	}
	headers := msg.Signatures()[0].ProtectedHeaders()

	typ, _ := headers.Type()
	if typ != "dpop+jwt" {
		return nil, BadRequest(InvalidRequest, "DPoP typ must be dpop+jwt")
	}
	walletJWK, hasJWK := headers.JWK()
	if !hasJWK {
		return nil, BadRequest(InvalidRequest, "DPoP must contain jwk header")
	}
	// RFC 9449 §4.2: the jwk header conveys the wallet's *public* key —
	// a "d" field (EC/OKP/RSA private exponent) means the proof leaked
	// private key material and must be rejected outright.
	if walletJWK.Has("d") {
		return nil, BadRequest(InvalidRequest, "DPoP jwk header must not contain a private key")
	}
	alg, _ := headers.Algorithm()
	if alg != jwa.ES256() {
		return nil, BadRequest(InvalidRequest, "DPoP must use ES256")
	}

	token, err := jwt.Parse([]byte(dpopHeader), jwt.WithKey(jwa.ES256(), walletJWK), jwt.WithValidate(false))
	if err != nil {
		return nil, BadRequest(InvalidRequest, "DPoP signature invalid")
	}

	var claimedHTM string
	_ = token.Get("htm", &claimedHTM)
	if !equalFoldASCII(claimedHTM, htm) {
		return nil, BadRequest(InvalidRequest, "DPoP htm mismatch")
	}
	var claimedHTU string
	_ = token.Get("htu", &claimedHTU)
	if !htuMatches(claimedHTU, htu) {
		return nil, BadRequest(InvalidRequest, "DPoP htu mismatch")
	}

	iat, hasIAT := token.IssuedAt()
	if !hasIAT {
		return nil, BadRequest(InvalidRequest, "DPoP proof expired")
	}
	if skew := time.Since(iat); skew > dpopIATWindow || skew < -dpopIATWindow {
		return nil, BadRequest(InvalidRequest, "DPoP proof expired")
	}

	var jti string
	_ = token.Get("jti", &jti)
	if jti == "" || !jtis.Accept(jti) {
		return nil, BadRequest(InvalidRequest, "DPoP jti replay detected")
	}

	if ath != "" {
		var claimedATH string
		_ = token.Get("ath", &claimedATH)
		if claimedATH != ath {
			return nil, BadRequest(InvalidRequest, "DPoP ath mismatch")
		}
	}

	return walletJWK, nil
}

// ComputeATH computes the DPoP `ath` claim value for accessToken, per RFC
// 9449 §4.2: BASE64URL(SHA-256(accessToken)).
func ComputeATH(accessToken string) string {
	hash := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// DPoPThumbprint returns the RFC 7638 SHA-256 JWK thumbprint of key, for
// pinning/comparing a DPoP key across requests within a session.
func DPoPThumbprint(key jwk.Key) (string, error) {
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("oauth2: computing DPoP key thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

// htuMatches compares a DPoP proof's claimed htu against the expected
// value per RFC 9449 §4.3 point 9: any query or fragment component on
// either side must be ignored, only scheme+authority+path are compared.
// Falls back to an exact string match if either side fails to parse as a
// URL, so a malformed htu is still rejected rather than silently matched.
func htuMatches(claimed, expected string) bool {
	claimedURL, err1 := url.Parse(claimed)
	expectedURL, err2 := url.Parse(expected)
	if err1 != nil || err2 != nil {
		return claimed == expected
	}
	claimedURL.RawQuery, claimedURL.Fragment = "", ""
	expectedURL.RawQuery, expectedURL.Fragment = "", ""
	return claimedURL.String() == expectedURL.String()
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
