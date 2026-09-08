// Package sdjwtverify verifies SD-JWT VC presentations received by the
// OID4VP Verifier — the inverse of fikua-lab-issuer's internal/sdjwt, which
// builds them. Named apart from that package on purpose: the two do
// opposite things and readers move between the repos.
//
// Nothing is shared with the issuer beyond the two byte-level details that
// have to agree for any of this to work at all — the `~`-separated compact
// serialization, and digest = base64url(SHA-256(ASCII of the base64url
// disclosure string)) — which are reimplemented here for the same reason
// internal/oauth2/dpop.go is duplicated: they track a frozen spec, and a
// shared module's version pinning would cost more than the few lines.
package sdjwtverify

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// kbIATSkew is the tolerated absolute difference between a KB-JWT's iat and
// now. The conformance suite presents KB-JWTs dated ±1 year to check the
// Verifier rejects them; 5 minutes accepts genuine clock skew and nothing
// else.
const kbIATSkew = 5 * time.Minute

// Error is a presentation verification failure. Distinct from a plumbing
// error: the Verifier maps it to a 4xx rejection of the presentation
// (OID4VP 1.0 Final §8.2), never to a 500.
type Error struct {
	Reason string
}

func (e *Error) Error() string { return e.Reason }

func failf(format string, args ...any) error {
	return &Error{Reason: fmt.Sprintf(format, args...)}
}

// Verify checks a full SD-JWT VC presentation and returns the disclosed
// claims. In order:
//
//  1. the issuer JWT's signature, against the public key of its own x5c
//     leaf certificate;
//  2. every disclosure's digest is present in the issuer JWT's `_sd` array
//     (catching a tampered salt, name or value, and any disclosure the
//     issuer never committed to);
//  3. the KB-JWT's signature, against the holder key in the issuer JWT's
//     `cnf.jwk`;
//  4. the KB-JWT's aud (= this Verifier's client_id), nonce (= the request
//     nonce), sd_hash (= SHA-256 over the presentation up to and including
//     the final `~`), and iat freshness.
//
// The issuer signature is checked against the certificate embedded in the
// presentation rather than a configured trust anchor — see
// certchain.Validate for why that is conformance-testing behaviour and what
// closing the gap would take.
func Verify(presentation, expectedAud, expectedNonce string) (map[string]any, error) {
	result, err := VerifyWithStatus(presentation, expectedAud, expectedNonce)
	return result.Claims, err
}

// Result is one SD-JWT VC presentation's verified content: its disclosed
// claims, the issuer's own "status" claim (see VerifyWithStatus), and the
// holder key the KB-JWT was checked against. HolderKey is exposed so a
// caller presented with more than one credential in the same session (e.g.
// a PID alongside an attestation whose Rulebook declares
// `cryptographically_bound_to` it) can compare holder keys across
// credentials — this package only ever verifies one presentation at a
// time and has no notion of that cross-credential relationship itself.
type Result struct {
	Claims    map[string]any
	Status    map[string]any
	HolderKey jwk.Key
}

// VerifyWithStatus is Verify plus the issuer JWT's own "status" claim
// (IETF Token Status List, draft-ietf-oauth-status-list-21 §6.2's
// {status_list: {idx, uri}}), so a caller can fetch and check the
// credential's revocation state — HAIP §7 point 2.2.2.2 requires the
// Verifier do this, not just validate the presentation's signatures.
// Result.Status is nil when the issuer JWT carries no "status" claim at all
// (unusual for this ecosystem's own issuer, but not itself a reason to
// reject a presentation — an issuer that opts out of revocation is a
// policy question, not a cryptographic failure). Result.HolderKey is
// always set on success (verifyKeyBinding requires a valid cnf.jwk to
// return at all).
func VerifyWithStatus(presentation, expectedAud, expectedNonce string) (Result, error) {
	parsed, err := parse(presentation)
	if err != nil {
		return Result{}, err
	}

	// Read first, verify after: HAIP §7 point 2.2.2.2 requires the
	// Verifier fetch and check the referenced Token Status List
	// regardless of whether the presentation is ultimately accepted —
	// confirmed against OIDF conformance runs for the invalid-signature,
	// invalid-KB-JWT-signature and invalid-sd_hash tests, all of which
	// still require EnsureVerifierFetchedStatusList to pass even though
	// the presentation itself is rejected. Reading status off the
	// unverified payload is safe: it only ever gates a second, unrelated
	// network fetch (see statuslistcheck.ParseRef's caller), never trust
	// decisions about the claims themselves — those still wait for the
	// signature check below.
	status := unverifiedStatusClaim(parsed.issuerJWT)

	issuerClaims, err := verifyIssuerSignature(parsed.issuerJWT)
	if err != nil {
		return Result{Status: status}, err
	}
	if err := verifyDisclosureDigests(parsed.disclosures, issuerClaims); err != nil {
		return Result{Status: status}, err
	}
	holderKey, err := verifyKeyBinding(parsed, issuerClaims, presentation, expectedAud, expectedNonce)
	if err != nil {
		return Result{Status: status}, err
	}

	claims := make(map[string]any, len(parsed.disclosures))
	for _, d := range parsed.disclosures {
		claims[d.claimName] = d.claimValue
	}
	// Now backed by a signature-verified payload — no change in value
	// from the unverified read above unless the issuer JWT's signature
	// check just failed to catch a tampered status claim, which the
	// caller relies on not happening.
	status, _ = issuerClaims["status"].(map[string]any)
	return Result{Claims: claims, Status: status, HolderKey: holderKey}, nil
}

// unverifiedStatusClaim reads the "status" claim straight off an issuer
// JWT's payload without checking its signature — see VerifyWithStatus's
// call site for why that is safe here.
func unverifiedStatusClaim(issuerJWT string) map[string]any {
	msg, err := jws.Parse([]byte(issuerJWT))
	if err != nil {
		return nil
	}
	var claims map[string]any
	if err := json.Unmarshal(msg.Payload(), &claims); err != nil {
		return nil
	}
	status, _ := claims["status"].(map[string]any)
	return status
}

// presentationParts is a parsed SD-JWT compact serialization:
// <issuer-jwt>~<disclosure>~…~<kb-jwt>.
type presentationParts struct {
	issuerJWT   string
	disclosures []disclosure
	kbJWT       string
}

// disclosure is one decoded SD-JWT disclosure: the base64url string as it
// appeared in the presentation (which is what the digest is computed over —
// re-encoding it would change the digest) plus the [salt, name, value] it
// decodes to.
type disclosure struct {
	encoded    string
	salt       string
	claimName  string
	claimValue any
}

func parse(presentation string) (presentationParts, error) {
	parts := strings.Split(presentation, "~")
	if len(parts) < 2 {
		return presentationParts{}, failf("malformed SD-JWT: expected at least one '~' separator")
	}

	out := presentationParts{issuerJWT: parts[0]}
	// A trailing empty segment means "no KB-JWT" — the presentation ended
	// on its mandatory final `~`.
	last := len(parts) - 1
	if parts[last] != "" {
		out.kbJWT = parts[last]
	}

	for _, encoded := range parts[1:last] {
		if encoded == "" {
			continue
		}
		d, err := parseDisclosure(encoded)
		if err != nil {
			return presentationParts{}, err
		}
		out.disclosures = append(out.disclosures, d)
	}
	return out, nil
}

// parseDisclosure decodes one base64url disclosure into its 3-element
// [salt, claimName, claimValue] JSON array (SD-JWT §5.1).
func parseDisclosure(encoded string) (disclosure, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(encoded, "="))
	if err != nil {
		return disclosure{}, failf("malformed disclosure: %v", err)
	}
	var arr []any
	if err := json.Unmarshal(raw, &arr); err != nil {
		return disclosure{}, failf("malformed disclosure: %v", err)
	}
	if len(arr) != 3 {
		return disclosure{}, failf("disclosure must be a 3-element array, got %d", len(arr))
	}
	salt, ok := arr[0].(string)
	if !ok {
		return disclosure{}, failf("disclosure salt is not a string")
	}
	name, ok := arr[1].(string)
	if !ok {
		return disclosure{}, failf("disclosure claim name is not a string")
	}
	return disclosure{encoded: encoded, salt: salt, claimName: name, claimValue: arr[2]}, nil
}

// digest is the SD-JWT §5.1.1.3 digest: SHA-256 over the ASCII bytes of the
// base64url disclosure string itself, base64url no padding.
func (d disclosure) digest() string {
	sum := sha256.Sum256([]byte(d.encoded))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// verifyIssuerSignature checks the issuer JWT against the public key of its
// x5c leaf, and returns its payload claims.
func verifyIssuerSignature(issuerJWT string) (map[string]any, error) {
	msg, err := jws.Parse([]byte(issuerJWT))
	if err != nil {
		return nil, failf("malformed issuer JWT: %v", err)
	}
	if len(msg.Signatures()) != 1 {
		return nil, failf("issuer JWT must carry exactly one signature")
	}
	headers := msg.Signatures()[0].ProtectedHeaders()

	chain, ok := headers.X509CertChain()
	if !ok || chain.Len() == 0 {
		return nil, failf("issuer JWT has no x5c certificate")
	}
	leafDER, ok := chain.Get(0)
	if !ok {
		return nil, failf("issuer JWT x5c leaf unreadable")
	}
	// jwx hands back the base64-encoded DER exactly as it sat in the
	// header, so it has to be decoded before x509 will look at it.
	der, err := base64.StdEncoding.DecodeString(string(leafDER))
	if err != nil {
		return nil, failf("issuer JWT x5c leaf is not valid base64: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, failf("issuer JWT x5c leaf is not a valid certificate: %v", err)
	}
	issuerKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, failf("issuer certificate public key is %T, not EC", cert.PublicKey)
	}

	payload, err := jws.Verify([]byte(issuerJWT), jws.WithKey(jwa.ES256(), issuerKey))
	if err != nil {
		return nil, failf("issuer JWT signature is invalid")
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, failf("issuer JWT payload is not a JSON object: %v", err)
	}
	return claims, nil
}

// verifyDisclosureDigests requires every presented disclosure's digest to
// appear in the issuer JWT's `_sd` array — the check that makes selective
// disclosure sound: a wallet cannot invent, edit or re-salt a claim the
// issuer did not commit to.
func verifyDisclosureDigests(disclosures []disclosure, issuerClaims map[string]any) error {
	committed := make(map[string]struct{})
	if sd, ok := issuerClaims["_sd"].([]any); ok {
		for _, entry := range sd {
			if s, ok := entry.(string); ok {
				committed[s] = struct{}{}
			}
		}
	}
	for _, d := range disclosures {
		if _, ok := committed[d.digest()]; !ok {
			return failf("disclosure %q digest not found in _sd", d.claimName)
		}
	}
	return nil
}

// verifyKeyBinding checks the KB-JWT's signature and its aud/nonce/sd_hash/
// iat claims. Together these are what stop a captured presentation being
// replayed at a different Verifier (aud), in a different session (nonce),
// with disclosures added or removed after the holder signed (sd_hash), or
// at an arbitrary later time (iat).
func verifyKeyBinding(parsed presentationParts, issuerClaims map[string]any, presentation, expectedAud, expectedNonce string) (jwk.Key, error) {
	if parsed.kbJWT == "" {
		return nil, failf("Key Binding JWT is missing")
	}

	cnf, ok := issuerClaims["cnf"].(map[string]any)
	if !ok {
		return nil, failf("issuer JWT has no cnf for key binding")
	}
	cnfJWK, ok := cnf["jwk"].(map[string]any)
	if !ok {
		return nil, failf("issuer JWT has no cnf.jwk for key binding")
	}
	cnfJSON, err := json.Marshal(cnfJWK)
	if err != nil {
		return nil, failf("issuer JWT cnf.jwk is unreadable: %v", err)
	}
	holderKey, err := jwk.ParseKey(cnfJSON)
	if err != nil {
		return nil, failf("issuer JWT cnf.jwk is not a valid JWK: %v", err)
	}

	// Signature first, claims after: jwt.Parse with WithValidate(false)
	// still verifies the signature, and the registered-claim checks are
	// done explicitly below so each failure names itself.
	token, err := jwt.Parse([]byte(parsed.kbJWT), jwt.WithKey(jwa.ES256(), holderKey), jwt.WithValidate(false))
	if err != nil {
		return nil, failf("Key Binding JWT signature is invalid")
	}

	aud, ok := token.Audience()
	if !ok || len(aud) == 0 || aud[0] != expectedAud {
		return nil, failf("KB-JWT aud does not match client_id %q", expectedAud)
	}

	var nonce string
	_ = token.Get("nonce", &nonce)
	if nonce != expectedNonce {
		return nil, failf("KB-JWT nonce does not match the request nonce")
	}

	var sdHash string
	_ = token.Get("sd_hash", &sdHash)
	if sdHash != computeSdHash(presentation) {
		return nil, failf("KB-JWT sd_hash does not match the presentation")
	}

	iat, ok := token.IssuedAt()
	if !ok {
		return nil, failf("KB-JWT is missing iat")
	}
	if skew := time.Since(iat); skew > kbIATSkew || skew < -kbIATSkew {
		return nil, failf("KB-JWT iat is outside the acceptable window (skew %s)", skew.Truncate(time.Second))
	}
	return holderKey, nil
}

// computeSdHash is base64url(SHA-256(everything up to and including the
// last `~`)) — i.e. the issuer JWT plus the exact disclosures presented,
// which is what binds the KB-JWT to this presentation and no other.
func computeSdHash(presentation string) string {
	lastTilde := strings.LastIndex(presentation, "~")
	if lastTilde < 0 {
		return ""
	}
	sum := sha256.Sum256([]byte(presentation[:lastTilde+1]))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
