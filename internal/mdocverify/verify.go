// Package mdocverify verifies ISO 18013-5 mso_mdoc DeviceResponses
// received by the OID4VP Verifier — the inverse of fikua-lab-issuer's
// internal/mdoc, which builds the IssuerSigned half of one. Named apart
// from that package on purpose: the two do opposite things and readers move
// between the repos.
//
// The COSE_Sign1 layout, the CBOR tag-24 wrapping and the ISO 18013-5
// §9.1.2.5 digest rule are reimplemented here rather than shared, for the
// same reason internal/oauth2/dpop.go is duplicated: they track frozen
// specs, and cross-repo version pinning would cost more than the lines do.
// Where the shapes must agree byte-for-byte with what that builder emits,
// they are written to match it.
package mdocverify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// validitySkew is the tolerated clock skew on the MSO's validityInfo
// window, matching sdjwtverify's own iat tolerance.
const validitySkew = 5 * time.Minute

// Error is a presentation verification failure, mapped by the Verifier to a
// 4xx rejection (OID4VP 1.0 Final §8.2) rather than a 500 — same contract
// as sdjwtverify.Error.
type Error struct {
	Reason string
}

func (e *Error) Error() string { return e.Reason }

func failf(format string, args ...any) error {
	return &Error{Reason: fmt.Sprintf(format, args...)}
}

// Verify checks an OID4VP mso_mdoc DeviceResponse and returns the disclosed
// element values. In order:
//
//  1. DeviceResponse structure: version 1.0, status OK, at least one
//     Document;
//  2. issuerAuth's COSE_Sign1 signature against its x5chain leaf, and that
//     chain's own integrity (see validateCertChain on why no trust anchor
//     is pinned);
//  3. MSO version and digestAlgorithm, and docType agreement across the
//     Document, the MSO, and the docType the DCQL query asked for;
//  4. every disclosed IssuerSignedItem's digest against MSO.valueDigests;
//  5. the MSO validityInfo window;
//  6. deviceSignature over the SessionTranscript reconstructed from this
//     Verifier's own session state — the binding that makes the
//     presentation non-replayable.
//
// vpToken is the base64url DeviceResponse as it arrived. encJWKThumbprint
// is the raw RFC 7638 thumbprint of the response-encryption key for an
// encrypted response, nil otherwise. trustAnchor pins the issuer chain when
// non-nil.
func Verify(vpToken, expectedDocType, clientID, nonce string, encJWKThumbprint []byte, responseURI string, trustAnchor *x509.Certificate) (map[string]any, error) {
	document, err := parseSingleDocument(vpToken)
	if err != nil {
		return nil, err
	}

	docType, _ := document["docType"].(string)
	issuerSigned, err := requireMap(document, "issuerSigned", "Document missing issuerSigned")
	if err != nil {
		return nil, err
	}
	deviceSigned, err := requireMap(document, "deviceSigned", "Document missing deviceSigned")
	if err != nil {
		return nil, err
	}

	mso, err := verifyIssuerAuthAndExtractMSO(issuerSigned, trustAnchor)
	if err != nil {
		return nil, err
	}
	if err := verifyMSOMeta(mso); err != nil {
		return nil, err
	}
	if err := verifyDocType(docType, mso, expectedDocType); err != nil {
		return nil, err
	}

	claims, err := verifyDigestsAndCollectClaims(issuerSigned, mso)
	if err != nil {
		return nil, err
	}
	if err := verifyValidity(mso); err != nil {
		return nil, err
	}
	if err := verifyDeviceSignature(deviceSigned, mso, docType, clientID, nonce, encJWKThumbprint, responseURI); err != nil {
		return nil, err
	}
	return claims, nil
}

// parseSingleDocument decodes the base64url DeviceResponse and returns its
// first Document, after the structural checks.
func parseSingleDocument(vpToken string) (map[string]any, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(vpToken, "="))
	if err != nil {
		return nil, failf("vp_token is not valid base64url: %v", err)
	}
	var deviceResponse map[string]any
	if err := cbor.Unmarshal(raw, &deviceResponse); err != nil {
		return nil, failf("malformed DeviceResponse CBOR: %v", err)
	}

	if version, _ := deviceResponse["version"].(string); version != "1.0" {
		return nil, failf("unsupported DeviceResponse version: %q", version)
	}
	if status, ok := deviceResponse["status"]; ok {
		if code, ok := toInt64(status); !ok || code != 0 {
			return nil, failf("DeviceResponse status is not OK: %v", status)
		}
	}
	documents, ok := deviceResponse["documents"].([]any)
	if !ok || len(documents) == 0 {
		return nil, failf("DeviceResponse has no documents")
	}
	document, ok := documents[0].(map[string]any)
	if !ok {
		return nil, failf("DeviceResponse document is not a CBOR map")
	}
	return document, nil
}

// verifyIssuerAuthAndExtractMSO verifies issuerAuth's signature and its
// certificate chain, then unwraps the MobileSecurityObject from the
// tag-24-wrapped payload.
func verifyIssuerAuthAndExtractMSO(issuerSigned map[string]any, trustAnchor *x509.Certificate) (map[string]any, error) {
	rawIssuerAuth, ok := issuerSigned["issuerAuth"]
	if !ok {
		return nil, failf("issuerSigned missing issuerAuth")
	}
	sign1, err := decodeCoseSign1(rawIssuerAuth)
	if err != nil {
		return nil, failf("malformed issuerAuth: %v", err)
	}

	chain, err := coseCertChain(sign1)
	if err != nil {
		return nil, failf("issuerAuth x5chain unreadable: %v", err)
	}
	if len(chain) == 0 {
		return nil, failf("issuerAuth has no x5chain certificate")
	}
	issuerKey, ok := chain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, failf("issuer certificate public key is %T, not EC", chain[0].PublicKey)
	}

	payload, err := verifyCoseSign1Attached(sign1, issuerKey)
	if err != nil {
		return nil, failf("issuerAuth signature is invalid: %v", err)
	}
	if err := validateCertChain(chain, trustAnchor); err != nil {
		return nil, failf("issuer certificate chain invalid: %v", err)
	}

	// payload = #6.24(bstr .cbor MobileSecurityObject)
	var tagged cbor.Tag
	if err := cbor.Unmarshal(payload, &tagged); err != nil {
		return nil, failf("MSO payload is not a tagged CBOR item: %v", err)
	}
	if tagged.Number != tagEncodedCBOR {
		return nil, failf("MSO payload is tag %d, not 24 (MobileSecurityObjectBytes)", tagged.Number)
	}
	inner, ok := tagged.Content.([]byte)
	if !ok {
		return nil, failf("MSO payload tag 24 content is not a byte string")
	}
	var mso map[string]any
	if err := cbor.Unmarshal(inner, &mso); err != nil {
		return nil, failf("malformed MobileSecurityObject: %v", err)
	}
	return mso, nil
}

func verifyMSOMeta(mso map[string]any) error {
	if version, _ := mso["version"].(string); version != "1.0" {
		return failf("unsupported MSO version: %q", version)
	}
	if alg, _ := mso["digestAlgorithm"].(string); alg != "SHA-256" {
		return failf("unsupported MSO digestAlgorithm: %q", alg)
	}
	return nil
}

// verifyDocType requires the Document, the MSO, and the DCQL query to agree
// on the document type — a wallet must not satisfy a PID request with some
// other credential it happens to hold.
func verifyDocType(docType string, mso map[string]any, expectedDocType string) error {
	msoDocType, _ := mso["docType"].(string)
	if docType == "" || docType != msoDocType {
		return failf("Document docType %q does not match MSO docType %q", docType, msoDocType)
	}
	if expectedDocType != "" && expectedDocType != docType {
		return failf("docType %q does not match requested %q", docType, expectedDocType)
	}
	return nil
}

// verifyDigestsAndCollectClaims checks every disclosed IssuerSignedItem
// against the MSO's valueDigests, and collects the element values that
// pass. This is the mdoc counterpart of SD-JWT's _sd check: the issuer
// signed only the MSO, so an element is trustworthy exactly when its digest
// is the one the MSO committed to.
func verifyDigestsAndCollectClaims(issuerSigned, mso map[string]any) (map[string]any, error) {
	nameSpaces, err := requireMap(issuerSigned, "nameSpaces", "issuerSigned missing nameSpaces")
	if err != nil {
		return nil, err
	}
	valueDigests, err := requireMap(mso, "valueDigests", "MSO missing valueDigests")
	if err != nil {
		return nil, err
	}

	claims := make(map[string]any)
	for ns, rawItems := range nameSpaces {
		items, ok := rawItems.([]any)
		if !ok {
			return nil, failf("nameSpaces[%s] is not an array", ns)
		}
		nsDigests, ok := valueDigests[ns].(map[any]any)
		if !ok {
			return nil, failf("MSO has no valueDigests for namespace %s", ns)
		}

		for _, rawItem := range items {
			tagged, ok := rawItem.(cbor.Tag)
			if !ok || tagged.Number != tagEncodedCBOR {
				return nil, failf("IssuerSignedItem in namespace %s is not tag 24", ns)
			}
			inner, ok := tagged.Content.([]byte)
			if !ok {
				return nil, failf("IssuerSignedItem tag 24 content is not a byte string")
			}

			// ISO 18013-5 §9.1.2.5: the digest covers the *tagged*
			// IssuerSignedItemBytes (#6.24(bstr .cbor IssuerSignedItem)) —
			// the full encoding as it sits in nameSpaces — not the inner
			// untagged item bytes. Re-encoding the tag here rather than
			// slicing the original buffer is safe because tag 24 wrapping a
			// definite-length byte string has exactly one valid encoding.
			taggedBytes, err := cbor.Marshal(cbor.Tag{Number: tagEncodedCBOR, Content: inner})
			if err != nil {
				return nil, err
			}
			digest := sha256.Sum256(taggedBytes)

			var item map[string]any
			if err := cbor.Unmarshal(inner, &item); err != nil {
				return nil, failf("malformed IssuerSignedItem in namespace %s: %v", ns, err)
			}
			digestID, ok := toInt64(item["digestID"])
			if !ok {
				return nil, failf("IssuerSignedItem in namespace %s has no digestID", ns)
			}
			elementID, _ := item["elementIdentifier"].(string)

			expected, err := lookupDigest(nsDigests, digestID)
			if err != nil {
				return nil, failf("no MSO digest for digestID %d in namespace %s", digestID, ns)
			}
			if !bytesEqual(expected, digest[:]) {
				return nil, failf("digest mismatch for %q (tampered IssuerSignedItem)", elementID)
			}
			claims[elementID] = cborToGo(item["elementValue"])
		}
	}
	return claims, nil
}

// lookupDigest finds a digestID's expected digest. The map is keyed by CBOR
// integers, which fxamacker decodes into whichever Go integer type fits, so
// a plain map index on one type would miss.
func lookupDigest(nsDigests map[any]any, digestID int64) ([]byte, error) {
	for k, v := range nsDigests {
		if id, ok := toInt64(k); ok && id == digestID {
			digest, ok := v.([]byte)
			if !ok {
				return nil, fmt.Errorf("digest is not a byte string")
			}
			return digest, nil
		}
	}
	return nil, fmt.Errorf("not found")
}

func verifyValidity(mso map[string]any) error {
	validity, err := requireMap(mso, "validityInfo", "MSO missing validityInfo")
	if err != nil {
		return err
	}
	now := time.Now()
	validFrom, err := parseTdate(validity["validFrom"])
	if err != nil {
		return err
	}
	validUntil, err := parseTdate(validity["validUntil"])
	if err != nil {
		return err
	}
	if !validFrom.IsZero() && now.Add(validitySkew).Before(validFrom) {
		return failf("credential is not yet valid (validFrom %s)", validFrom.Format(time.RFC3339))
	}
	if !validUntil.IsZero() && now.Add(-validitySkew).After(validUntil) {
		return failf("credential is expired (validUntil %s)", validUntil.Format(time.RFC3339))
	}
	return nil
}

// verifyDeviceSignature checks the holder's signature over the
// SessionTranscript this Verifier reconstructs from its own session state.
// Because every input to that transcript (client_id, nonce, encryption-key
// thumbprint, response_uri) is ours and none of it travels in the response,
// a presentation captured from another session — or replayed at another
// Verifier — cannot make this verify.
func verifyDeviceSignature(deviceSigned, mso map[string]any, docType, clientID, nonce string, encJWKThumbprint []byte, responseURI string) error {
	deviceAuth, err := requireMap(deviceSigned, "deviceAuth", "deviceSigned missing deviceAuth")
	if err != nil {
		return err
	}
	rawSignature, ok := deviceAuth["deviceSignature"]
	if !ok {
		if _, hasMac := deviceAuth["deviceMac"]; hasMac {
			return failf("deviceMac is not supported; deviceSignature required")
		}
		return failf("deviceAuth missing deviceSignature")
	}
	sign1, err := decodeCoseSign1(rawSignature)
	if err != nil {
		return failf("malformed deviceSignature: %v", err)
	}

	deviceKey, err := deviceKeyFromMSO(mso)
	if err != nil {
		return err
	}

	// DeviceNameSpacesBytes must be the verbatim bytes the wallet signed
	// over, so it is re-marshalled from the decoded tag rather than
	// reconstructed from its contents.
	rawNameSpaces, ok := deviceSigned["nameSpaces"]
	if !ok {
		return failf("deviceSigned missing nameSpaces")
	}
	deviceNameSpacesBytes, err := cbor.Marshal(rawNameSpaces)
	if err != nil {
		return failf("re-encoding deviceSigned nameSpaces: %v", err)
	}

	sessionTranscript, err := openID4VPHandover(clientID, nonce, encJWKThumbprint, responseURI)
	if err != nil {
		return err
	}
	deviceAuthBytes, err := deviceAuthenticationBytes(sessionTranscript, docType, deviceNameSpacesBytes)
	if err != nil {
		return err
	}

	if err := verifyCoseSign1Detached(sign1, deviceAuthBytes, deviceKey); err != nil {
		return failf("deviceSignature does not verify against the reconstructed SessionTranscript: %v", err)
	}
	return nil
}

// deviceKeyFromMSO reads the holder's public key out of the MSO's
// deviceKeyInfo.deviceKey COSE_Key (RFC 9053 §7.1: 1=kty, -1=crv, -2=x,
// -3=y).
func deviceKeyFromMSO(mso map[string]any) (*ecdsa.PublicKey, error) {
	deviceKeyInfo, err := requireMap(mso, "deviceKeyInfo", "MSO missing deviceKeyInfo")
	if err != nil {
		return nil, err
	}
	coseKey, ok := deviceKeyInfo["deviceKey"].(map[any]any)
	if !ok {
		return nil, failf("deviceKeyInfo missing deviceKey")
	}
	x, okX := coseKeyBytes(coseKey, -2)
	y, okY := coseKeyBytes(coseKey, -3)
	if !okX || !okY {
		return nil, failf("deviceKey is missing its x or y coordinate")
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}, nil
}

func coseKeyBytes(coseKey map[any]any, label int64) ([]byte, bool) {
	for k, v := range coseKey {
		if n, ok := toInt64(k); ok && n == label {
			b, ok := v.([]byte)
			return b, ok
		}
	}
	return nil, false
}

// parseTdate reads an ISO 18013-5 tdate — an RFC 3339 string, normally
// wrapped in CBOR tag 0.
func parseTdate(value any) (time.Time, error) {
	if value == nil {
		return time.Time{}, nil
	}
	if tagged, ok := value.(cbor.Tag); ok {
		value = tagged.Content
	}
	switch v := value.(type) {
	case string:
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return time.Time{}, failf("invalid validityInfo date: %v", err)
		}
		return t, nil
	case time.Time:
		return v, nil
	default:
		return time.Time{}, failf("invalid validityInfo date type %T", value)
	}
}

// cborToGo converts a decoded CBOR element value into a plain JSON-able Go
// value. Tags 0 (date/time) and 1004 (full-date) become their ISO strings,
// so a birth_date reads the same whichever the issuer chose.
func cborToGo(value any) any {
	switch v := value.(type) {
	case nil:
		return nil
	case cbor.Tag:
		if v.Number == 0 || v.Number == 1004 {
			if s, ok := v.Content.(string); ok {
				return s
			}
		}
		return cborToGo(v.Content)
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = cborToGo(item)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(v))
		for k, item := range v {
			out[fmt.Sprint(k)] = cborToGo(item)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, item := range v {
			out[k] = cborToGo(item)
		}
		return out
	default:
		return v
	}
}

// decodeCoseSign1 re-encodes an already-decoded CBOR value and decodes it
// into a coseSign1. Going through bytes is what lets the payload and
// unprotected-header members stay as cbor.RawMessage, which the signature
// checks need — decoding straight into `any` would have flattened them.
func decodeCoseSign1(raw any) (coseSign1, error) {
	encoded, err := cbor.Marshal(raw)
	if err != nil {
		return coseSign1{}, err
	}
	var sign1 coseSign1
	if err := cbor.Unmarshal(encoded, &sign1); err != nil {
		return coseSign1{}, err
	}
	return sign1, nil
}

// requireMap fetches a nested CBOR map, normalising the two map shapes
// fxamacker produces (map[string]any at the top level, map[any]any nested).
func requireMap(parent map[string]any, key, errMsg string) (map[string]any, error) {
	value, ok := parent[key]
	if !ok {
		return nil, failf("%s", errMsg)
	}
	switch m := value.(type) {
	case map[string]any:
		return m, nil
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, v := range m {
			out[fmt.Sprint(k)] = v
		}
		return out, nil
	default:
		return nil, failf("%s: not a CBOR map (%T)", errMsg, value)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
