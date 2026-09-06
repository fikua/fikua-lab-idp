// Package statuslistcheck fetches and reads an IETF Token Status List
// token (draft-ietf-oauth-status-list-21) to answer one question: what
// status does entry idx carry. This is the Verifier-side counterpart of
// fikua-lab-issuer's internal/statuslist, which builds and signs these
// tokens — named differently (not just "statuslist") since importing a
// package across repos isn't how this project shares code (see
// internal/oauth2/dpop.go's doc comment for the established rationale);
// this is a from-scratch, read-only reimplementation of just the wire
// format, not a port of the issuer's build-side logic.
package statuslistcheck

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Status values, per draft-ietf-oauth-status-list-21 §7.1. Only the ones
// this Verifier's own issuer actually emits are named; any other value
// still round-trips through Status correctly, just unnamed.
const (
	StatusValid     uint8 = 0
	StatusInvalid   uint8 = 1
	StatusSuspended uint8 = 2
)

// bitsPerEntry matches fikua-lab-issuer/internal/statuslist.Bits — the two
// sides of this wire format have to agree on it, but neither reads it off
// the token itself; draft-ietf-oauth-status-list-21 §5's "bits" claim is
// theoretically per-token but this ecosystem only ever produces 2.
const bitsPerEntry = 2

// Fetch retrieves and reads a Token Status List token from uri, returning
// the status of entry idx. It does not validate the token's signature
// against a trust anchor — matching this Verifier's existing SD-JWT VC/
// mdoc issuer-signature posture (see sdjwtverify.Verify's doc comment):
// conformance testing today, a real Issuer trust anchor is future work
// (see docs/issuer-trust-validation.md).
func Fetch(ctx context.Context, uri string, idx int64) (uint8, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return 0, fmt.Errorf("statuslistcheck: building request for %s: %w", uri, err)
	}
	req.Header.Set("Accept", "application/statuslist+jwt")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("statuslistcheck: fetching %s: %w", uri, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("statuslistcheck: fetching %s: unexpected status %d", uri, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("statuslistcheck: reading %s: %w", uri, err)
	}

	return statusAt(body, idx)
}

// statusAt parses a Status List Token JWT (unverified — see Fetch's doc
// comment) and returns the status bits at idx.
func statusAt(tokenBytes []byte, idx int64) (uint8, error) {
	token, err := jwt.Parse(tokenBytes, jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return 0, fmt.Errorf("statuslistcheck: parsing status list token: %w", err)
	}

	var statusListClaim map[string]any
	if err := token.Get("status_list", &statusListClaim); err != nil {
		return 0, fmt.Errorf("statuslistcheck: status list token has no status_list claim: %w", err)
	}
	lst, ok := statusListClaim["lst"].(string)
	if !ok || lst == "" {
		return 0, fmt.Errorf("statuslistcheck: status_list claim has no lst field")
	}
	bits := bitsPerEntry
	if b, ok := statusListClaim["bits"].(float64); ok && b > 0 {
		bits = int(b)
	}

	raw, err := decompressLST(lst)
	if err != nil {
		return 0, err
	}

	byteIndex := (idx * int64(bits)) / 8
	bitOffset := uint((idx * int64(bits)) % 8)
	if byteIndex < 0 || int(byteIndex) >= len(raw) {
		return 0, fmt.Errorf("statuslistcheck: idx %d out of range for a %d-byte bitstring", idx, len(raw))
	}
	mask := uint8((1 << bits) - 1)
	return (raw[byteIndex] >> bitOffset) & mask, nil
}

// decompressLST reverses fikua-lab-issuer/internal/statuslist.
// compressAndEncode: base64url-decode, then inflate the ZLIB/RFC1950
// stream (draft-ietf-oauth-status-list-21 §4.1 — not bare DEFLATE).
func decompressLST(lst string) ([]byte, error) {
	compressed, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(lst))
	if err != nil {
		return nil, fmt.Errorf("statuslistcheck: lst is not valid base64url: %w", err)
	}
	r, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("statuslistcheck: lst is not a valid zlib stream: %w", err)
	}
	defer r.Close()
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("statuslistcheck: inflating lst: %w", err)
	}
	return raw, nil
}

// StatusListRef is the {status_list: {idx, uri}} shape a presented
// credential's own "status" claim carries (draft-ietf-oauth-status-list-21
// §6.2), as decoded straight off the wire (json.Unmarshal into a
// map[string]any leaves idx as float64, not int64 — ParseRef's job).
type StatusListRef struct {
	Idx int64
	URI string
}

// ParseRef reads a StatusListRef out of the raw "status" claim map
// sdjwtverify.VerifyWithStatus returns. ok is false when status is nil or
// malformed — the caller decides whether "this credential carries no
// status claim" is acceptable (see Fetch's doc comment).
func ParseRef(status map[string]any) (ref StatusListRef, ok bool) {
	inner, ok := status["status_list"].(map[string]any)
	if !ok {
		return StatusListRef{}, false
	}
	idxFloat, ok := inner["idx"].(float64)
	if !ok {
		return StatusListRef{}, false
	}
	uri, ok := inner["uri"].(string)
	if !ok || uri == "" {
		return StatusListRef{}, false
	}
	return StatusListRef{Idx: int64(idxFloat), URI: uri}, true
}

// statusName renders a status byte the way this package's own constants
// name it, falling back to the raw number — used only for error/log
// messages, never for a status comparison (compare the byte itself).
func statusName(status uint8) string {
	switch status {
	case StatusValid:
		return "VALID"
	case StatusInvalid:
		return "INVALID"
	case StatusSuspended:
		return "SUSPENDED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", status)
	}
}

// CheckValid fetches the Status List Token ref points at and requires the
// entry read StatusValid — the one call a Verifier needs to satisfy HAIP
// §7 point 2.2.2.2 ("the Verifier did not fetch the Token Status List...
// so it cannot have checked the credential's revocation status"). Any
// non-VALID status is reported by name, not just its numeric value, so a
// rejected presentation's error is legible without cross-referencing the
// spec.
func CheckValid(ctx context.Context, ref StatusListRef) error {
	status, err := Fetch(ctx, ref.URI, ref.Idx)
	if err != nil {
		return fmt.Errorf("statuslistcheck: checking status list entry %d at %s: %w", ref.Idx, ref.URI, err)
	}
	if status != StatusValid {
		return fmt.Errorf("statuslistcheck: credential status is %s, not VALID", statusName(status))
	}
	return nil
}
