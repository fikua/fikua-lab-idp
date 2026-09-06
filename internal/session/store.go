// Package session holds this authorization server's ephemeral protocol
// state: PAR requests, authorization codes, deferred (pending)
// authorizations awaiting end-user identification, and the revoked-token
// denylist. In-memory only. PAR requests and authorization codes carry a
// short TTL (parRequestTTL, authCodeTTL — 60s each) on top of single-use
// consumption, since a spec-conformant client may present either after
// time has passed without ever using it once.
//
// Access tokens are deliberately absent: since the split from
// fikua-lab-issuer they are stateless RFC 9068 JWTs (see
// internal/oauth2.Minter), validated offline by the Credential Issuer
// against this AS's published JWK Set. Only their jti survives here, and
// only for the revocation case — see RecordIssuedJTI.
package session

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// Data is the state bound to an authorization code.
type Data struct {
	SessionID string
	CreatedAt time.Time
	Metadata  map[string]any
}

// Store is the in-memory session store.
type Store struct {
	mu             sync.Mutex
	parRequests    map[string]parRequestEntry
	authCodes      map[string]Data
	pendingAuth    map[string]map[string]string
	identifyReplay map[string]identifyReplayEntry
	// identifiedSessions backs the reused-request_uri flow required by
	// FAPI 2.0 Security Profile §5.3.2.2 Note 3 (see
	// fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds):
	// completing identification must not itself finish the OAuth2
	// response, only mark the request_uri as identified so a *second*
	// GET /authorize call is the one that actually mints the code.
	identifiedSessions map[string]identifiedSessionEntry
	// issuedJTIByCode maps an authorization code to the jti of the access
	// token minted from it, kept past the code's own deletion so a later
	// reuse of that code can find the token to revoke — the stateless-JWT
	// equivalent of the old issuedTokensByCode map.
	issuedJTIByCode map[string]string
	// revokedJTIs is the denylist served at /oid4vci/v1/revoked-tokens
	// and polled by the Credential Issuer. Entries expire once the token
	// they name could no longer have been valid anyway.
	revokedJTIs map[string]time.Time
}

// parRequestEntry is a stored PAR request plus its creation time, so
// ConsumeParRequest can enforce parRequestTTL (RFC 9126 §2.2: request_uri
// values must be short-lived and single-use) — see authCodeTTL's doc
// comment for the equivalent on authorization codes.
type parRequestEntry struct {
	Params    map[string]string
	CreatedAt time.Time
}

// parRequestTTL matches the 60s expires_in this AS already advertises in
// the PAR response (HandlePar's return value) — enforcing it here is what
// makes that number true rather than just advisory.
const parRequestTTL = 60 * time.Second

// identifyReplayEntry is a cached /identify/complete result plus its
// expiry. Checked lazily on read, matching this package's
// no-background-sweeper style.
type identifyReplayEntry struct {
	Redirect string
	Expiry   time.Time
}

// NewStore builds an empty Store.
func NewStore() *Store {
	return &Store{
		parRequests:        make(map[string]parRequestEntry),
		authCodes:          make(map[string]Data),
		pendingAuth:        make(map[string]map[string]string),
		identifyReplay:     make(map[string]identifyReplayEntry),
		identifiedSessions: make(map[string]identifiedSessionEntry),
		issuedJTIByCode:    make(map[string]string),
		revokedJTIs:        make(map[string]time.Time),
	}
}

// RandomToken returns a base64url, no-padding random token of n bytes.
func RandomToken(n int) string {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// GenerateNonce returns a fresh 32-byte random c_nonce, bound into the
// access token this AS mints at /token. Unlike fikua-lab-issuer's Nonce
// Endpoint nonces, this one is not registered anywhere here: the
// Credential Issuer reads it out of the token's own c_nonce claim.
func GenerateNonce() string {
	return RandomToken(32)
}

// StoreParRequest stores a Pushed Authorization Request's form params
// under requestUri, stamped with the current time for parRequestTTL.
func (s *Store) StoreParRequest(requestURI string, params map[string]string) {
	s.mu.Lock()
	s.parRequests[requestURI] = parRequestEntry{Params: params, CreatedAt: time.Now()}
	s.mu.Unlock()
}

// ConsumeParRequest atomically removes and returns the params stored
// under requestURI. ok is false if unknown (already consumed, or never
// stored), or if it has outlived parRequestTTL — an expired entry is
// deleted (not left to linger) but treated as if it never existed, same
// as an unknown one (RFC 9126 §2.2's single-use, short-lived request_uri).
//
// Only the branch of HandleAuthorize that actually completes the OAuth2
// response (a valid, request_uri-bound identified session already
// present — see identifiedSessions) may call this. Reaching /authorize
// and being shown the identification form must not itself count as
// "using" request_uri, or the fapi2-security-profile-final-par-ensure-
// reused-request-uri-prior-to-auth-completion-succeeds conformance test's
// legitimate second visit would find it already gone — see PeekParRequest
// for the non-destructive lookup every other caller wants.
func (s *Store) ConsumeParRequest(requestURI string) (params map[string]string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, found := s.parRequests[requestURI]
	if !found {
		return nil, false
	}
	delete(s.parRequests, requestURI)
	if time.Since(entry.CreatedAt) > parRequestTTL {
		return nil, false
	}
	params, ok = entry.Params, true
	return params, ok
}

// PeekParRequest is ConsumeParRequest's non-destructive counterpart: it
// leaves the entry in place so a legitimate later visit (first-time
// identification, or a client_id/expiry check that fails and must still
// allow a retry) doesn't burn the request_uri's one use. Expiry is still
// enforced and still deletes the expired entry (nothing to preserve by
// leaving a dead entry around), it just doesn't delete a live one.
func (s *Store) PeekParRequest(requestURI string) (params map[string]string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, found := s.parRequests[requestURI]
	if !found {
		return nil, false
	}
	if time.Since(entry.CreatedAt) > parRequestTTL {
		delete(s.parRequests, requestURI)
		return nil, false
	}
	return entry.Params, true
}

// authCodeTTL is how long an authorization code stays redeemable after
// issuance (RFC 6749 §4.1.2 "SHOULD expire shortly", FAPI 2.0 Security
// Profile §5.3.2.1-11's own conformance check expects a code presented
// for the first time after this long to be rejected) — matches the
// PAR request_uri's own advertised 60s lifetime for consistency.
const authCodeTTL = 60 * time.Second

// CreateAuthCode stores session under a fresh authorization code.
// data.CreatedAt is stamped here (any caller-set value is overwritten)
// so ConsumeAuthCode can enforce authCodeTTL.
func (s *Store) CreateAuthCode(data Data) string {
	code := RandomToken(32)
	data.CreatedAt = time.Now()
	s.mu.Lock()
	s.authCodes[code] = data
	s.mu.Unlock()
	return code
}

// ConsumeAuthCode atomically removes and returns the session bound to
// code. ok is false if the code is unknown, has already been consumed
// once before, or has outlived authCodeTTL — an expired code is deleted
// (not left to linger) but treated as never having existed, exactly
// like an unknown one.
//
// reused reports specifically the "already consumed once before" case
// (RFC 6749 §4.1.2: reuse of a code MUST be denied and the tokens it
// issued SHOULD be revoked) — the caller uses this to revoke the access
// token minted from code via RevokeTokensForCode, something that's only
// possible because issuedJTIByCode outlives the code's own deletion here.
func (s *Store) ConsumeAuthCode(code string) (data Data, ok bool, reused bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok = s.authCodes[code]
	if !ok {
		_, wasIssued := s.issuedJTIByCode[code]
		return Data{}, false, wasIssued
	}
	delete(s.authCodes, code)
	if time.Since(data.CreatedAt) > authCodeTTL {
		return Data{}, false, false
	}
	return data, true, false
}

// RecordIssuedJTI remembers that jti was minted from authCode, so a later
// reuse of that code can revoke it. This is all that remains of the old
// in-memory access token table: the token itself is stateless, but the
// "which token came from which code" link RFC 6749 §4.1.2's revocation
// requirement depends on cannot be reconstructed from the token alone.
func (s *Store) RecordIssuedJTI(authCode, jti string) {
	s.mu.Lock()
	s.issuedJTIByCode[authCode] = jti
	s.mu.Unlock()
}

// RevokeTokensForCode revokes the access token (if any) minted from
// authCode — called when authCode is presented a second time. Since the
// token is a stateless JWT this AS cannot reach into, "revoke" means
// publishing its jti on the denylist RevokedJTIs serves, which the
// Credential Issuer polls and checks before honouring a token.
func (s *Store) RevokeTokensForCode(authCode string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	jti, ok := s.issuedJTIByCode[authCode]
	if !ok {
		return
	}
	delete(s.issuedJTIByCode, authCode)
	// Entries only need to outlive the token itself; anything older is
	// unreachable regardless of the denylist, since the Credential Issuer
	// rejects it on `exp` first. Doubled to absorb clock skew between the
	// two services plus one polling interval.
	s.revokedJTIs[jti] = time.Now().Add(2 * revokedJTIRetention)
}

// revokedJTIRetention bounds how long a revoked jti stays published. It
// must exceed oauth2.AccessTokenTTL plus the Credential Issuer's poll
// interval, or a token could outlive its own revocation notice.
const revokedJTIRetention = 10 * time.Minute

// RevokedJTIs returns the currently-published denylist, dropping entries
// whose tokens have expired on their own. Lazy expiry on read, matching
// this store's no-background-sweeper style.
func (s *Store) RevokedJTIs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	out := make([]string, 0, len(s.revokedJTIs))
	for jti, expiry := range s.revokedJTIs {
		if now.After(expiry) {
			delete(s.revokedJTIs, jti)
			continue
		}
		out = append(out, jti)
	}
	return out
}

// StorePendingAuth stores the OAuth2 params for an authorization request
// that's been deferred to the end-user identification flow, keyed by a
// fresh session token this returns. No TTL — it lives until
// ConsumePendingAuth removes it or the process restarts.
func (s *Store) StorePendingAuth(params map[string]string) string {
	token := RandomToken(16)
	s.mu.Lock()
	s.pendingAuth[token] = params
	s.mu.Unlock()
	return token
}

// GetPendingAuth is a non-destructive lookup of a pending authorization's
// params — used by GET /identify/claims, which a page may legitimately
// reload before ever submitting.
func (s *Store) GetPendingAuth(token string) (params map[string]string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	params, ok = s.pendingAuth[token]
	return params, ok
}

// ConsumePendingAuth atomically removes and returns the params stored
// under token. ok is false if unknown (already consumed, or never
// stored).
func (s *Store) ConsumePendingAuth(token string) (params map[string]string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	params, ok = s.pendingAuth[token]
	if ok {
		delete(s.pendingAuth, token)
	}
	return params, ok
}

// identifiedSessionTTL bounds how long a completed identification stays
// good for the follow-up /authorize visit that actually completes the
// OAuth2 response. Matches parRequestTTL: there is no reason for this
// leg of the flow to outlive the request_uri it's bound to.
const identifiedSessionTTL = parRequestTTL

// identifiedSessionEntry is a completed identification, bound to the one
// request_uri it was identified for — see CheckIdentified for why the
// binding is checked exactly, not just presence. RecordID is the
// issuance record CompleteIdentification created, carried here because
// the second /authorize visit that finishes the OAuth2 response has no
// issuer_state of its own to resolve it from (that PAR param is only
// ever present on the separate Credential-Issuer-initiated fast path).
type identifiedSessionEntry struct {
	RequestURI string
	RecordID   string
	CreatedAt  time.Time
}

// MarkIdentified records that requestURI's identification succeeded
// against recordID and returns a fresh opaque cookie value naming that
// fact, valid for identifiedSessionTTL. Called by CompleteIdentification
// instead of minting the authorization code directly — the code is only
// minted when this cookie later comes back to /authorize bound to the
// same request_uri (see CheckIdentified), which is what makes that
// second /authorize call, and not the /identify/complete POST, the one
// the FAPI conformance test observes completing the authorization.
func (s *Store) MarkIdentified(requestURI, recordID string) (cookieValue string) {
	cookieValue = RandomToken(24)
	s.mu.Lock()
	s.identifiedSessions[cookieValue] = identifiedSessionEntry{RequestURI: requestURI, RecordID: recordID, CreatedAt: time.Now()}
	s.mu.Unlock()
	return cookieValue
}

// CheckIdentified reports whether cookieValue names a live, unexpired
// identification for exactly requestURI, returning the issuance record it
// was identified against. The exact request_uri match is the anti-leakage
// property this whole mechanic depends on: two conformance tests (or two
// wallets) running their identification flows around the same time must
// never have test/wallet A's completed session satisfy test/wallet B's
// /authorize call for a different request_uri, even though both sessions
// are simultaneously live in this same map. Lazy expiry on read, matching
// this store's no-background-sweeper style (see identifyReplayTTL's
// GetIdentifyReplay for the same pattern) — the entry is left in place
// either way since nothing but memory is at stake and a caller will not
// retry across process restarts.
func (s *Store) CheckIdentified(cookieValue, requestURI string) (recordID string, ok bool) {
	if cookieValue == "" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, found := s.identifiedSessions[cookieValue]
	if !found || time.Since(entry.CreatedAt) > identifiedSessionTTL || entry.RequestURI != requestURI {
		return "", false
	}
	return entry.RecordID, true
}

// identifyReplayTTL bounds how long a completed /identify/complete
// result stays replayable — long enough to absorb a double form submit
// or a flaky network retry, short enough that reusing it later isn't a
// realistic risk.
const identifyReplayTTL = 120 * time.Second

// StoreIdentifyReplay caches redirect as the result for token, replayable
// for identifyReplayTTL — called once, right after ConsumePendingAuth
// succeeds, so a retried POST /identify/complete for the same session
// gets the same answer instead of "invalid or expired session".
func (s *Store) StoreIdentifyReplay(token, redirect string) {
	s.mu.Lock()
	s.identifyReplay[token] = identifyReplayEntry{Redirect: redirect, Expiry: time.Now().Add(identifyReplayTTL)}
	s.mu.Unlock()
}

// GetIdentifyReplay returns the cached /identify/complete result for
// token, if any and not yet expired. Lazy expiry: an expired entry is
// treated as absent (and left in place — this store has no background
// sweeper anywhere, matching its existing style).
func (s *Store) GetIdentifyReplay(token string) (redirect string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, found := s.identifyReplay[token]
	if !found || time.Now().After(entry.Expiry) {
		return "", false
	}
	return entry.Redirect, true
}
