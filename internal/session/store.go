// Package session holds this service's ephemeral protocol state: the
// authorization server's PAR requests, authorization codes, deferred
// (pending) authorizations awaiting end-user identification and
// revoked-token denylist, plus the OID4VP Verifier's verification sessions
// (see VerificationSession). In-memory only. PAR requests and authorization codes carry a
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

	fikuacrypto "github.com/fikua/fikua-lab-idp/internal/crypto"
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
	// verifications holds the OID4VP Verifier's sessions, and
	// verificationIDByState indexes them by the `state` a wallet echoes
	// back at /oid4vp/v1/response (there is nothing else in a direct_post
	// body to resolve a session from).
	//
	// Kept in this store rather than a separate one: the shape is the same
	// as everything else here — ephemeral, in-memory, TTL'd, lazily
	// expired, gone on restart — and a second store would duplicate the
	// mutex, the constructor and the random-token helper to hold a map.
	// This does mean one process holds both roles' state; if the Verifier
	// ever splits into its own service (as the AS split out of the
	// issuer), this is the seam to cut along.
	verifications          map[string]*VerificationSession
	verificationIDByState  map[string]string
	verificationIDByEncKID map[string]string
}

// VerificationSession is one OID4VP verification: the Authorization
// Request sent to a wallet, and whatever came back. Ported from the Java
// verifier's SessionStore.VerificationSession record, with two shape
// changes.
//
// First, DCQLQuery is the marshalled query object rather than the JSON
// string the Java version stored: that version re-parsed its own JSON on
// every response to recover the format and doctype_value, which is a round
// trip through a string this process never needed to make.
//
// Second, the claims are held as a map instead of a JSON string, for the
// same reason — GetResult in Java deserialized what CreateSession had just
// serialized.
type VerificationSession struct {
	SessionID    string
	State        string
	Nonce        string
	DCQLQuery    DCQLQuery
	ResponseMode string
	ClientID     string
	ResponseURI  string
	RequestJWT   string
	// EncryptionKey is this session's own response-encryption keypair
	// (nil unless ResponseMode is direct_post.jwt). OID4VP §8.3 / HAIP
	// §5.5 require a Verifier supply an ephemeral key specific to each
	// Authorization Request — a key held on the Service and reused
	// across sessions failed VP1FinalCheckEncryptionKeyNotReused in OIDF
	// conformance testing, since the same public key showed up in two
	// different requests' client_metadata.
	EncryptionKey *fikuacrypto.ResponseEncryptionKey
	// Status is one of: pending, request_sent, verified, failed.
	Status string
	// VPTokens and VerifiedClaims are keyed by DCQLCredentialQuery.ID, one
	// entry per credential requested in DCQLQuery.Credentials. A
	// single-credential session (the common case) still has exactly one
	// key here — there is no separate flat-field path for it.
	VPTokens       map[string]string
	VerifiedClaims map[string]map[string]any
	Error          string
	CreatedAt      time.Time
}

// DCQLQuery is the subset of the Digital Credentials Query Language (OID4VP
// 1.0 Final §6) this Verifier both builds and reads back. Held here, in the
// session package, because the session is what owns it for the duration of
// a verification — internal/verifier builds it and reads it back off the
// session when the response arrives.
type DCQLQuery struct {
	Credentials []DCQLCredentialQuery `json:"credentials"`
	// CredentialSets names which combinations of the above Credentials IDs
	// must be satisfied together (OID4VP §6.3.1). Omitted for a
	// single-credential query, where it would say nothing a bare
	// Credentials entry doesn't already require on its own.
	CredentialSets []DCQLCredentialSet `json:"credential_sets,omitempty"`
}

// DCQLCredentialSet is one entry of DCQLQuery.CredentialSets: Options is a
// list of alternative ID combinations, any one of which satisfies this set.
// This Verifier only ever emits a single option per set — HAIP is a fixed
// profile with no "either X or Y" credential choices — but Options stays a
// [][]string rather than []string to match the spec shape exactly, since a
// wallet's DCQL parser expects it.
type DCQLCredentialSet struct {
	Options [][]string `json:"options"`
}

// DCQLCredentialQuery is one credential's query (OID4VP §6.1).
type DCQLCredentialQuery struct {
	ID     string           `json:"id"`
	Format string           `json:"format"`
	Meta   *DCQLMeta        `json:"meta,omitempty"`
	Claims []DCQLClaimQuery `json:"claims,omitempty"`
}

// DCQLMeta is format-specific credential filtering (OID4VP §6.1): SD-JWT VC
// filters on vct_values, mso_mdoc on a single doctype_value. Only the field
// belonging to the query's format is emitted.
type DCQLMeta struct {
	VCTValues    []string `json:"vct_values,omitempty"`
	DoctypeValue string   `json:"doctype_value,omitempty"`
}

// DCQLClaimQuery names one requested claim (OID4VP §6.3). Path is a single
// segment for SD-JWT VC and two segments ([namespace, element]) for
// mso_mdoc.
type DCQLClaimQuery struct {
	Path      []string `json:"path"`
	Values    []string `json:"values,omitempty"`
	Essential *bool    `json:"essential,omitempty"`
}

// verificationSessionTTL is how long a verification session stays usable
// after creation. Far longer than parRequestTTL/authCodeTTL (60s each)
// because the human is in the loop for all of it: they have to notice the
// QR code, unlock a phone, open a wallet app, pick a credential and consent
// to releasing it — a minute is not enough, and a wallet that has to
// install or update first will take longer still. Five minutes is the same
// window the Java verifier put on the Request Object's own `exp`, so the
// session and the request it carries die together rather than one
// outliving the other; anything much beyond that is just a stale QR code on
// a screen somebody walked away from.
const verificationSessionTTL = 5 * time.Minute

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

		verifications:          make(map[string]*VerificationSession),
		verificationIDByState:  make(map[string]string),
		verificationIDByEncKID: make(map[string]string),
	}
}

// StoreVerification stores a freshly created verification session, stamping
// CreatedAt so the TTL is measured from here (any caller-set value is
// overwritten, matching CreateAuthCode).
func (s *Store) StoreVerification(v VerificationSession) {
	v.CreatedAt = time.Now()
	s.mu.Lock()
	s.verifications[v.SessionID] = &v
	s.verificationIDByState[v.State] = v.SessionID
	if v.EncryptionKey != nil {
		s.verificationIDByEncKID[v.EncryptionKey.KID()] = v.SessionID
	}
	s.mu.Unlock()
}

// FindVerification returns the session with this id. ok is false if unknown
// or past verificationSessionTTL — an expired session is deleted on read
// (lazy expiry, no background sweeper, matching this store's style
// throughout) and then treated exactly like one that never existed, so a
// wallet arriving late gets the same answer as one arriving with a bad id.
func (s *Store) FindVerification(sessionID string) (VerificationSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.findVerificationLocked(sessionID)
}

// FindVerificationByState resolves the `state` a wallet echoes back at
// /oid4vp/v1/response to its session. Same expiry semantics as
// FindVerification.
func (s *Store) FindVerificationByState(state string) (VerificationSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sessionID, ok := s.verificationIDByState[state]
	if !ok {
		return VerificationSession{}, false
	}
	return s.findVerificationLocked(sessionID)
}

// FindVerificationByEncryptionKID resolves a direct_post.jwt response's own
// JWE `kid` (crypto.PeekResponseEncryptionKID) to its session — needed
// because each session now carries its own response-encryption key, so the
// session has to be known before it is known which private key to try
// decrypting with. Same expiry semantics as FindVerification.
func (s *Store) FindVerificationByEncryptionKID(kid string) (VerificationSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sessionID, ok := s.verificationIDByEncKID[kid]
	if !ok {
		return VerificationSession{}, false
	}
	return s.findVerificationLocked(sessionID)
}

// findVerificationLocked is FindVerification's body; callers hold s.mu.
func (s *Store) findVerificationLocked(sessionID string) (VerificationSession, bool) {
	v, ok := s.verifications[sessionID]
	if !ok {
		return VerificationSession{}, false
	}
	if time.Since(v.CreatedAt) > verificationSessionTTL {
		s.deleteVerificationLocked(v)
		return VerificationSession{}, false
	}
	return *v, true
}

func (s *Store) deleteVerificationLocked(v *VerificationSession) {
	delete(s.verifications, v.SessionID)
	delete(s.verificationIDByState, v.State)
	if v.EncryptionKey != nil {
		delete(s.verificationIDByEncKID, v.EncryptionKey.KID())
	}
}

// UpdateVerificationStatus advances a live session's status (pending →
// request_sent). A no-op for an unknown or expired session: the status is
// telemetry for the polling frontend, never a gate on anything, so there is
// nothing for a caller to handle.
func (s *Store) UpdateVerificationStatus(sessionID, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.findVerificationPointerLocked(sessionID); ok {
		v.Status = status
	}
}

// UpdateVerificationResult records the outcome of a presentation against
// its session — status "verified" with claims per credential-query ID, or
// "failed" with the reason. vpTokens and claims are both keyed by
// DCQLCredentialQuery.ID; a failed verification may still pass a partial
// vpTokens (whatever was received) for diagnostics, with claims nil.
func (s *Store) UpdateVerificationResult(sessionID, status string, vpTokens map[string]string, claims map[string]map[string]any, verifyErr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.findVerificationPointerLocked(sessionID); ok {
		v.Status = status
		v.VPTokens = vpTokens
		v.VerifiedClaims = claims
		v.Error = verifyErr
	}
}

// findVerificationPointerLocked returns the stored session itself (not a
// copy) for in-place mutation, applying the same lazy expiry as the read
// path so an expired session cannot be resurrected by an update.
func (s *Store) findVerificationPointerLocked(sessionID string) (*VerificationSession, bool) {
	v, ok := s.verifications[sessionID]
	if !ok {
		return nil, false
	}
	if time.Since(v.CreatedAt) > verificationSessionTTL {
		s.deleteVerificationLocked(v)
		return nil, false
	}
	return v, true
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
