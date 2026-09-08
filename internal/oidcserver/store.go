package oidcserver

import (
	"sync"
	"time"

	"github.com/fikua/fikua-lab-idp/internal/session"
)

// authRequestTTL bounds how long an unfinished AuthRequest survives —
// long enough for a person to scan a QR code and complete a wallet
// presentation, matching the OID4VP verification session TTL family
// (session.VerificationSession's own short-lived design) rather than a
// classic login form's much shorter expectation.
const authRequestTTL = 5 * time.Minute

// authCodeTTL is deliberately short: the code exists only for the
// instant between AuthorizeCallback minting it and the RP's own /token
// call, mirroring internal/authz's authorization_code lifetime
// philosophy (RFC 6749 §4.1.2 "SHOULD expire shortly").
const authCodeTTL = time.Minute

// refreshTokenTTL governs how long a refresh token (issued only to a
// client that requested offline_access) can mint new access tokens
// without the end user presenting their credential again. Kept in the
// same single-digit-to-low-double-digit-minutes family as this bridge's
// other lifetimes rather than the multi-day/permanent lifetimes a
// password-based OIDC provider might use — a verifiable-credential-backed
// identity re-proving itself periodically is the point, not a
// convenience to engineer away.
const refreshTokenTTL = 30 * time.Minute

type authRequestEntry struct {
	req       *authRequest
	expiresAt time.Time
	// verificationSessionID is the OID4VP session login.go started for
	// this AuthRequest, once one exists — linked separately from
	// authRequest itself (rather than a field on it) since op.AuthRequest
	// has no slot for bridge-specific bookkeeping and authRequest already
	// implements that interface exactly, no more.
	verificationSessionID string
}

type authCodeEntry struct {
	authRequestID string
	expiresAt     time.Time
}

type refreshTokenEntry struct {
	subject   string
	clientID  string
	scopes    []string
	expiresAt time.Time
}

// store holds this bridge's own OpenID Connect session state — AuthRequests,
// the authorization-code-to-AuthRequest-ID mapping, and refresh tokens.
// Deliberately separate from session.Store (which already exists for
// internal/authz and internal/verifier): this state has a different
// shape (op.AuthRequest, not that package's PAR/auth-code metadata maps)
// and this package should not need to touch session.Store's internals to
// add or change its own fields. The two only meet where oidcLogin (see
// login.go) reads a session.VerificationSession by ID to learn whether
// the Verifier has finished.
type store struct {
	mu            sync.Mutex
	authRequests  map[string]*authRequestEntry
	authCodes     map[string]*authCodeEntry
	refreshTokens map[string]*refreshTokenEntry
}

func newStore() *store {
	return &store{
		authRequests:  make(map[string]*authRequestEntry),
		authCodes:     make(map[string]*authCodeEntry),
		refreshTokens: make(map[string]*refreshTokenEntry),
	}
}

func (s *store) putAuthRequest(req *authRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authRequests[req.id] = &authRequestEntry{req: req, expiresAt: time.Now().Add(authRequestTTL)}
}

func (s *store) getAuthRequest(id string) (*authRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.authRequests[id]
	if !ok || time.Now().After(entry.expiresAt) {
		delete(s.authRequests, id)
		return nil, false
	}
	return entry.req, true
}

func (s *store) deleteAuthRequest(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.authRequests, id)
}

// linkVerificationSession records which OID4VP verification session a
// login page started for authRequestID — see login.go's
// verificationSessionFor for why a page reload must not start a second
// one.
func (s *store) linkVerificationSession(authRequestID, verificationSessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry, ok := s.authRequests[authRequestID]; ok {
		entry.verificationSessionID = verificationSessionID
	}
}

func (s *store) getVerificationSession(authRequestID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.authRequests[authRequestID]
	if !ok || entry.verificationSessionID == "" {
		return "", false
	}
	return entry.verificationSessionID, true
}

func (s *store) putAuthCode(code, authRequestID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authCodes[code] = &authCodeEntry{authRequestID: authRequestID, expiresAt: time.Now().Add(authCodeTTL)}
}

// consumeAuthCode returns and deletes the AuthRequest ID a code was
// issued for — single-use, matching internal/authz.Service's
// ConsumeAuthCode philosophy (RFC 6749 §4.1.2: a code MUST NOT be used
// more than once).
func (s *store) consumeAuthCode(code string) (authRequestID string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, found := s.authCodes[code]
	delete(s.authCodes, code)
	if !found || time.Now().After(entry.expiresAt) {
		return "", false
	}
	return entry.authRequestID, true
}

func (s *store) putRefreshToken(token, subject, clientID string, scopes []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshTokens[token] = &refreshTokenEntry{
		subject:   subject,
		clientID:  clientID,
		scopes:    scopes,
		expiresAt: time.Now().Add(refreshTokenTTL),
	}
}

func (s *store) getRefreshToken(token string) (*refreshTokenEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.refreshTokens[token]
	if !ok || time.Now().After(entry.expiresAt) {
		delete(s.refreshTokens, token)
		return nil, false
	}
	return entry, true
}

func (s *store) deleteRefreshToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.refreshTokens, token)
}

// randomToken is session.RandomToken re-exported under this package's own
// name at the call sites that use it, to keep every ID/token/code this
// package mints visibly generated the same way (crypto/rand, base64url)
// as the rest of this service — see session.RandomToken's own doc
// comment for the concrete guarantee.
func randomToken(n int) string { return session.RandomToken(n) }
