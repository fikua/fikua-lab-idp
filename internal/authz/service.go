// Package authz implements this authorization server's OAuth2 flow —
// HAIP only: authorization_code grant via PAR, with DPoP
// sender-constraining and ATCA client attestation mandatory throughout,
// and PKCE (S256) mandatory at the token endpoint. There is no
// pre-authorized_code profile; this AS does not implement one.
//
// Extracted from fikua-lab-issuer's internal/issuance, which used to
// embed this AS alongside the credential issuance it actually exists to
// do. The one behavioural change from that extraction: access tokens are
// now RFC 9068 JWTs (see internal/oauth2.Minter) rather than opaque
// strings looked up in a session store the Credential Issuer shared.
package authz

import (
	"context"
	"crypto/x509"
	"net/url"

	"github.com/fikua/fikua-lab-idp/internal/issuerclient"
	"github.com/fikua/fikua-lab-idp/internal/oauth2"
	"github.com/fikua/fikua-lab-idp/internal/session"
)

// boundClientIDKey is the internal (non-spec) key used to carry the
// attested client_id that made a PAR request through to the resulting
// authorization code's session metadata — see HandlePar's doc comment.
const boundClientIDKey = "_bound_client_id"

// pendingRequestURIKey is the internal (non-spec) key HandleAuthorize
// stashes the original request_uri under when it defers to
// identification. CompleteIdentification needs it to know which
// request_uri to mark identified (session.Store.MarkIdentified) and
// which /authorize call to redirect back to — the PAR params themselves
// never carry request_uri (HandlePar rejects it per RFC 9126 §2.1).
const pendingRequestURIKey = "_pending_request_uri"

// IdentifiedCookieName is the opaque cookie CompleteIdentification sets
// and HandleAuthorize's second visit reads back, naming a completed
// identification bound to one request_uri — see session.Store's
// MarkIdentified/CheckIdentified for the actual state. Exported so the
// httpapi layer (which alone touches http.Cookie) uses the exact same
// name on both ends without duplicating the literal.
const IdentifiedCookieName = "fikua_idp_identified"

// PIDConfigID is the credential_configuration_id the identification form
// collects claims for. This ecosystem only issues PID today — kept as a
// constant in one place so a future scope-to-config mapping has somewhere
// to live.
const PIDConfigID = "urn:eudi:pid:1"

// requestURIPrefix is the PAR request_uri format prefix, per RFC 9126.
const requestURIPrefix = "urn:ietf:params:oauth:request_uri:"

// Service implements the authorization server's endpoints.
type Service struct {
	baseURL      string
	sessions     *session.Store
	issuer       *issuerclient.Client
	minter       *oauth2.Minter
	jtis         *oauth2.JTIStore
	attestations *oauth2.ClientAttestationValidator
}

// NewService builds a Service. baseURL is this AS's own identifier (e.g.
// "https://idp.fikua.com"), used as the expected `htu` of every DPoP
// proof presented here and the expected `aud` of every client-attestation
// PoP. issuer resolves and creates issuance records on the Credential
// Issuer. minter signs the access tokens. walletProviderAnchor optionally
// pins client-attestation (WIA) signature verification to a single
// trusted CA — pass nil to accept any self-consistent WIA (no
// chain-of-trust check).
func NewService(baseURL string, sessions *session.Store, issuer *issuerclient.Client, minter *oauth2.Minter, walletProviderAnchor *x509.Certificate) *Service {
	return &Service{
		baseURL:      baseURL,
		sessions:     sessions,
		issuer:       issuer,
		minter:       minter,
		jtis:         oauth2.NewJTIStore(),
		attestations: oauth2.NewClientAttestationValidator(walletProviderAnchor, baseURL),
	}
}

// BuildAuthorizationRedirect adds the authorization response params
// (code, state, iss) to result.RedirectURI. Registered redirect_uris can
// already carry their own query string (RFC 6749 §3.1.2 explicitly
// allows this — the OIDF conformance suite's "matching callback
// parameters" test registers one with ?dummy1=lorem&dummy2=ipsum and
// requires it survive intact), so this must merge into any existing
// query rather than always starting a fresh "?". Shared by the httpapi
// layer's /authorize 302 and CompleteIdentification's JSON redirect
// field — both produce the exact same URL shape.
func BuildAuthorizationRedirect(result AuthorizeResult, issuer string) (string, error) {
	u, err := url.Parse(result.RedirectURI)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("code", result.Code)
	if result.State != "" {
		q.Set("state", result.State)
	}
	q.Set("iss", issuer)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// HandlePar implements the Pushed Authorization Request endpoint (RFC
// 9126). Client attestation is mandatory; code_challenge_method, if
// given, must be S256. Returns the request_uri and its 60s lifetime
// (enforced by session.parRequestTTL, not merely advertised).
//
// DPoP-PAR binding (RFC 9449 §10.1): a client may bind the eventual
// authorization code to a DPoP key either by sending a dpop_jkt form
// parameter, or by attaching a DPoP proof to the PAR request itself
// (in which case the proof's key thumbprint is treated as if it were
// dpop_jkt). Both mechanisms must be supported, and if both are used at
// once, the thumbprints must match — the resolved thumbprint, whichever
// path it came from, is stored on the PAR params under "dpop_jkt" so
// HandleAuthCodeToken can enforce it against the token endpoint's own
// DPoP proof later.
func (s *Service) HandlePar(params map[string]string, wiaHeader, popHeader, dpopHeader string) (requestURI string, expiresIn int, err error) {
	// RFC 9126 §2.1: request_uri is the one authorization-endpoint
	// parameter a pushed authorization request MUST NOT carry — it's
	// what this endpoint produces, not something a client can push in.
	if params["request_uri"] != "" {
		return "", 0, oauth2.BadRequest(oauth2.InvalidRequest, "request_uri must not be provided in a pushed authorization request")
	}

	clientID, attErr := s.attestations.Resolve(wiaHeader, popHeader, params["client_assertion_type"], params["client_assertion"])
	if attErr != nil {
		return "", 0, attErr
	}
	if clientID == "" {
		return "", 0, oauth2.BadRequest(oauth2.InvalidRequest, "Client attestation is required")
	}
	// Bound to the authorization code at /authorize time and re-checked
	// against the /token endpoint's own client attestation in
	// HandleAuthCodeToken (RFC 6749 §4.1.3: the token endpoint must
	// reject a code presented by a client other than the one it was
	// issued to). boundClientID isn't a real OAuth2 param — it's an
	// internal key on the same params map that rides along through
	// StoreParRequest/StorePendingAuth to CreateAuthCode's session
	// metadata.
	params[boundClientIDKey] = clientID

	// FAPI 2.0 Security Profile §5.3.2.2-1: only the authorization_code
	// flow (response_type=code) is permitted — code id_token and other
	// hybrid/implicit response types would return an id_token via the
	// browser, where it can leak.
	if responseType, ok := params["response_type"]; ok && responseType != "code" {
		return "", 0, oauth2.BadRequest(oauth2.UnsupportedResponseType, "Only response_type=code is supported")
	}

	// FAPI 2.0 Security Profile §5.3.2.2-5 / RFC 7636: PKCE is mandatory,
	// not merely validated when present.
	if params["code_challenge"] == "" {
		return "", 0, oauth2.BadRequest(oauth2.InvalidRequest, "code_challenge is required")
	}
	if method := params["code_challenge_method"]; method != "S256" {
		return "", 0, oauth2.BadRequest(oauth2.InvalidRequest, "Only S256 code_challenge_method is supported")
	}

	if dpopHeader != "" {
		dpopKey, err := oauth2.ValidateDPoPProof(dpopHeader, "POST", s.baseURL+"/oid4vci/v1/par", "", s.jtis)
		if err != nil {
			return "", 0, err
		}
		thumbprint, err := oauth2.DPoPThumbprint(dpopKey)
		if err != nil {
			return "", 0, oauth2.BadRequest(oauth2.InvalidRequest, "Failed to compute DPoP thumbprint: "+err.Error())
		}
		if declared := params["dpop_jkt"]; declared != "" && declared != thumbprint {
			return "", 0, oauth2.BadRequest(oauth2.InvalidRequest, "dpop_jkt does not match the DPoP proof's key")
		}
		params["dpop_jkt"] = thumbprint
	}

	requestURI = requestURIPrefix + session.RandomToken(16)
	s.sessions.StoreParRequest(requestURI, params)
	return requestURI, 60, nil
}

// AuthorizeResult is the outcome of GET /oid4vci/v1/authorize. Exactly
// one of two shapes applies: IdentifyRedirect non-empty means "302 the
// browser here instead, ignore the rest" (deferring to the end-user
// identification flow); otherwise Code/RedirectURI/State carry the
// completed OAuth2 authorization response.
type AuthorizeResult struct {
	Code             string
	RedirectURI      string
	State            string
	IdentifyRedirect string
}

// HandleAuthorize resolves a PAR request_uri into an authorization code,
// bound to the issuance record referenced by the PAR params' issuer_state
// (set by the Credential Issuer's own TriggerIssuance when it built the
// credential offer). Only the client_id-bearing, PAR-backed flow is
// implemented — there is no client_id-less wallet-initiated sub-flow.
//
// When no issuer_state resolves an existing issuance record, the request
// is deferred to the end-user identification flow (see
// ResolveIdentifyScope/CompleteIdentification) — but per FAPI 2.0
// Security Profile §5.3.2.2 Note 3
// (fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds),
// a *first* visit that lands here must only show the identification page
// — it must not complete the authorization. Only a *second* /authorize
// visit, made after identification has succeeded, is allowed to mint the
// code. That second visit is recognized by identifiedCookie: an opaque
// cookie value (session.Store.MarkIdentified/CheckIdentified) that
// CompleteIdentification sets and redirects the browser straight back to
// this same /authorize call with. So request_uri is only PEEKed (not
// consumed) here on a first visit — burning its one RFC 9126 §2.2 use
// happens only once identification is confirmed, on the success path
// below.
//
// A spec-conformant wallet/test client has no reason to know about
// issuer_state as an out-of-band mechanism at all: it may reuse a
// credential_offer's issuer_state for a second authorization (e.g. a
// conformance test exercising two OAuth2 clients against the same
// offer), or send a completely fresh authorization request with no
// issuer_state. Either case defers to identification.
//
// queryClientID, if non-empty, is the client_id query parameter this
// GET request itself carried (distinct from the PAR-time client_id that
// minted requestURI). PAR §2.2 requires a request_uri be bound to the
// client that pushed it — RFC 9126's PAR-3-3 conformance check catches
// exactly this: presenting client A's request_uri while claiming to be
// client B. Checked on every visit, first or second, same as before.
func (s *Service) HandleAuthorize(ctx context.Context, requestURI, queryClientID, identifiedCookie string) (AuthorizeResult, error) {
	if requestURI == "" {
		return AuthorizeResult{}, oauth2.BadRequest(oauth2.InvalidRequest, "Missing request_uri")
	}
	// Non-destructive: a first visit (the common case) must leave
	// request_uri exactly as usable as it was, since this visit does not
	// complete the authorization. Only the identified branch below
	// re-fetches destructively via ConsumeParRequest.
	params, ok := s.sessions.PeekParRequest(requestURI)
	if !ok {
		return AuthorizeResult{}, oauth2.BadRequest(oauth2.InvalidRequest, "Invalid or expired request_uri")
	}
	if queryClientID != "" && params["client_id"] != "" && queryClientID != params["client_id"] {
		return AuthorizeResult{}, oauth2.BadRequest(oauth2.InvalidRequest, "request_uri is bound to a different client")
	}

	var recordID string
	if issuerState := params["issuer_state"]; issuerState != "" {
		rec, found, err := s.issuer.FindByIssuerState(ctx, issuerState)
		if err != nil {
			return AuthorizeResult{}, oauth2.ServiceUnavailable(oauth2.InvalidRequest, "Credential Issuer unreachable: "+err.Error())
		}
		if found {
			recordID = rec.ID
		}
	}
	if recordID != "" {
		// issuer_state already resolved an existing issuance record: this
		// is the pre-existing, separate fast path (a Credential Issuer
		// -initiated offer) that never went through end-user
		// identification in the first place, so there is no "first visit
		// vs second visit" distinction to make — it always completes
		// immediately, exactly as before this change.
		params, ok = s.sessions.ConsumeParRequest(requestURI)
		if !ok {
			return AuthorizeResult{}, oauth2.BadRequest(oauth2.InvalidRequest, "Invalid or expired request_uri")
		}
		code := s.sessions.CreateAuthCode(session.Data{
			SessionID: session.RandomToken(16),
			Metadata:  authCodeMetadata(recordID, params),
		})
		return AuthorizeResult{Code: code, RedirectURI: params["redirect_uri"], State: params["state"]}, nil
	}

	// No issuance record: this is the identification-gated branch the
	// FAPI test targets. A valid session cookie bound to this exact
	// request_uri (CheckIdentified enforces the binding — never accept a
	// cookie minted for a different request_uri, see
	// session.Store.CheckIdentified's doc comment for why) means
	// identification already happened and this is the legitimate second
	// visit: consume request_uri for real now and complete the response.
	if identifiedRecordID, identified := s.sessions.CheckIdentified(identifiedCookie, requestURI); identified {
		params, ok = s.sessions.ConsumeParRequest(requestURI)
		if !ok {
			return AuthorizeResult{}, oauth2.BadRequest(oauth2.InvalidRequest, "Invalid or expired request_uri")
		}
		code := s.sessions.CreateAuthCode(session.Data{
			SessionID: session.RandomToken(16),
			Metadata:  authCodeMetadata(identifiedRecordID, params),
		})
		return AuthorizeResult{Code: code, RedirectURI: params["redirect_uri"], State: params["state"]}, nil
	}

	// First visit (or a visit with no/wrong/expired session): defer to
	// identification without touching request_uri. pendingRequestURIKey
	// rides along on the same params map so CompleteIdentification knows
	// which request_uri to mark identified and which /authorize call to
	// send the browser back to.
	pending := make(map[string]string, len(params)+1)
	for k, v := range params {
		pending[k] = v
	}
	pending[pendingRequestURIKey] = requestURI
	token := s.sessions.StorePendingAuth(pending)
	return AuthorizeResult{IdentifyRedirect: s.baseURL + "/identify/?session=" + token}, nil
}

// authCodeMetadata carries everything HandleAuthCodeToken must re-check
// or mint into the access token, from the PAR params that produced this
// authorization code.
func authCodeMetadata(recordID string, params map[string]string) map[string]any {
	metadata := map[string]any{
		"issuanceRecordId": recordID,
		boundClientIDKey:   params[boundClientIDKey],
	}
	if codeChallenge := params["code_challenge"]; codeChallenge != "" {
		metadata["code_challenge"] = codeChallenge
	}
	if dpopJKT := params["dpop_jkt"]; dpopJKT != "" {
		metadata["dpop_jkt"] = dpopJKT
	}
	return metadata
}

// ResolveIdentifyScope is a non-destructive lookup for GET
// /identify/claims: given a pending-authorization session token (minted
// by HandleAuthorize's identify-redirect branch), returns the
// credential_configuration_id the identification form should collect
// claims for.
func (s *Service) ResolveIdentifyScope(sessionToken string) (credentialConfigID string, err error) {
	if _, ok := s.sessions.GetPendingAuth(sessionToken); !ok {
		return "", oauth2.BadRequest(oauth2.InvalidRequest, "Invalid or expired identification session")
	}
	return PIDConfigID, nil
}

// CompleteIdentification implements POST /identify/complete. It no
// longer completes the OAuth2 authorization response itself — per FAPI
// 2.0 Security Profile §5.3.2.2 Note 3
// (fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds),
// authentication must not be considered done until a *second* visit to
// /authorize observes it. So this only creates the issuance record and
// then marks the original request_uri's session as identified
// (session.Store.MarkIdentified), returning cookieValue for the httpapi
// layer to set on the response and a redirect straight back to
// /authorize?request_uri=<original> — whose second invocation (now
// finding a valid, matching session) is what actually mints the code and
// redirects to the client's own redirect_uri.
//
// Replay-safe for identifyReplayTTL: a retried POST for the same
// session (double form submit, flaky network) gets back the exact same
// redirect instead of "invalid or expired session", since the
// pending-authorization token itself is consumed destructively
// (single-use) on the first successful call. On a replay, cookieValue is
// returned empty — the browser's original Set-Cookie already landed, and
// minting a second live cookie for the same request_uri is unnecessary.
func (s *Service) CompleteIdentification(ctx context.Context, sessionToken string, credentialData map[string]any, sourceType, sourceRef string) (redirect string, cookieValue string, err error) {
	if cached, ok := s.sessions.GetIdentifyReplay(sessionToken); ok {
		return cached, "", nil
	}

	params, ok := s.sessions.ConsumePendingAuth(sessionToken)
	if !ok {
		return "", "", oauth2.BadRequest(oauth2.InvalidRequest, "Invalid or expired identification session")
	}
	requestURI := params[pendingRequestURIKey]
	if requestURI == "" {
		// Can only happen if HandleAuthorize's identify-redirect branch
		// changes without this field staying in sync — fail loudly rather
		// than silently completing with no second-visit gate at all.
		return "", "", oauth2.BadRequest(oauth2.InvalidRequest, "Identification session is missing its request_uri")
	}

	rec, err := s.issuer.Create(ctx, issuerclient.CreateRequest{
		CredentialType: PIDConfigID,
		CredentialData: credentialData,
		SourceType:     sourceType,
		SourceRef:      sourceRef,
	})
	if err != nil {
		return "", "", oauth2.ServiceUnavailable(oauth2.InvalidRequest, "Credential Issuer unreachable: "+err.Error())
	}

	// rec.ID travels to the second /authorize visit via the identified
	// session entry itself (session.Store.CheckIdentified returns it) —
	// that visit has no issuer_state PAR param of its own to resolve an
	// issuance record from, since this whole branch only exists for
	// requests that never had one.
	cookieValue = s.sessions.MarkIdentified(requestURI, rec.ID)
	redirect = s.baseURL + "/oid4vci/v1/authorize?request_uri=" + url.QueryEscape(requestURI)

	s.sessions.StoreIdentifyReplay(sessionToken, redirect)
	return redirect, cookieValue, nil
}

// RejectIdentification implements the user-cancels-authentication path:
// per RFC 6749 §4.1.2.1, when the resource owner denies the request, the
// authorization server redirects back to redirect_uri with
// error=access_denied (never a JSON error body — the client is waiting
// on a redirect, exactly like the success path). No issuance record is
// created. Replay-safe the same way CompleteIdentification is, and
// shares its replay cache — a session can be completed or rejected, but
// not both, and either outcome replays identically on a retried POST.
func (s *Service) RejectIdentification(sessionToken string) (redirect string, err error) {
	if cached, ok := s.sessions.GetIdentifyReplay(sessionToken); ok {
		return cached, nil
	}

	params, ok := s.sessions.ConsumePendingAuth(sessionToken)
	if !ok {
		return "", oauth2.BadRequest(oauth2.InvalidRequest, "Invalid or expired identification session")
	}

	u, err := url.Parse(params["redirect_uri"])
	if err != nil {
		return "", oauth2.BadRequest(oauth2.InvalidRequest, "Invalid redirect_uri: "+err.Error())
	}
	q := u.Query()
	q.Set("error", "access_denied")
	q.Set("error_description", "The end-user denied the authorization request")
	if params["state"] != "" {
		q.Set("state", params["state"])
	}
	u.RawQuery = q.Encode()
	redirect = u.String()

	s.sessions.StoreIdentifyReplay(sessionToken, redirect)
	return redirect, nil
}

// HandleAuthCodeToken implements the authorization_code grant at the
// token endpoint: client attestation and DPoP are validated, then the
// authorization code is consumed (irrecoverably — a subsequent PKCE
// failure does not un-consume it, matching upstream), then PKCE S256 is
// verified before minting a DPoP-bound RFC 9068 access token.
func (s *Service) HandleAuthCodeToken(req oauth2.TokenRequest, dpopHeader, wiaHeader, popHeader string) (oauth2.TokenResponse, error) {
	// Resolve tries the header transport first (wiaHeader/popHeader), then
	// falls back to the request's own form-based assertion — mirroring
	// HandlePar's same precedence, so a client authenticating via
	// client_assertion/client_assertion_type at /token (instead of the
	// OAuth-Client-Attestation headers) is no longer silently ignored.
	clientID, attErr := s.attestations.Resolve(wiaHeader, popHeader, req.ClientAssertionType, req.ClientAssertion)
	if attErr != nil {
		return oauth2.TokenResponse{}, attErr
	}
	if clientID == "" {
		return oauth2.TokenResponse{}, oauth2.BadRequest(oauth2.InvalidRequest, "Client attestation is required")
	}
	// RFC 6749 §5.2: an explicit client_id form parameter naming a
	// different client than the one this request's attestation
	// authenticates must be rejected — this AS doesn't use client_id
	// for authentication, but a mismatch here means the caller is trying
	// to claim an identity its attestation doesn't back.
	if req.ClientID != "" && req.ClientID != clientID {
		return oauth2.TokenResponse{}, oauth2.Unauthorized(oauth2.InvalidClient, "client_id does not match the attested client")
	}

	dpopKey, err := oauth2.ValidateDPoPProof(dpopHeader, "POST", s.baseURL+"/oid4vci/v1/token", "", s.jtis)
	if err != nil {
		return oauth2.TokenResponse{}, err
	}

	if req.Code == "" {
		return oauth2.TokenResponse{}, oauth2.BadRequest(oauth2.InvalidGrant, "Missing authorization code")
	}
	sess, ok, reused := s.sessions.ConsumeAuthCode(req.Code)
	if !ok {
		if reused {
			// RFC 6749 §4.1.2: a reused authorization code must be
			// denied, and any access token it previously minted SHOULD
			// be revoked. The token is a stateless JWT, so "revoked"
			// means published on the denylist the Credential Issuer
			// polls — see session.Store.RevokeTokensForCode.
			s.sessions.RevokeTokensForCode(req.Code)
		}
		return oauth2.TokenResponse{}, oauth2.BadRequest(oauth2.InvalidGrant, "Invalid authorization code")
	}

	// Authorization code binding to client (RFC 6749 §4.1.3): the client
	// presenting the code at /token must be the same one the PAR/authorize
	// request came from — not merely any client with valid attestation.
	if boundClientID, _ := sess.Metadata[boundClientIDKey].(string); boundClientID != "" && boundClientID != clientID {
		return oauth2.TokenResponse{}, oauth2.BadRequest(oauth2.InvalidGrant, "Authorization code was not issued to this client")
	}

	// DPoP-PAR binding (RFC 9449 §10.1): if a dpop_jkt was bound to this
	// authorization at PAR time, the token endpoint's own DPoP proof must
	// be for that exact key.
	if boundJKT, _ := sess.Metadata["dpop_jkt"].(string); boundJKT != "" {
		thumbprint, err := oauth2.DPoPThumbprint(dpopKey)
		if err != nil || thumbprint != boundJKT {
			return oauth2.TokenResponse{}, oauth2.BadRequest(oauth2.InvalidGrant, "DPoP proof key does not match the one bound at the PAR endpoint")
		}
	}

	// RFC 7636 §4.6: a missing code_verifier is a PKCE verification
	// failure like any other, and must be reported the same way
	// (invalid_grant) — not invalid_request, which the OIDF conformance
	// suite (RFC6749-5.2/RFC7636-4.6) treats as a distinct, wrong error.
	if req.CodeVerifier == "" {
		return oauth2.TokenResponse{}, oauth2.BadRequest(oauth2.InvalidGrant, "Missing code_verifier")
	}
	storedChallenge, _ := sess.Metadata["code_challenge"].(string)
	if storedChallenge == "" || !oauth2.VerifyPKCES256(req.CodeVerifier, storedChallenge) {
		return oauth2.TokenResponse{}, oauth2.BadRequest(oauth2.InvalidGrant, "PKCE verification failed")
	}

	issuanceRecordID, _ := sess.Metadata["issuanceRecordId"].(string)
	accessToken, jti, err := s.minter.Mint(oauth2.AccessTokenClaims{
		IssuanceRecordID: issuanceRecordID,
		// The c_nonce travels inside the token rather than in a shared
		// nonce store, so the Credential Issuer can accept the wallet's
		// first proof JWT without a round trip to its own Nonce
		// Endpoint — which stays available for subsequent ones.
		CNonce:   session.GenerateNonce(),
		ClientID: clientID,
		DPoPKey:  dpopKey,
	})
	if err != nil {
		return oauth2.TokenResponse{}, oauth2.BadRequest(oauth2.InvalidRequest, "Failed to mint access token: "+err.Error())
	}
	s.sessions.RecordIssuedJTI(req.Code, jti)

	return oauth2.DPoPToken(accessToken), nil
}

// RevokedJTIs returns the access token identifiers this AS has revoked —
// served to the Credential Issuer, which polls it and refuses any token
// whose jti appears here. See session.Store.RevokeTokensForCode for why
// a denylist replaced simply deleting a row.
func (s *Service) RevokedJTIs() []string {
	return s.sessions.RevokedJTIs()
}
