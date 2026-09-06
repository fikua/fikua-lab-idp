package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/fikua/fikua-lab-idp/internal/oauth2"
	"github.com/fikua/fikua-lab-idp/internal/verifier"
)

// createSessionRequest is POST /oid4vp/v1/session's body — what the
// verification frontend asks for. Every field is optional; the defaults
// applied below are the PID request this ecosystem exists to make.
type createSessionRequest struct {
	CredentialType string   `json:"credential_type"`
	Claims         []string `json:"claims"`
	Format         string   `json:"format"`
}

// Defaults for a session request that names nothing. Kept as constants so
// the "what does this Verifier ask for by default" answer lives in one
// place, matching the Java controller's own defaults.
const defaultCredentialType = "eu.europa.ec.eudi.pid.1"

var defaultClaims = []string{"given_name", "family_name", "birth_date"}

// oid4vpCreateSession implements POST /oid4vp/v1/session: builds a
// verification session and returns the request_uri a wallet is pointed at,
// usually via a QR code the frontend renders from it.
func (h *Handler) oid4vpCreateSession(w http.ResponseWriter, r *http.Request) {
	var req createSessionRequest
	// A body is optional here, and a malformed one falls through to the
	// defaults rather than erroring — matching the Java controller, which
	// logged and carried on. The wallet-facing endpoints below are strict;
	// this one is called by our own frontend.
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	if req.CredentialType == "" {
		req.CredentialType = defaultCredentialType
	}
	if len(req.Claims) == 0 {
		req.Claims = defaultClaims
	}

	result, err := h.verifier.CreateSession(verifier.CreateSessionRequest{
		CredentialType: req.CredentialType,
		Claims:         req.Claims,
		Format:         req.Format,
	})
	if err != nil {
		writeOAuthError(w, oauth2.BadRequest(oauth2.InvalidRequest, "Failed to create verification session: "+err.Error()))
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"session_id":  result.SessionID,
		"request_uri": result.RequestURI,
		"client_id":   result.ClientID,
		"state":       result.State,
	})
}

// oid4vpRequestObject implements GET|POST /oid4vp/v1/request/{id}: serves
// the signed Authorization Request the wallet fetches.
//
// POST is registered alongside GET for OID4VP's request_uri_method=post,
// where a wallet may send wallet_metadata/wallet_nonce form parameters.
// Those are accepted and ignored: this Verifier is HAIP-fixed, so there is
// nothing about the request it would negotiate, and a wallet_nonce would
// only matter if the Request Object were built per-fetch rather than at
// session creation.
//
// The response media type is application/oauth-authz-req+jwt, per RFC 9101
// §10.8 and OID4VP §5.10. It had been application/json in the Java
// controller (with a standing TODO at the line), which a wallet that
// content-negotiates rejects outright — the request object is a JWS
// compact string, not a JSON document, whatever it happens to contain.
func (h *Handler) oid4vpRequestObject(w http.ResponseWriter, r *http.Request) {
	requestObject, err := h.verifier.GetRequestObject(r.PathValue("id"))
	if err != nil {
		writeOAuthError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/"+verifier.JARType)
	// The Request Object is bound to one session and carries a nonce; a
	// cached copy is a replayed one.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(requestObject))
}

// oid4vpResponse implements POST /oid4vp/v1/response: receives the wallet's
// VP Token (direct_post) or the JWE carrying it (direct_post.jwt), verifies
// it, and answers with the redirect_uri OID4VP §8.2 defines for the
// same-device flow.
//
// A rejected presentation is a 400 with the error body, never a 200 — §8.2
// requires the Verifier refuse rather than acknowledge, and a wallet that
// got a 200 would tell the holder their credential had been accepted.
func (h *Handler) oid4vpResponse(w http.ResponseWriter, r *http.Request) {
	form, err := parseForm(r)
	if err != nil {
		writeOAuthError(w, oauth2.BadRequest(oauth2.InvalidRequest, "Invalid form body: "+err.Error()))
		return
	}

	result, session, err := h.verifier.HandleResponse(r.Context(), verifier.ResponseRequest{
		VPToken:  form["vp_token"],
		State:    form["state"],
		Response: form["response"],
	})
	if err != nil {
		writeOAuthError(w, err)
		return
	}
	if result.Status != verifier.StatusSuccess {
		writeJSON(w, http.StatusBadRequest, result)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"redirect_uri": h.verifier.ResultURI(session.SessionID),
	})
}

// oid4vpResult implements GET /oid4vp/v1/result/{id}: the frontend's poll
// for a session's outcome. A live but unpresented session answers 200 with
// a "pending" error status rather than 404 — the frontend is asking "is it
// done yet", and 404 is reserved for a session id that is genuinely gone.
func (h *Handler) oid4vpResult(w http.ResponseWriter, r *http.Request) {
	result, err := h.verifier.GetResult(r.PathValue("id"))
	if err != nil {
		writeOAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
