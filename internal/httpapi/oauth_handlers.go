package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/fikua/fikua-lab-idp/internal/authz"
	"github.com/fikua/fikua-lab-idp/internal/oauth2"
)

func (h *Handler) par(w http.ResponseWriter, r *http.Request) {
	form, err := parseForm(r)
	if err != nil {
		writeOAuthError(w, oauth2.BadRequest(oauth2.InvalidRequest, "Invalid form body: "+err.Error()))
		return
	}
	wiaHeader, popHeader := clientAttestationHeaders(r)
	dpopHeader, err := oauth2.SingleDPoPHeader(r.Header.Values("DPoP"))
	if err != nil {
		writeOAuthError(w, err)
		return
	}

	requestURI, expiresIn, err := h.authz.HandlePar(form, wiaHeader, popHeader, dpopHeader)
	if err != nil {
		writeOAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"request_uri": requestURI, "expires_in": expiresIn})
}

func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) {
	var identifiedCookie string
	if c, err := r.Cookie(authz.IdentifiedCookieName); err == nil {
		identifiedCookie = c.Value
	}
	result, err := h.authz.HandleAuthorize(r.Context(), r.URL.Query().Get("request_uri"), r.URL.Query().Get("client_id"), identifiedCookie)
	if err != nil {
		writeAuthorizeError(w, err)
		return
	}
	if result.IdentifyRedirect != "" {
		http.Redirect(w, r, result.IdentifyRedirect, http.StatusFound)
		return
	}
	redirect, err := authz.BuildAuthorizationRedirect(result, h.baseURL)
	if err != nil {
		writeAuthorizeError(w, oauth2.BadRequest(oauth2.InvalidRequest, "Invalid redirect_uri: "+err.Error()))
		return
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (h *Handler) token(w http.ResponseWriter, r *http.Request) {
	form, err := parseForm(r)
	if err != nil {
		writeOAuthError(w, oauth2.BadRequest(oauth2.InvalidRequest, "Invalid form body: "+err.Error()))
		return
	}
	req := oauth2.TokenRequestFromForm(form)
	// RFC 6749 §2.3.1: client_secret_basic sends client_id (and a
	// secret this AS doesn't use for authentication) via HTTP Basic
	// auth on the Authorization header, not as a form parameter — a
	// client authenticating this way had its client_id silently missed
	// entirely, since only the form was ever consulted.
	if basicClientID, _, ok := r.BasicAuth(); ok && req.ClientID == "" {
		req.ClientID = basicClientID
	}
	w.Header().Set("Cache-Control", "no-store")
	if !req.IsAuthorizationCode() {
		writeOAuthError(w, oauth2.BadRequest(oauth2.UnsupportedGrantType, "Only the authorization_code grant is supported"))
		return
	}

	dpopHeader, err := oauth2.SingleDPoPHeader(r.Header.Values("DPoP"))
	if err != nil {
		writeOAuthError(w, err)
		return
	}
	wiaHeader, popHeader := clientAttestationHeaders(r)

	resp, err := h.authz.HandleAuthCodeToken(req, dpopHeader, wiaHeader, popHeader)
	if err != nil {
		writeOAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// identifyClaims implements GET /identify/claims: resolves which
// credential_configuration_id a pending identification session is for,
// then asks the Credential Issuer for that configuration's claim
// metadata — no claim metadata is hardcoded here.
func (h *Handler) identifyClaims(w http.ResponseWriter, r *http.Request) {
	sessionToken := r.URL.Query().Get("session")
	credentialConfigID, err := h.authz.ResolveIdentifyScope(sessionToken)
	if err != nil {
		writeOAuthError(w, err)
		return
	}

	claims, err := h.issuer.CredentialClaims(r.Context(), credentialConfigID)
	if err != nil {
		writeOAuthError(w, oauth2.ServiceUnavailable(oauth2.InvalidRequest, "Could not load claim metadata: "+err.Error()))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"credential_configuration_id": credentialConfigID,
		"claims":                      claims,
	})
}

// identifyCompleteRequest is POST /identify/complete's body — matches the
// identification UI's own submitIdentification() in web/static/app.js.
type identifyCompleteRequest struct {
	Session        string         `json:"session"`
	CredentialData map[string]any `json:"credential_data"`
	SourceType     string         `json:"source_type"`
	SourceRef      string         `json:"source_ref"`
}

// identifyComplete implements POST /identify/complete: marks the
// deferred authorization's request_uri as identified (setting a cookie
// naming that session) and hands the frontend a redirect URL to follow —
// back to /authorize?request_uri=<original>, not the client's own
// redirect_uri (see authz.CompleteIdentification's doc comment for why:
// FAPI 2.0 Security Profile §5.3.2.2 Note 3 requires a *second*
// /authorize visit be the one that completes the OAuth2 response). It
// does not itself redirect — the frontend's own JS drives
// window.location.href, per app.js — but the Set-Cookie on this response
// rides along with the browser to that follow-up GET regardless.
func (h *Handler) identifyComplete(w http.ResponseWriter, r *http.Request) {
	var req identifyCompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, oauth2.BadRequest(oauth2.InvalidRequest, "Invalid request body: "+err.Error()))
		return
	}
	redirect, cookieValue, err := h.authz.CompleteIdentification(r.Context(), req.Session, req.CredentialData, req.SourceType, req.SourceRef)
	if err != nil {
		writeOAuthError(w, err)
		return
	}
	if cookieValue != "" {
		h.setIdentifiedCookie(w, cookieValue)
	}
	writeJSON(w, http.StatusOK, map[string]string{"redirect": redirect})
}

// setIdentifiedCookie sets the opaque session cookie CompleteIdentification
// mints, read back by HandleAuthorize's second /authorize visit.
//
//   - HttpOnly: this cookie is never read by the identification page's own
//     JS (app.js drives navigation via the JSON "redirect" field, never
//     document.cookie) — no reason to expose it to script, every reason
//     not to (XSS exfiltration).
//   - Secure based on h.baseURL's scheme rather than the inbound request's
//     own r.TLS: this AS typically sits behind a TLS-terminating reverse
//     proxy (see the README's Traefik/nginx mentions for the sibling
//     X.509 flow), so the connection reaching this process is often plain
//     HTTP even in production and r.TLS would wrongly read as insecure.
//     h.baseURL is this service's own externally-visible identifier
//     (FIKUA_BASE_URL, "https://idp.fikua.com" by default) and is already
//     authoritative elsewhere in this codebase (e.g. the `iss` claim) —
//     using it here means local `make run` (baseURL defaults aside, a
//     dev override would use an http:// baseURL) still gets a cookie the
//     browser will actually store.
//   - SameSite=Lax: the browser navigation this cookie must survive is the
//     frontend's own window.location.href to /authorize — a same-site,
//     top-level GET, which Lax always sends; Strict would too, but Lax is
//     the least restrictive setting that still blocks the cookie from
//     being attached to a cross-site request, which is all this needs.
//   - Path=/oid4vci/v1/authorize: scoped to the one endpoint that ever
//     reads it, so it never rides along on unrelated same-origin requests.
//   - MaxAge matches session.identifiedSessionTTL (60s) so the cookie
//     itself expires no later than the server-side session it names —
//     letting it outlive the session would just mean CheckIdentified
//     rejects it anyway, but there is no reason to ask the browser to hold
//     a cookie the server already considers dead.
func (h *Handler) setIdentifiedCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     authz.IdentifiedCookieName,
		Value:    value,
		Path:     "/oid4vci/v1/authorize",
		MaxAge:   60,
		HttpOnly: true,
		Secure:   strings.HasPrefix(h.baseURL, "https://"),
		SameSite: http.SameSiteLaxMode,
	})
}

// identifyRejectRequest is POST /identify/reject's body.
type identifyRejectRequest struct {
	Session string `json:"session"`
}

// identifyReject implements the user-cancels-authentication path: the
// frontend's "Deny access" action calls this instead of
// /identify/complete, and gets back a redirect URL carrying
// error=access_denied (RFC 6749 §4.1.2.1) instead of an authorization
// code.
func (h *Handler) identifyReject(w http.ResponseWriter, r *http.Request) {
	var req identifyRejectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, oauth2.BadRequest(oauth2.InvalidRequest, "Invalid request body: "+err.Error()))
		return
	}
	redirect, err := h.authz.RejectIdentification(req.Session)
	if err != nil {
		writeOAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"redirect": redirect})
}

// parseForm parses a form-urlencoded request body into a plain map,
// taking the first value per key and dropping empty-valued keys.
func parseForm(r *http.Request) (map[string]string, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	form := make(map[string]string, len(r.PostForm))
	for k, values := range r.PostForm {
		if len(values) > 0 && values[0] != "" {
			form[k] = values[0]
		}
	}
	return form, nil
}

// clientAttestationHeaders extracts the ATCA draft-07 WIA/PoP headers,
// shared by /par and /token — the only two endpoints that accept
// header-based client attestation.
func clientAttestationHeaders(r *http.Request) (wia, pop string) {
	return r.Header.Get(oauth2.HeaderClientAttestation), r.Header.Get(oauth2.HeaderClientAttestationPoP)
}

func writeOAuthError(w http.ResponseWriter, err error) {
	exc, ok := err.(*oauth2.Exception)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, oauth2.Error{Code: oauth2.InvalidRequest, Description: err.Error()})
		return
	}
	writeJSON(w, exc.HTTPStatus, exc.Err)
}

// writeAuthorizeError renders authorizeErrorTemplate instead of JSON —
// GET /oid4vci/v1/authorize is loaded directly in a browser (redirected
// there by a wallet), so a failure here should read as a page, not a raw
// JSON error body.
func writeAuthorizeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	oauthErr := oauth2.Error{Code: oauth2.InvalidRequest, Description: err.Error()}
	if exc, ok := err.(*oauth2.Exception); ok {
		status = exc.HTTPStatus
		oauthErr = exc.Err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = authorizeErrorTemplate.Execute(w, oauthErr)
}
