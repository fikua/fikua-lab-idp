package oidcserver

import (
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// authRequest implements op.AuthRequest. Held in authRequestStore (see
// store.go) from CreateAuthRequest until DeleteAuthRequest (op calls the
// latter itself once CreateTokenResponse has consumed it).
//
// subject and done together are this bridge's whole reason for existing:
// op.Authorize creates one of these and immediately redirects to
// LoginURL without waiting for anything, because op has no notion of an
// asynchronous, out-of-band login step — a classic username/password
// form fills these in as part of one HTTP handler. Here, login.go's poll
// loop fills them in once the OID4VP Verifier reports a verified
// presentation, arbitrarily later, and Done() is what tells op's
// AuthorizeCallback the wait is over.
type authRequest struct {
	id           string
	clientID     string
	redirectURI  string
	state        string
	nonce        string
	scopes       []string
	responseType oidc.ResponseType
	// codeChallenge is never nil for a request this bridge created (see
	// storage.go's CreateAuthRequest) — PKCE is mandatory for every
	// client in oidcclients' registry (all of them are public clients,
	// see oidcclients.Client.TokenEndpointAuthMethod's doc comment), and
	// op.AuthorizeCodeChallenge only enforces PKCE when this is non-nil
	// (a nil challenge makes a code_verifier merely optional). A request
	// arriving with no code_challenge at all must therefore be rejected
	// before a bare authRequest is ever constructed, not represented as
	// one with a nil challenge.
	codeChallenge *oidc.CodeChallenge
	createdAt     time.Time

	// subject and doneAt are set exactly once, by login.go, when the
	// Verifier session behind this AuthRequest resolves to "verified".
	// subject is internal/verifier's SubjectID — see that field's doc
	// comment for what it is and, just as importantly, is not.
	subject string
	doneAt  time.Time
}

var _ op.AuthRequest = (*authRequest)(nil)

func (a *authRequest) GetID() string                         { return a.id }
func (a *authRequest) GetACR() string                        { return "" }
func (a *authRequest) GetAMR() []string                      { return nil }
func (a *authRequest) GetAudience() []string                 { return []string{a.clientID} }
func (a *authRequest) GetAuthTime() time.Time                { return a.doneAt }
func (a *authRequest) GetClientID() string                   { return a.clientID }
func (a *authRequest) GetCodeChallenge() *oidc.CodeChallenge { return a.codeChallenge }
func (a *authRequest) GetNonce() string                      { return a.nonce }
func (a *authRequest) GetRedirectURI() string                { return a.redirectURI }
func (a *authRequest) GetResponseType() oidc.ResponseType    { return a.responseType }
func (a *authRequest) GetResponseMode() oidc.ResponseMode    { return "" }
func (a *authRequest) GetScopes() []string                   { return a.scopes }
func (a *authRequest) GetState() string                      { return a.state }
func (a *authRequest) GetSubject() string                    { return a.subject }
func (a *authRequest) Done() bool                            { return a.subject != "" }
