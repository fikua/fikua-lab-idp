package oidcserver

import (
	"time"

	"github.com/zitadel/oidc/v3/pkg/op"
)

// refreshTokenRequest implements op.RefreshTokenRequest — the shape op's
// refresh_token grant handler asks for a new access token with. Built
// fresh from a store.refreshTokenEntry on each refresh (see storage.go's
// TokenRequestByRefreshToken), not persisted itself.
type refreshTokenRequest struct {
	subject  string
	clientID string
	scopes   []string
}

var _ op.RefreshTokenRequest = (*refreshTokenRequest)(nil)

func (r *refreshTokenRequest) GetAMR() []string       { return nil }
func (r *refreshTokenRequest) GetAudience() []string  { return []string{r.clientID} }
func (r *refreshTokenRequest) GetAuthTime() time.Time { return time.Time{} }
func (r *refreshTokenRequest) GetClientID() string    { return r.clientID }
func (r *refreshTokenRequest) GetScopes() []string    { return r.scopes }
func (r *refreshTokenRequest) GetSubject() string     { return r.subject }

// SetCurrentScopes lets op narrow the scopes a refresh request may keep
// (RFC 6749 §6: the new access token's scope may not exceed the
// original). This bridge does not support scope narrowing, in keeping
// with client.IsScopeAllowed's "nothing beyond the standard scopes at
// all" stance — the RP either has the openid (+ optionally
// offline_access) scope it started with, or it does not still hold a
// valid refresh token to ask with.
func (r *refreshTokenRequest) SetCurrentScopes(scopes []string) { r.scopes = scopes }
