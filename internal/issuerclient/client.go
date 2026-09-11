// Package issuerclient talks to the Credential Issuer's JSON API for the
// two things this authorization server cannot answer on its own: which
// issuance record an issuer_state refers to, and creating a record for an
// authorization that arrived without one.
//
// Types here are hand-mirrored from fikua-lab-issuer's own API, not
// imported from it — the same deliberate boundary that service already
// keeps with fikua-lab-attestation-registry. No shared Go module, only the
// JSON contract, so the two stay independently deployable.
package issuerclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// Client calls the Credential Issuer's issuance API.
type Client struct {
	baseURL string
	http    *http.Client
}

// New builds a Client against the Credential Issuer at baseURL (e.g.
// "https://issuer.fikua.com").
func New(baseURL string) *Client {
	return &Client{baseURL: baseURL, http: &http.Client{Timeout: 10 * time.Second}}
}

// Record is the subset of an issuance record this AS needs: only its id,
// which becomes the access token's issuance_record_id claim. The
// credential data itself never passes through this service.
type Record struct {
	ID string `json:"id"`
}

// FindByIssuerState resolves the issuance record a credential offer's
// issuer_state points at. ok is false when no record matches — a
// spec-conformant wallet may legitimately send an authorization request
// with no issuer_state at all, or reuse a stale one, so this is an
// ordinary outcome and not an error.
func (c *Client) FindByIssuerState(ctx context.Context, issuerState string) (Record, bool, error) {
	var rec Record
	status, err := c.get(ctx, "/oid4vci/v1/issuance/by-issuer-state/"+url.PathEscape(issuerState), &rec)
	if err != nil {
		return Record{}, false, err
	}
	if status == http.StatusNotFound {
		return Record{}, false, nil
	}
	return rec, true, nil
}

// CreateRequest is POST /oid4vci/v1/issuance's body.
type CreateRequest struct {
	CredentialType string         `json:"credential_type"`
	CredentialData map[string]any `json:"credential_data"`
	SourceType     string         `json:"source_type"`
	SourceRef      string         `json:"source_ref"`
}

// createResponse is POST /oid4vci/v1/issuance's body — only issuance_id
// matters here; the credential_offer_uri it also returns is for the
// issuer's own UI, since this AS is already mid-authorization and has no
// use for a fresh offer.
type createResponse struct {
	IssuanceID string `json:"issuance_id"`
}

// Create records a new issuance on the Credential Issuer, carrying the
// credential data collected by the identification flow, and returns its
// id for the access token's issuance_record_id claim.
func (c *Client) Create(ctx context.Context, req CreateRequest) (Record, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return Record{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/oid4vci/v1/issuance", bytes.NewReader(body))
	if err != nil {
		return Record{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return Record{}, fmt.Errorf("issuerclient: creating issuance record: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Record{}, fmt.Errorf("issuerclient: creating issuance record: unexpected status %d", resp.StatusCode)
	}

	var out createResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Record{}, fmt.Errorf("issuerclient: decoding issuance response: %w", err)
	}
	return Record{ID: out.IssuanceID}, nil
}

// CredentialConfig is one credential_configurations_supported entry, cut
// down to what the identification form renders: its claim paths and their
// display labels.
type CredentialConfig struct {
	CredentialMetadata struct {
		Claims []Claim `json:"claims"`
	} `json:"credential_metadata"`
}

// Claim is one claim the identification form may ask for.
type Claim struct {
	Path    []string       `json:"path"`
	Display []ClaimDisplay `json:"display,omitempty"`
	// Mandatory mirrors the attestation-registry scheme's own presence
	// declaration, passed through unchanged from the Credential Issuer's
	// metadata. The identification UI (web/static/app.js) uses this to
	// decide which fields to require — see identifyClaims's doc comment
	// for why no claim metadata is hardcoded here or downstream.
	Mandatory bool `json:"mandatory"`
}

// ClaimDisplay is one locale's label for a claim.
type ClaimDisplay struct {
	Name   string `json:"name"`
	Locale string `json:"locale"`
}

// issuerMetadata is the slice of the Credential Issuer Metadata document
// this AS reads.
type issuerMetadata struct {
	CredentialConfigurationsSupported map[string]CredentialConfig `json:"credential_configurations_supported"`
}

// CredentialClaims fetches the claim metadata for credentialConfigID from
// the Credential Issuer's public metadata document.
//
// Read from /.well-known/openid-credential-issuer rather than from
// fikua-lab-attestation-registry directly: the registry is the source of
// truth for schemes, but the issuer is the authority on which of them it
// actually issues and how it shapes them. Asking the issuer means the
// form can never collect a claim set the issuer would then refuse.
func (c *Client) CredentialClaims(ctx context.Context, credentialConfigID string) ([]Claim, error) {
	var metadata issuerMetadata
	if _, err := c.get(ctx, "/.well-known/openid-credential-issuer", &metadata); err != nil {
		return nil, err
	}
	cfg, ok := metadata.CredentialConfigurationsSupported[credentialConfigID]
	if !ok {
		return nil, fmt.Errorf("issuerclient: credential issuer does not offer %q", credentialConfigID)
	}
	return cfg.CredentialMetadata.Claims, nil
}

// get performs a GET and decodes a 200 body into out, returning the
// status so callers can distinguish 404 (an ordinary "not found") from a
// transport or server failure.
func (c *Client) get(ctx context.Context, path string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("issuerclient: GET %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return resp.StatusCode, nil
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("issuerclient: GET %s: unexpected status %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return resp.StatusCode, fmt.Errorf("issuerclient: GET %s: decoding response: %w", path, err)
	}
	return resp.StatusCode, nil
}
