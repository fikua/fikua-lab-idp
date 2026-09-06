// DUPLICATED FILE: fikua-lab-issuer/internal/cscclient/client.go is a
// near-copy of this one. CSC v2.0 is a frozen third-party HTTP contract
// spoken directly to the Fikua DSS by whichever service holds a credential
// there — the issuer for its credential signing key, this service for the
// OID4VP Verifier's Request Object signing key — and neither consults the
// other at request time. A shared Go module was weighed and rejected on the
// same grounds as internal/oauth2/dpop.go: cross-repo version pinning costs
// more than ~200 duplicated lines tracking a spec that does not move. Fix
// bugs in both copies; extract a module only if a third consumer appears.
//
// Package cscclient implements a client for the Cloud Signature Consortium
// (CSC) API v2.0, as exposed by the Fikua Digital Signature Service
// (fikua-dss). It fetches an OAuth2 client_credentials access token, then
// authorizes and signs with a single CSC credential — matching this
// service's use as one tenant of a multi-tenant CSC signing service.
package cscclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config holds everything needed to authenticate as one CSC tenant against
// a Fikua DSS instance.
type Config struct {
	// BaseURL is the DSS's base URL, e.g. "https://dss.fikua.com".
	BaseURL string
	// ClientID/ClientSecret authenticate at POST /oauth2/token
	// (client_credentials grant, HTTP Basic auth).
	ClientID     string
	ClientSecret string
	// CredentialID/CredentialPassword identify and authorize this tenant's
	// signing credential at POST /csc/v2/credentials/authorize.
	CredentialID       string
	CredentialPassword string
}

// Client is a CSC v2.0 client scoped to a single tenant/credential.
type Client struct {
	cfg  Config
	http *http.Client

	mu          sync.Mutex
	accessToken string
	expiresAt   time.Time
}

// New builds a Client for cfg. It performs no network calls until a method
// is called.
func New(cfg Config) *Client {
	return &Client{cfg: cfg, http: &http.Client{Timeout: 15 * time.Second}}
}

// token returns a cached access token, fetching a new one if missing or
// close to expiry.
func (c *Client) token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.accessToken != "" && time.Now().Before(c.expiresAt) {
		return c.accessToken, nil
	}

	form := url.Values{"grant_type": {"client_credentials"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(c.cfg.ClientID, c.cfg.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := c.do(req, &out); err != nil {
		return "", fmt.Errorf("cscclient: fetching access token: %w", err)
	}

	c.accessToken = out.AccessToken
	// Refresh a bit early so a token never expires mid-request.
	c.expiresAt = time.Now().Add(time.Duration(out.ExpiresIn)*time.Second - 30*time.Second)
	return c.accessToken, nil
}

// CertificateInfo is the leaf-first certificate chain and public-key
// metadata for this tenant's credential, as reported by
// /csc/v2/credentials/info.
type CertificateInfo struct {
	KeyAlgorithmOIDs []string
	// ChainDER is the leaf-first certificate chain, DER-encoded (decoded
	// from the CSC response's base64 certificates).
	ChainDER [][]byte
}

// CredentialInfo fetches this tenant's certificate chain and key metadata.
func (c *Client) CredentialInfo(ctx context.Context) (CertificateInfo, error) {
	token, err := c.token(ctx)
	if err != nil {
		return CertificateInfo{}, err
	}

	reqBody, err := json.Marshal(map[string]string{"credentialID": c.cfg.CredentialID})
	if err != nil {
		return CertificateInfo{}, err
	}
	req, err := c.newAuthedRequest(ctx, token, "/csc/v2/credentials/info", reqBody)
	if err != nil {
		return CertificateInfo{}, err
	}

	var out struct {
		Key struct {
			Algo []string `json:"algo"`
		} `json:"key"`
		Cert struct {
			Certificates []string `json:"certificates"`
		} `json:"cert"`
	}
	if err := c.do(req, &out); err != nil {
		return CertificateInfo{}, fmt.Errorf("cscclient: fetching credential info: %w", err)
	}

	chain := make([][]byte, 0, len(out.Cert.Certificates))
	for _, b64 := range out.Cert.Certificates {
		der, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return CertificateInfo{}, fmt.Errorf("cscclient: decoding certificate: %w", err)
		}
		chain = append(chain, der)
	}
	return CertificateInfo{KeyAlgorithmOIDs: out.Key.Algo, ChainDER: chain}, nil
}

// authorize fetches a single-use SAD (Signature Activation Data) for one
// signing operation.
func (c *Client) authorize(ctx context.Context, token string) (string, error) {
	reqBody, err := json.Marshal(map[string]any{
		"credentialID":  c.cfg.CredentialID,
		"numSignatures": 1,
		"authData": []map[string]string{
			{"id": "password", "value": c.cfg.CredentialPassword},
		},
	})
	if err != nil {
		return "", err
	}
	req, err := c.newAuthedRequest(ctx, token, "/csc/v2/credentials/authorize", reqBody)
	if err != nil {
		return "", err
	}

	var out struct {
		SAD string `json:"SAD"`
	}
	if err := c.do(req, &out); err != nil {
		return "", fmt.Errorf("cscclient: authorizing credential: %w", err)
	}
	return out.SAD, nil
}

// SignHash authorizes and signs a single pre-computed hash, returning the
// raw signature bytes. hashAlgorithmOID identifies the digest algorithm
// used to compute hash (e.g. "2.16.840.1.101.3.4.2.1" for SHA-256).
func (c *Client) SignHash(ctx context.Context, hash []byte, hashAlgorithmOID string) ([]byte, error) {
	token, err := c.token(ctx)
	if err != nil {
		return nil, err
	}
	sad, err := c.authorize(ctx, token)
	if err != nil {
		return nil, err
	}

	reqBody, err := json.Marshal(map[string]any{
		"credentialID":     c.cfg.CredentialID,
		"SAD":              sad,
		"hashes":           []string{base64.RawURLEncoding.EncodeToString(hash)},
		"hashAlgorithmOID": hashAlgorithmOID,
	})
	if err != nil {
		return nil, err
	}
	req, err := c.newAuthedRequest(ctx, token, "/csc/v2/signatures/signHash", reqBody)
	if err != nil {
		return nil, err
	}

	var out struct {
		Signatures []string `json:"signatures"`
	}
	if err := c.do(req, &out); err != nil {
		return nil, fmt.Errorf("cscclient: signing hash: %w", err)
	}
	if len(out.Signatures) != 1 {
		return nil, fmt.Errorf("cscclient: expected 1 signature, got %d", len(out.Signatures))
	}
	return base64.RawURLEncoding.DecodeString(out.Signatures[0])
}

func (c *Client) newAuthedRequest(ctx context.Context, token, path string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+path, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

func (c *Client) do(req *http.Request, out any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s %s: unexpected status %d", req.Method, req.URL.Path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
