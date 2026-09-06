// Command idp runs the Fikua Identity Provider: the OAuth2 authorization
// server for the Fikua Lab EUDI Wallet ecosystem, serving both its OAuth2
// endpoints and the end-user identification UI from a single Go binary.
package main

import (
	"context"
	"io/fs"
	"log"
	"net/http"

	"github.com/fikua/fikua-lab-idp/internal/authz"
	"github.com/fikua/fikua-lab-idp/internal/config"
	fikuacrypto "github.com/fikua/fikua-lab-idp/internal/crypto"
	"github.com/fikua/fikua-lab-idp/internal/cscclient"
	"github.com/fikua/fikua-lab-idp/internal/httpapi"
	"github.com/fikua/fikua-lab-idp/internal/issuerclient"
	"github.com/fikua/fikua-lab-idp/internal/oauth2"
	"github.com/fikua/fikua-lab-idp/internal/session"
	"github.com/fikua/fikua-lab-idp/internal/verifier"
	"github.com/fikua/fikua-lab-idp/internal/webui"
	"github.com/fikua/fikua-lab-idp/web"
)

func main() {
	cfg := config.Load()

	signingKey, err := fikuacrypto.LoadFromPEM(cfg.CertsDir)
	if err != nil {
		log.Fatalf("loading access-token signing key: %v", err)
	}
	log.Printf("access-token signing key loaded (kid=%s)", signingKey.KID())

	walletProviderAnchor, err := fikuacrypto.LoadWalletProviderAnchor(cfg.CertsDir)
	if err != nil {
		log.Fatalf("loading wallet provider trust anchor: %v", err)
	}
	if walletProviderAnchor == nil {
		log.Printf("warning: no root-ca.crt found in %s — accepting any self-consistent client attestation (no Wallet Provider trust pinning)", cfg.CertsDir)
	}

	sessions := session.NewStore()
	issuer := issuerclient.New(cfg.CredentialIssuerURL)
	minter := oauth2.NewMinter(signingKey, cfg.BaseURL, cfg.CredentialIssuerURL)
	authzService := authz.NewService(cfg.BaseURL, sessions, issuer, minter, walletProviderAnchor)

	staticFS, err := fs.Sub(web.StaticFS, "static")
	if err != nil {
		log.Fatalf("static assets: %v", err)
	}

	verifierService, err := loadVerifier(cfg, sessions)
	if err != nil {
		log.Fatalf("loading OID4VP Verifier: %v", err)
	}

	mux := http.NewServeMux()
	httpapi.NewHandler(cfg.BaseURL, signingKey, authzService, issuer, verifierService).Routes(mux)
	webui.NewHandler(staticFS, cfg.BasePath).Routes(mux)

	log.Printf("fikua-lab-idp listening on %s (issuing access tokens for %s)", cfg.Addr, cfg.CredentialIssuerURL)
	if err := http.ListenAndServe(cfg.Addr, mux); err != nil {
		log.Fatal(err)
	}
}

// loadVerifier builds the OID4VP Verifier, or returns nil when no Fikua DSS
// is configured — in which case the /oid4vp/v1/* endpoints are simply not
// registered (see httpapi.Handler.Routes).
//
// Nil rather than a local-key fallback because there is no useful degraded
// mode here: a Request Object signed by a self-signed local key is one no
// wallet will act on, so the endpoints would exist only to fail at the last
// step of a flow a human already started. Not registering them at all makes
// the misconfiguration a 404 at the first call instead. Once the DSS *is*
// configured, every failure below is fatal — a Verifier that cannot reach
// its signing credential at boot will not acquire one later.
func loadVerifier(cfg config.Config, sessions *session.Store) (*verifier.Service, error) {
	if cfg.DSSURL == "" {
		log.Printf("no FIKUA_DSS_URL configured — OID4VP Verifier endpoints (%s/*) are disabled", verifier.APIPrefix)
		return nil, nil
	}

	log.Printf("OID4VP Request Objects signed via Fikua DSS at %s (credential=%s)", cfg.DSSURL, cfg.DSSVerifierCredentialID)
	client := cscclient.New(cscclient.Config{
		BaseURL:            cfg.DSSURL,
		ClientID:           cfg.DSSClientID,
		ClientSecret:       cfg.DSSClientSecret,
		CredentialID:       cfg.DSSVerifierCredentialID,
		CredentialPassword: cfg.DSSCredentialPassword,
	})
	signer, err := cscclient.NewSigner(context.Background(), client)
	if err != nil {
		return nil, err
	}
	leafDER, err := signer.LeafDER(context.Background())
	if err != nil {
		return nil, err
	}
	// Only the leaf goes into x5c — see cscclient.Signer.LeafDER.
	signingKey, err := fikuacrypto.NewRequestSigningKey(signer, [][]byte{leafDER})
	if err != nil {
		return nil, err
	}
	log.Printf("OID4VP Verifier ready (request signing kid=%s)", signingKey.KID())

	return verifier.NewService(cfg.VerifierBaseURL, signingKey, sessions, ""), nil
}
