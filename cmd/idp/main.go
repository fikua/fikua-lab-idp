// Command idp runs the Fikua Identity Provider: the OAuth2 authorization
// server for the Fikua Lab EUDI Wallet ecosystem, serving both its OAuth2
// endpoints and the end-user identification UI from a single Go binary.
package main

import (
	"io/fs"
	"log"
	"net/http"

	"github.com/fikua/fikua-lab-idp/internal/authz"
	"github.com/fikua/fikua-lab-idp/internal/config"
	fikuacrypto "github.com/fikua/fikua-lab-idp/internal/crypto"
	"github.com/fikua/fikua-lab-idp/internal/httpapi"
	"github.com/fikua/fikua-lab-idp/internal/issuerclient"
	"github.com/fikua/fikua-lab-idp/internal/oauth2"
	"github.com/fikua/fikua-lab-idp/internal/session"
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

	mux := http.NewServeMux()
	httpapi.NewHandler(cfg.BaseURL, signingKey, authzService, issuer).Routes(mux)
	webui.NewHandler(staticFS, cfg.BasePath).Routes(mux)

	log.Printf("fikua-lab-idp listening on %s (issuing access tokens for %s)", cfg.Addr, cfg.CredentialIssuerURL)
	if err := http.ListenAndServe(cfg.Addr, mux); err != nil {
		log.Fatal(err)
	}
}
