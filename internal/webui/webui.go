// Package webui serves the end-user identification UI: plain HTML/CSS/JS,
// no server-side templating. Absorbed from the standalone
// fikua-lab-identify Cloudflare Worker, which used to sit on its own
// origin and call the issuer cross-origin; now it is same-origin with the
// /identify/* endpoints backing it.
package webui

import (
	"io/fs"
	"net/http"
	"strings"
)

// Handler serves the embedded static UI.
type Handler struct {
	staticFS fs.FS
	basePath string
}

// NewHandler builds a webui Handler. staticFS must contain index.html at
// its root plus its sibling assets (app.js, style.css, favicon.svg).
//
// basePath is prepended to the mount point (e.g. "" serves at "/", used
// for local dev / direct access; a reverse proxy in front of this service
// would pass its own prefix).
func NewHandler(staticFS fs.FS, basePath string) *Handler {
	return &Handler{staticFS: staticFS, basePath: strings.TrimSuffix(basePath, "/")}
}

// Routes registers this handler's endpoints on mux.
//
// Mounted at /identify/ rather than at the root: unlike the Credential
// Issuer, whose root is its own operator UI, this service's only page is
// the identification flow, and /authorize redirects a browser straight to
// it. The root redirects there so a bare hostname isn't a 404.
func (h *Handler) Routes(mux *http.ServeMux) {
	prefix := h.basePath + "/identify/"
	mux.Handle("GET "+prefix, http.StripPrefix(prefix, http.FileServer(http.FS(h.staticFS))))
	mux.HandleFunc("GET "+h.basePath+"/{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, prefix, http.StatusFound)
	})
}
