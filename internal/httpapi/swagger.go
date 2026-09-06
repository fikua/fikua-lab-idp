package httpapi

import (
	_ "embed"
	"net/http"
)

// openAPISpec is this service's OpenAPI 3.0 spec — see docs/openapi.yaml
// for the source of truth; embedded so GET /swagger and GET /openapi.yaml
// stay accurate for whatever binary is actually running, not whatever
// commit the reader happens to have checked out.
//
//go:embed openapi.yaml
var openAPISpec []byte

// swaggerPage renders Swagger UI via CDN, pointed at the embedded OpenAPI
// spec served from /openapi.yaml. No swagger-ui assets are bundled — the
// CDN script/CSS are the only external calls this page makes, and only
// from the browser rendering it, not from the server itself. Matches
// fikua-lab-issuer's and fikua-lab-attestation-registry's own
// internal/httpapi/swagger.go — same route names, same pinned CDN
// version — so this is the third Fikua Go service following the same
// docs convention rather than inventing its own.
const swaggerPage = `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Fikua IdP &mdash; API docs</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.17.14/swagger-ui.min.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.17.14/swagger-ui-bundle.min.js"></script>
  <script>
    window.onload = () => {
      window.ui = SwaggerUIBundle({
        url: '/openapi.yaml',
        dom_id: '#swagger-ui',
        presets: [SwaggerUIBundle.presets.apis],
      });
    };
  </script>
</body>
</html>`

func (h *Handler) swaggerUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(swaggerPage))
}

func (h *Handler) openAPISpecHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(openAPISpec)
}
