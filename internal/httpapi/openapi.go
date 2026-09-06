package httpapi

import (
	_ "embed"
	"net/http"
)

// openapiYAML is this service's OpenAPI 3.0 spec — see docs/openapi.yaml
// for the source of truth; embedded so GET /docs and GET /openapi.yaml
// stay accurate for whatever binary is actually running, not whatever
// commit the reader happens to have checked out.
//
//go:embed openapi.yaml
var openapiYAML []byte

// docsHTML is a minimal Swagger UI shell (assets from the swagger-ui-dist
// CDN build, not vendored — this page is a developer-facing convenience,
// not something that needs to work offline).
const docsHTML = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Fikua IdP API</title>
<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>
window.onload = () => SwaggerUIBundle({url: "/openapi.yaml", dom_id: "#swagger-ui"});
</script>
</body>
</html>`

func (h *Handler) openapiSpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(openapiYAML)
}

func (h *Handler) docs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(docsHTML))
}
