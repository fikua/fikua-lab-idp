// Package web embeds the identification UI's static assets so they ship
// inside the compiled binary.
package web

import "embed"

//go:embed static/*
var StaticFS embed.FS
