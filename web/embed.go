// Package web embeds static templates into the binary.
package web

import "embed"

//go:embed templates/*.html
var FS embed.FS
