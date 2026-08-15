// Package webassets exposes the compiled browser application embedded in the
// native service executable.
package webassets

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var embedded embed.FS

// FS returns the root of the embedded browser distribution.
func FS() (fs.FS, error) {
	return fs.Sub(embedded, "dist")
}
