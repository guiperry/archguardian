package dashboard

import (
	"embed"
	"io/fs"
)

//go:embed *
var embeddedFiles embed.FS

// Dist is a filesystem that serves the embedded dashboard files.
var Dist, _ = fs.Sub(embeddedFiles, ".")
