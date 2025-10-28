package cni

import "embed"

//go:embed cni cni.conf
var EmbeddedFS embed.FS
