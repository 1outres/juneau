package webhookmanifests

import (
	_ "embed"
)

//go:embed manifests.yaml
var Manifests string
