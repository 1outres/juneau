package output

import (
	"io"

	"sigs.k8s.io/yaml"
)

// RenderYAML writes v as YAML using sigs.k8s.io/yaml so JSON tags on
// domain types double as YAML tags (matching kubectl convention).
func RenderYAML(w io.Writer, v any) error {
	b, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}
