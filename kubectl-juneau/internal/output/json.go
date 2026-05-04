package output

import (
	"encoding/json"
	"io"
)

// RenderJSON writes v as pretty-printed JSON. Used as the default
// JSON renderer for any command's domain type.
func RenderJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}
