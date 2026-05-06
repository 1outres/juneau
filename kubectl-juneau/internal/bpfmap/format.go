package bpfmap

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// formatU64 chooses between base-10 numeric and a flags-style label
// list. When a numeric field carries no flags, we render base-10; when
// flags are present we surface both forms so users see the bits and
// the raw value (e.g. "[A,B] (0x3)").
func formatU64(v uint64, flags []string) string {
	if len(flags) == 0 {
		return fmt.Sprintf("%d", v)
	}
	return fmt.Sprintf("[%s] (0x%x)", strings.Join(flags, ","), v)
}

// formatRaw chooses between hex and ASCII based on printability. Most
// raw fields are short headers / alignment slop where hex is the
// useful form; the ASCII branch is here for future text payloads.
func formatRaw(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	allPrint := true
	for _, c := range b {
		if c < 0x20 || c >= 0x7F {
			allPrint = false
			break
		}
	}
	if allPrint {
		return string(b)
	}
	return "0x" + hex.EncodeToString(b)
}
