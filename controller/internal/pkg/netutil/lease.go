package netutil

import "strings"

func LeaseNameFor(subnet, address string) string {
	return subnet + "-" + strings.ReplaceAll(address, ".", "-")
}
