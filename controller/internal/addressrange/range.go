/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package addressrange

import "net/netip"

// Range is an inclusive address interval. Both bounds belong to the same
// address family and Start is never after End.
type Range struct {
	Start netip.Addr
	End   netip.Addr
}

// PrefixRange returns the range that holds every address of the prefix,
// the network and broadcast addresses included.
func PrefixRange(p netip.Prefix) Range {
	p = p.Masked()
	return Range{Start: p.Addr(), End: LastAddr(p)}
}

// Intersect returns the addresses r shares with other. The second return is
// false when they share none. Addresses of different families never share.
func (r Range) Intersect(other Range) (Range, bool) {
	start := r.Start
	if other.Start.Compare(start) > 0 {
		start = other.Start
	}
	end := r.End
	if other.End.Compare(end) < 0 {
		end = other.End
	}
	if start.Compare(end) > 0 {
		return Range{}, false
	}
	return Range{Start: start, End: end}, true
}

// String writes a range of one address as that address, and a wider range
// in the start-end form.
func (r Range) String() string {
	if r.Start == r.End {
		return r.Start.String()
	}
	return r.Start.String() + separator + r.End.String()
}
