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

// LastAddr returns the broadcast (all-ones) address of the prefix.
func LastAddr(p netip.Prefix) netip.Addr {
	addr := p.Masked().Addr()
	bits := p.Bits()
	bs := addr.As16()
	totalBits := addr.BitLen()
	hostBits := totalBits - bits
	for i := 15; hostBits > 0 && i >= 0; i-- {
		flip := hostBits
		if flip > 8 {
			flip = 8
		}
		bs[i] |= byte(1<<flip - 1)
		hostBits -= flip
	}
	if addr.Is4() {
		return netip.AddrFrom4([4]byte{bs[12], bs[13], bs[14], bs[15]})
	}
	return netip.AddrFrom16(bs)
}

// FirstAddr returns the first address after the network address of the
// prefix — the `.1` of an IPv4 /24. A prefix with no room for one (a /31
// or a /32) has no such address, so the second return is false.
func FirstAddr(p netip.Prefix) (netip.Addr, bool) {
	masked := p.Masked()
	addr := masked.Addr().Next()
	if !addr.IsValid() || !masked.Contains(addr) {
		return netip.Addr{}, false
	}
	return addr, true
}
