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

package controller

import (
	"fmt"
	"net"
)

// endpointMAC derives the MAC address a NetworkEndpoint uses on the
// overlay from its IPv4 address: 02:00 followed by the four address
// octets. The 02 prefix marks a locally administered unicast address,
// so it can never collide with a real vendor MAC, and the address
// itself is unique inside its Subnet because the Subnet's IP pool
// hands out each IP once. That makes the MAC stable: the same IP
// always yields the same MAC, on any node and after any restart.
func endpointMAC(ip net.IP) (string, error) {
	if ip == nil {
		return "", fmt.Errorf("endpoint address is missing")
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "", fmt.Errorf("endpoint address %q is not IPv4", ip.String())
	}
	return fmt.Sprintf("02:00:%02x:%02x:%02x:%02x", ip4[0], ip4[1], ip4[2], ip4[3]), nil
}
