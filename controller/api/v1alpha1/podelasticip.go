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

package v1alpha1

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

const (
	// PodElasticIPGateway is the next hop of every NIC that carries an
	// ElasticIP address directly. The NIC holds only a /32, so no address
	// of it covers the gateway: the route to it is marked onLink, and the
	// node answers ARP for it on the host side of the veth.
	PodElasticIPGateway = "169.254.0.1"

	// PodElasticIPRulePriority is the priority of the policy routing rule
	// that sends traffic from the ElasticIP address of an extra NIC to the
	// table PodElasticIPRouteTable returns. It has to come before the rule
	// of the main table (32766), which holds the default route of eth0.
	// Every such rule of a Pod shares this priority; their source
	// addresses never overlap, so their order does not matter.
	PodElasticIPRulePriority int32 = 100
)

// podReservedRouteTables is the first route table number Juneau may use.
// Linux gives the numbers below it special meanings: 0 is "no table",
// 253 is default, 254 is main and 255 is local.
const podReservedRouteTables = 256

// PodElasticIPRouteTable returns the route table, inside the Pod's network
// namespace, that holds the default route of an extra NIC that carries an
// ElasticIP address directly. The primary NIC does not use it: its default
// route stays in the main table.
//
// The table number is the IPv4 address itself read as a big-endian 32-bit
// number, so 203.0.113.10 uses table 3405803786. This makes the number
// depend on nothing but the NIC's own address: it is the same on every
// reconcile and on every node, it survives the Pod being created again with
// the same ElasticIP, and two NICs of one Pod never share it, because two
// NICs of one Pod never share an ElasticIP.
//
// The address must be IPv4. Addresses whose number falls below 256 are
// rejected, because Linux reserves those tables.
func PodElasticIPRouteTable(address netip.Addr) (int64, error) {
	if !address.Is4() {
		return 0, fmt.Errorf("an ElasticIP route table needs an IPv4 address, got %q", address)
	}
	bytes := address.As4()
	table := int64(binary.BigEndian.Uint32(bytes[:]))
	if table < podReservedRouteTables {
		return 0, fmt.Errorf("address %s maps to route table %d, which Linux reserves", address, table)
	}
	return table, nil
}
