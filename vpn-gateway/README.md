# VPN gateway

One VPN runs one privileged Pod with two Juneau NICs: `eth0` in the chosen Subnet and `ext0` with the VPN's ElasticIP. The image contains strongSwan, BIRD 2, and the `vpn-gateway` process. It does not use host networking. Install the image with `make image-vpn-gateway` (or `make publish-vpn-gateway`), and set the controller's `--vpn-gateway-image` to the image that its nodes can pull. The bundled controller manifest uses `vpn-gateway:latest`; Tilt builds that local tag.

Create a dedicated IPv4 `AllocationPool` for tunnel addresses and set `--vpn-tunnel-pool` to its name on the controller manager. Do not share that pool with Subnets. The pool and image flags are required; without either, no VPN gateway is started. The controller creates the EIP, allocates two addresses, mounts the VPN namespace's PSK Secret, and replaces the Pod when the Secret or its routes change. The Secret is never copied into Pod environment variables or VPN status.

## Pod configuration contract

The controller supplies `PUBLIC_IP`, `LOCAL_TUNNEL_IP`, `REMOTE_TUNNEL_IP`, `LOCAL_ASN`, `REMOTE_ASN`, `PEER_IKE_ID`, `VPN_PSK_FILE`, `VPN_REMOTE_ROUTES`, and `VPN_ADVERTISED_ROUTES`. The last two are JSON arrays of IPv4 CIDRs, including `[]` when empty. `VPN_PSK_FILE` is the mounted Secret key, not the key itself. All required values are validated at startup. Invalid configuration exits nonzero rather than starting a weaker or partial tunnel.

The gateway accepts IKEv2 initiation from any outer remote address, authenticates the fixed remote IKE ID with the PSK, forces UDP encapsulation for NAT traversal, and negotiates AES-256-GCM, SHA-384 PRF, and ECP-384 only. The XFRM interface ID is 42 in both directions; selectors are `0.0.0.0/0` for route-based operation. Both tunnel IPs are /32: configure an explicit host route to Juneau's tunnel IP on a Cisco VTI if it is not in the same on-link prefix. Do not configure a policy-based crypto ACL. Cisco IOS XE interoperability and the precise crypto proposal have **not** been tested on hardware.

`VPN_REMOTE_ROUTES` comes from RouteTables in the VPN Vpc that explicitly point to this VPN and are Ready (or waiting only for this VPN's endpoint). These routes are placed in gateway-only Linux table 200. Incoming tunnel sources and outgoing tunnel destinations are restricted to these CIDRs by the gateway's FORWARD chain. Incoming tunnel traffic is also restricted to advertised destination CIDRs, so the gateway cannot forward it to another VPN. No SNAT or MASQUERADE is installed. The Vpc's other Pods still require matching manual RouteTable entries. `VPN_ADVERTISED_ROUTES` comes from Ready local Subnets and the selected gateway Subnet's effective RouteTable: resolved, directly peered, and TransitGateway Subnets and only individual /32 Service addresses allowed by Vpc Service settings are eligible. Default, InternetGateway, NATGateway, and other VPN routes are not advertised. BIRD rejects **all** received BGP routes and never exports its own static blackhole advertisements to the kernel.

### IOS XE starting template (not tested on hardware)

Replace the angle-bracketed values with the VPN status addresses, the VPN ASNs, the fixed peer IKE ID, and the Secret's PSK. This template is a starting point only; validate its command syntax and crypto support on the target IOS XE release. Use a unique profile per VPN. The Cisco end starts the tunnel from behind NAT; Juneau never initiates IKE.

```
crypto ikev2 proposal JUNEAU-IKE
 encryption aes-gcm-256
 prf sha384
 group 20
crypto ikev2 policy JUNEAU-IKE
 proposal JUNEAU-IKE
crypto ikev2 keyring JUNEAU-KEY
 peer JUNEAU
  address <PUBLIC_IP>
  pre-shared-key <PSK>
crypto ikev2 profile JUNEAU-IKE
 match identity remote address <PUBLIC_IP> 255.255.255.255
 identity local fqdn <PEER_IKE_ID_WITHOUT_AT_PREFIX>
 authentication local pre-share
 authentication remote pre-share
 keyring local JUNEAU-KEY
crypto ipsec transform-set JUNEAU-ESP esp-gcm 256
 mode tunnel
crypto ipsec profile JUNEAU-IPSEC
 set transform-set JUNEAU-ESP
 set ikev2-profile JUNEAU-IKE
 set pfs group20
interface Tunnel101
 ip address <REMOTE_TUNNEL_IP> 255.255.255.255
 tunnel source <CISCO_WAN_INTERFACE>
 tunnel destination <PUBLIC_IP>
 tunnel mode ipsec ipv4
 tunnel protection ipsec profile JUNEAU-IPSEC
ip route <LOCAL_TUNNEL_IP> 255.255.255.255 Tunnel101
router bgp <REMOTE_ASN>
 neighbor <LOCAL_TUNNEL_IP> remote-as <LOCAL_ASN>
 neighbor <LOCAL_TUNNEL_IP> update-source Tunnel101
```

`vpn-gateway health` exits zero only while the strongSwan IKE SA and child SA are installed and BIRD reports an established BGP session. Until then the Kubernetes readiness probe is false and the VPN Ready condition stays false. A stopped or failing strongSwan/BIRD process exits the Pod. The tunnel address status is published once allocated; the public IP is published after attachment even when the peer is still connecting.

## Limits

The gateway is single-Pod and is not highly available. The external-network firewall must permit UDP 500/4500. The node data plane must accept forwarded on-premises source addresses only for the matching VPN and implement manual `via.type: vpn` forwarding; deploying this image alone does not change the node's source validation or peering/TGW return routing. Until these separate components are in place, BGP establishment does not imply end-to-end reachability. No live or Cisco hardware test was performed here.
