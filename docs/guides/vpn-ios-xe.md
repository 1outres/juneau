# Cisco IOS XEからVPNに接続する（設定例）

以下は[vpn-gatewayの設定](https://github.com/1outres/juneau/blob/develop/vpn-gateway/README.md)に合わせた**未検証のひな型**です。Cisco IOS XE実機での相互接続も、対象リリースでのコマンド構文や暗号スイートの動作も確認していません。適用前に対象機種とリリースの仕様を確認してください。Juneau単体の機能であり、mNi CloudのVPN APIやUIとの連携は含みません。

## Juneau側

管理者が専用IPv4 AllocationPoolとゲートウェイイメージを設定し、インターネットから公開IPへのUDP 500/4500を許可します。VPNと同じnamespaceにPSK Secretを用意してください。作成例と`--vpn-tunnel-pool`、`--vpn-gateway-image`の指定は[VPN](../resources/vpn.md)にあります。

例ではVPN名`branch`、namespace`default`、Vpc`production`、オンプレネットワーク`192.0.2.0/24`を使います。`branch`の`spec.peerIKEID`は`branch.example.com`、`spec.localASN`は`65001`、`spec.remoteASN`は`65002`です。VPN作成後、Ciscoに渡す値を確認します。

```console
$ kubectl -n default get vpn branch -o jsonpath='{.status.publicIP}{"\n"}{.status.localTunnelIP}{"\n"}{.status.remoteTunnelIP}{"\n"}'
```

`PUBLIC_IP`には`status.publicIP`、`LOCAL_TUNNEL_IP`には`status.localTunnelIP`、`REMOTE_TUNNEL_IP`には`status.remoteTunnelIP`を使います。トンネルアドレスはそれぞれ/32です。値がまだ空なら割り当てを待ち、VPNのReady conditionも確認してください。ReadyになるにはCiscoからの接続が必要です。

`production`の戻り経路を忘れずに設定します。受信先Subnetが個別のRouteTableを使う場合も、それぞれ同じオンプレCIDRへの経路を追加してください。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: RouteTable
metadata:
  name: production
spec:
  vpc: production
  routes:
    - dst: 192.0.2.0/24
      via:
        type: vpn
        vpn:
          namespace: default
          name: branch
```

## Cisco側のひな型

次の`<...>`を実際の値に置き換えてください。`<PSK>`はSecretの指定キーと同じ値で、設定ファイルや操作ログに残さないよう取り扱ってください。`<PEER_IKE_ID_WITHOUT_AT_PREFIX>`はVPNの固定`peerIKEID`に対応するFQDNです。`<CISCO_WAN_INTERFACE>`はNAT越しにJuneauへ出られるインターフェースを指定します。拠点ごとに固有のprofileを使います。

```text
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

このひな型は[vpn-gateway README](https://github.com/1outres/juneau/blob/develop/vpn-gateway/README.md)のIOS XE starting templateと同じ暗号条件です。Juneau側はIKEv2、AES-256-GCM、SHA-384 PRF、ECP-384に固定し、NAT-T用にUDPカプセル化を使います。route-based VTIを使い、policy-basedのcrypto ACLは設定しません。CiscoのNAT外側IPは変わっても構いませんが、Ciscoから接続を開始する必要があります。JuneauからIKEの接続を開始しません。

/32のVTIで対向のトンネルアドレスがオンリンクにならない場合に備えて、上の例には`LOCAL_TUNNEL_IP`へのホスト経路を含めています。Cisco側でJuneauから受信したBGP経路を確認し、オンプレ側の機器にVpc宛経路と復路があることも確認してください。JuneauはCiscoから受信したBGP経路を採用しません。オンプレ宛経路は前述のRouteTableで手動設定します。BGPセッションが確立しても、SecurityGroupとNetworkACL、直接のVpcPeeringやTransitGatewayの戻り経路を含めた往復疎通は別途確認してください。
