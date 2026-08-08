# ElasticIPAttachment

ElasticIPAttachmentは、ElasticIPをNetworkInterfaceへ関連付けるリソースです。

1つのElasticIPに対して有効なElasticIPAttachmentは最大1つです。
1つのNetworkInterfaceに対して有効なElasticIPAttachmentも最大1つです。

## 前提

- 対象のNetworkInterfaceは**default以外のSubnet**に属している必要があります。default SubnetのPodはElasticIPの対象にできません
- 対象Podが属するVpcのRouteTableに`type: internetGateway`のルートが必要です。無いと外部疎通が成立しません

セットアップ手順の全体像は[BGPを使ってExternalNetworkを構築する](../guides/external-network-bgp.md)を参照してください。

`status.elasticIP`は関連付け対象として解決されたElasticIPのアドレスです。
`status.podIP`は関連付け先NetworkInterfaceのPod側IPアドレスです。
`status.nodeName`は関連付け先NetworkInterfaceが存在するノード名です。

`Ready`は、この関連付けを安全に扱える状態かを表します。
`Ready=True`ならElasticIPとNetworkInterfaceが解決され、対応するNetworkEndpointも一意に定まり、関連付け済みです。
`Ready=False`なら依存リソース待ち、または不整合があります。

## Phase

- Pending:依存リソースの割り当てや対応するNetworkEndpointの作成待ち
- Attached:ElasticIPが1つのNetworkInterfaceへ正常に関連付けられている状態
- Error:参照先不整合や複数NetworkEndpoint一致などで正常に扱えない状態

## ICMPの扱い

ElasticIPの1:1 NATは、外側のIPヘッダに加えて、ICMPエラーメッセージが内包している元パケットのヘッダも書き換えます。

Linuxは受信したICMPエラーを、内包されたヘッダのタプルだけで対応するソケットに結び付けます。内包の送信元がElasticIPのまま届くと、Pod内のカーネルはソケットを見つけられず、そのエラーを黙って捨てます。内包ヘッダを書き換えることで、次のものが成立します。

- Path MTU Discovery。`tcp_v4_err`は内包の`(送信元アドレス, 送信元ポート)`でソケットを探すので、内包がPod自身のアドレスであればFragmentation Neededが該当ソケットに渡り、経路MTUがキャッシュされます
- `traceroute`。UDPモードとICMPモードのどちらでも途中のホップが表示されます
- 到達不能な相手に対する`connect()`の中断

内包ヘッダの書き換えの対象になるのは、Destination Unreachable、Time Exceeded、Source Quench、Redirect、Parameter Problemの5種類です。それ以外のICMPタイプは外側のIPヘッダだけが書き換わります。ICMPのIdentifierを持つEcho Request/Replyもこちらで、1:1 NATはIdentifierを変換しません。

1:1 NATがポートを変換しないのは内包ヘッダでも同じで、変わるのはアドレスだけです。内包しているパケットのプロトコルがTCP、UDP、ICMP Echoのいずれでもないエラーメッセージと、内包ヘッダが関連付けたElasticIP以外のアドレスを指しているエラーメッセージは、書き換えようがないので破棄されます。

書き換えは`kubectl juneau trace`で`icmp error translated`として記録されます。

Podが持つのが1つのアドレスだけで、外向きの通信しか必要ないのであれば、[NATGateway](natgateway.md)でも同じことができます。
