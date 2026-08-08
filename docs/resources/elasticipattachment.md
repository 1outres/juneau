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

## 制限事項

ElasticIPの1:1 NATは、パケットの外側のIPヘッダしか書き換えません。ICMPエラーメッセージ (Destination UnreachableやTime Exceededなど) が内包している元パケットのヘッダは、ElasticIPのまま残ります。

Linuxは受信したICMPエラーを、内包されたヘッダのタプルだけで対応するソケットに結び付けます。内包の送信元がElasticIPになっていると、Pod内のカーネルはソケットを見つけられず、そのエラーを捨てます。影響が最も出るのはTCPです。

- Path MTU Discoveryがブラックホール化します。`tcp_v4_err`は内包の`(送信元アドレス, 送信元ポート)`でソケットを探すため、Fragmentation Neededが届いても該当ソケットに渡らず、経路MTUが学習されません。ハンドシェイクは成功するのに最初の大きなレスポンスで固まる、という形で出ます
- Destination Unreachableが`connect()`を中断させません。到達不能な相手への接続がタイムアウトまで待たされます

厄介なのは、`ping`と`traceroute`では気付けないことです。`ping`と`traceroute -I`はIdentifierで応答を照合し、1:1 NATはIdentifierを保存するので期待通りに動きます。UDPの`traceroute`もソケットが通常ワイルドカードでbindされているため、`__udp4_lib_err`が内包のアドレスに関係なく見つけてしまいます。見つからないのは、Pod IPを明示してbindしたUDPソケットだけです。

Path MTU Discoveryも、ツールの上では成功しているように見えます。ElasticIPを付けたPodで`ping -M do`を打つと`Frag needed and DF set (mtu = 1280)`と表示されます。しかし`ipv4_update_pmtu`が例外経路を入れる先は内包の送信元、つまりElasticIPです。Podはそのアドレスから送信しないため、実際の送信元に対する経路MTUはキャッシュされません。

つまり`ping`と`traceroute`で確認した限りでは正常に見え、大きなTCP転送だけが失敗します。egressだけが必要な用途であれば、ICMPエラーメッセージを内包ヘッダごと書き換える[NATGateway](natgateway.md)を使うことができます。
