# L2Network

L2Networkは、JuneauがL3を一切解釈しないL2セグメントです。宛先MACアドレスだけで転送するので、任意のEtherTypeと任意のIPプロトコルが通ります。

VMの中でbridgeを組む、自前のDHCPサーバを立てる、ルータVMを置く、といった使い方を想定しています。Subnetと同じくクラスタスコープで、shortNameは `l2net` です。

手順は[L2Networkで自由なセグメントを作る](../guides/l2-network.md)に、実装は[L2Networkの転送を追う](../developer/l2-data-plane.md)にあります。

## Vpc との関係

各L2Networkは、必ず1つのVpcに属します。`spec.vpc` は必須で、作成後は変更することができません。

`default` Vpcを指定することはできません。`default` Vpcはクラスタ全体で共有されるもので、そこに属せるのは `default` Subnetだけです。

## 3段階のスコープ

L2Networkは、書いたフィールドの数だけ機能が増えます。

| 宣言 | 挙動 |
|---|---|
| `cidr` なし | 純粋なL2として動きます。JuneauはIPを配りません |
| `cidr` あり | 上記に加えて、接続したNICにIPを配ります |
| `cidr` + `gateway` | 上記に加えて、VpcのRouteTableやNATGateway、Service、NetworkACLに繋がります |

## CIDR

`spec.cidr` を書くと、Juneauがそのプレフィックスから接続したNICにアドレスを配ります。書かなければ何も配りません。

指定できるのはIPv4 CIDRだけで、プレフィックス長は `/16` から `/28` までです。Subnetと違ってdefaulterを持たないので、ホスト部を落とした正規化済みの形で書く必要があります。`10.0.1.5/24` は拒否され、`10.0.1.0/24` と書き直すよう促されます。作成後は変更することができません。

`spec.cidr` を書いた場合は、Subnetと同じ5種類の重複検査を通ります。同一Vpc内のSubnetとL2Network、VpcPeeringの相手、TransitGateway経由で届くVpc、Vpcの `endpointPool`、そしてクラスタのService CIDRです。gatewayの有無では検査を切り替えません。gatewayなしで作った後からgatewayを足そうとしたときに重複で失敗する、という後出しの罠を避けるためです。

好きなCIDRを自由に使いたい場合は、`spec.cidr` を書かない選択で満たせます。

## gateway

`spec.gateway` を書くと、そのセグメントに出口が生えます。書かない場合、セグメントは閉じていて、同じL2Network上のNIC同士しか届きません。

`spec.gateway` には `spec.cidr` が必要です。gatewayが応答するアドレスがなければ成立しないためです。

`spec.gateway.address` を省略すると、controllerがプレフィックスの先頭アドレス、つまり `.1` を使います。明示する場合は `spec.cidr` の中で、ネットワークアドレスでもブロードキャストアドレスでもないアドレスを指定してください。

`spec.gateway.routeTable` を省略すると、所属VpcのメインルートテーブルがL2Networkの経路制御に使われます。指定する場合、そのRouteTableは同じVpcに属している必要があります。

gatewayを書くと、そのセグメントのポートを持つ各Nodeにルータのポートが1つ立ちます。アドレスもMACも全Nodeで同じなので、ワークロードは自分のNodeのgatewayを使い、L3の通信のためにNodeを跨ぎません。ポートを1つも持たないNodeには何も立ちません。

gatewayを書くと、そのCIDR宛の経路がVpcの全RouteTableに自動で入ります。Subnetのconnected routeと同じ扱いです。

`spec.gateway` は作成後にも変更することができます。ただし、そのアドレスを既にワークロードが持っている場合は拒否されます。`computeL2NetworkExcluded` はプールからの払い出しを止めるだけで、配ってしまったアドレスを取り返しません。別のアドレスを `spec.gateway.address` に書くか、持っているワークロードを消してから足してください。

Subnetと違って、L2NetworkはDNSリゾルバを持ちません。自前でDNSを立てたい人にとって予約アドレスは邪魔なだけなので、`spec.cidr` があってもgatewayの1アドレスしか予約しません。

gatewayは自分からARPを出しません。セグメントを流れるARPの送信者を記録して、Vpcから来たパケットの宛先MACを引きます。セグメント上のホストは外と話す前に必ずgatewayへARPを打つので普段は埋まっていますが、一度も名乗っていないホストへVpcの側から先に接続すると、最初のパケットは落ちます。

## SecurityGroup

L2NetworkのNICにも、`juneau.loutres.me/networks` アノテーションのエントリでSecurityGroupを付けることができます。参照されるのはgatewayを跨ぐ通信だけで、セグメントの中の通信には一切効きません。

そのため、`spec.gateway` を書いていないL2NetworkのNICにSecurityGroupを付けることはできません。`spec.networkACL` と同じ理由です。同じ理由で、Vpcの `spec.enforceSecurityGroups` はgatewayを持たないセグメントのNICには要求しません。

## NetworkACL

`spec.networkACL` には、同じVpcに属するNetworkACLを指定することができます。

このACLはgatewayを跨ぐ通信にだけ適用されます。同じL2Network上のNIC同士の通信には一切効きません。L2のデータプレーンはpolicyを読まないためです。

そのため、`spec.gateway` を書いていないL2Networkは `spec.networkACL` を書くことができません。効いているつもりの設定が残るくらいなら、作成時に拒否する方がましだと判断しました。

## MTU

`spec.mtu` には、そのセグメントのNICに与えるMTUを576から9000の範囲で指定することができます。

省略した場合は、controllerの `--default-l2-mtu` フラグの値が使われます。既定値は1450で、1500バイトのunderlayからVXLANのオーバーヘッド50バイトを引いた値です。underlayのMTUがこれと違う場合は、フラグかフィールドで合わせてください。

非IPプロトコルはフラグメントできないので、MTUが合っていないとフレームが黙って落ちます。

CNIがこのMTUをvethの両端に設定します。設定するのはL2NetworkのNICだけで、SubnetのNICは今まで通りカーネルの既定値のままです。

## VNI

L2NetworkのVNIは、Subnetと同じ `subnet-vni` AllocationPoolから払い出されます。データプレーンのフォワーディングテーブルはVNIだけをキーにしているので、プールを分けると2つのセグメントが同じVNIを取ってフレームが混ざります。

## status

`status.vni` は、そのセグメントのオーバーレイ識別子です。

`status.mtu` は、実際に適用されるMTUです。`spec.mtu` があればその値、なければcontrollerの既定値が入ります。

`status.gateway` は、解決済みのgatewayアドレスです。gatewayを持たないセグメントでは空のままです。

`status.gatewayMAC` は、gatewayがARPに応答するMACアドレスです。controllerが一度決めたらgatewayが存在する限り変わりません。

`status.networkACL` は、解決済みの `spec.networkACL` です。daemonがgatewayの境界に書き込む `aclID` と、解決した時点の `rulesetVersion` が入ります。ACLを指定していない場合は空のままです。

## Podへの接続

L2Networkは、追加NICとしてPodに接続します。`juneau.loutres.me/networks` アノテーションのエントリで `l2Network` を指定してください。

```yaml
annotations:
  juneau.loutres.me/subnet: web
  juneau.loutres.me/networks: |
    [
      {"interface": "eth1", "l2Network": "lab-net"}
    ]
```

1つのエントリに `subnet` と `l2Network` の両方を書くことはできません。どちらか一方が必要です。

eth0にL2Networkを指定することはできません。`juneau.loutres.me/subnet` はSubnet名だけを受け付けます。

`spec.cidr` を持たないL2NetworkのNICにはIPが載りません。追加NICなら、アドレスが無いままvethが作られて通信することができます。アドレスはPodの中で自分で振るか、セグメントに置いたDHCPサーバから受け取ってください。

eth0だけは例外です。コンテナランタイムはCNIの結果のeth0にアドレスが1つも無いとsandboxの作成を失敗させるので、`spec.cidr` を持たないL2NetworkはPodの1枚目のNICには使えません。

## 転送

L2NetworkのフレームはMACアドレスだけで転送されます。Juneauは学習テーブルを持っていて、ワークロードが出したフレームの送信元MACをそのポートに紐付けます。宛先MACが学習済みならそのポートへ、未学習ならセグメントの全ポートへ複製します。ブロードキャストとマルチキャストも全ポートへ複製します。

controllerはこのテーブルを一切書きません。`NetworkEndpoint.spec.macAddress` の静的エントリも使いません。NICの後ろでbridgeを組んだりnested VMを動かしたりすると、NIC自身のものではないMACが出てくるからです。誰がどのMACを名乗るかは制限していません。

学習したエントリは、300秒フレームを見なければ消えます。中身は `kubectl juneau bpf dump l2_fdb --inner-key vni=<VNI>` で読むことができます。

同じL2Network上のNIC同士の通信にはSecurityGroupもNetworkACLも効きません。L2のデータプレーンはpolicyを読まないので、テナント境界は `spec.vpc` で引いてください。

## 削除

L2Networkはfinalizerを持ちません。接続中のNetworkInterfaceやNetworkEndpointが残っていても削除は通ります。

参照を止めるのは、参照される側のwebhookです。L2Networkが残っているVpc、gatewayが使っているRouteTable、参照されているNetworkACLは、どれも削除が拒否されます。
