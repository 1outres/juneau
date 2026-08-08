# TransitGatewayAttachment

TransitGatewayAttachmentは、1つのVpcを[TransitGateway](transitgateway.md)に接続するリソースです。

`spec.transitGateway`と`spec.vpc`で、接続するTransitGatewayとVpcを指定します。どちらも作成後に変更することができません。同じ組み合わせのアタッチメントを2つ作ることはできません。

## associationとpropagation

`spec.association`は、このVpcから届いたトラフィックの宛先を解決する[TransitGatewayRouteTable](transitgatewayroutetable.md)です。1つだけ指定します。

`spec.propagations`は、このVpcのSubnetを広報するTransitGatewayRouteTableの一覧です。0個でも複数でも構いません。

この2つを別のルートテーブルに向けると、経路を非対称にすることができます。たとえばハブ&スポーク構成では、スポーク側のアタッチメントをスポーク用ルートテーブルにassociationし、ハブ用ルートテーブルにpropagationします。スポーク用ルートテーブルにはハブのSubnetしか載らないため、スポーク同士は到達しません。

`spec.association`と`spec.propagations`で参照するTransitGatewayRouteTableは、`spec.transitGateway`と同じTransitGatewayに属している必要があります。

## CIDRの重複

同じTransitGatewayRouteTableを共有するVpcの間では、SubnetのCIDRが重複していてはいけません。重複するアタッチメントを作成しようとするとwebhookで拒否されます。同じルートテーブル経由で到達し得るVpcのSubnetと重複するCIDRのSubnetを作成しようとした場合も同様に拒否されます。

## status

`status.prefixes[]`は、このアタッチメントが`spec.propagations`のルートテーブルへ広報しているSubnetの一覧です。`cidr`の昇順に並びます。

`status.conditions`の`Ready`は、TransitGatewayとVpc、参照先のルートテーブルがすべて存在して整合していることを表します。

## 削除

TransitGatewayAttachmentはいつでも削除できます。削除するとそのVpcのSubnetがルートテーブルから消えるため、そのVpc宛のトラフィックは宛先を解決できなくなり破棄されます。

削除したVpcのRouteTableに`via.type: transitGateway`のルートが残っている場合、そのRouteTableは`Ready=False`になり、`Vpc ... has no attachment to TransitGateway ...`というメッセージを返します。
