# TransitGateway

TransitGatewayは、複数のVpcを1つのハブに集めて相互接続するリソースです。

[VpcPeering](vpcpeering.md)が2つのVpcを直接つなぐのに対して、TransitGatewayでは各Vpcを[TransitGatewayAttachment](transitgatewayattachment.md)でハブに接続し、どのVpcからどのVpcへ通すかを[TransitGatewayRouteTable](transitgatewayroutetable.md)で決めます。

`spec`に設定項目はありません。TransitGateway自体は、ルートテーブルとアタッチメントをまとめる管理単位です。

## default route table

TransitGatewayを作成すると、同じ名前のTransitGatewayRouteTableが自動的に作成され、`status.defaultRouteTable`に記録されます。Vpcのメインルートテーブルと同じ考え方です。

ルートテーブルを分ける必要が無ければ、すべてのアタッチメントの`spec.association`と`spec.propagations`にこのルートテーブルを指定してください。接続したVpcが互いに到達できる構成になります。

## RouteTableとの連携

Vpc内のPodをTransitGateway経由で他のVpcへ出すには、対象VpcのRouteTableに`via.type: transitGateway`のルートを追加し、`via.transitGateway`でTransitGateway名を参照します。

このルートの`dst`は、複数のSubnetをまとめたスーパーネットでも構いません。実際の宛先解決は、そのVpcのアタッチメントがassociationしているTransitGatewayRouteTableの中で行われます。

詳しくは[RouteTable](routetable.md)を参照してください。

## SecurityGroupの制約

VpcPeeringと同じく、SecurityGroupの`securityGroupRef`は同じVpcのSecurityGroupしか参照できません。TransitGateway経由で届く他VpcのPodからの通信を許可するには、`cidr`のルールを書いてください。

## status

`status.defaultRouteTable`は、このTransitGatewayが自動的に作成したTransitGatewayRouteTableの名前です。

`status.conditions`の`Ready`は、default route tableが作成され、利用できる状態になったことを表します。`Ready=True`になるまでは、このTransitGatewayを参照するRouteTableのルートも有効になりません。

## 削除

TransitGatewayAttachmentが残っている間、またはこのTransitGatewayを`via.transitGateway`で参照するRouteTableが残っている間は削除できません。default route tableはTransitGatewayの削除に合わせて削除されます。
