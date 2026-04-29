# NATGateway

NATGatewayは、Vpcに属するPodがVpc外へ通信する際のNAPT (N:1のソースNAT) 出口を表すリソースです。
Vpc内の複数のPodが共通のソースIPアドレスで外部に出ていく構成を作るときに利用します。

`spec.vpc`はこのNATGatewayが属するVpcの名前です。
`spec.externalNetwork`は出口となるExternalNetworkの名前です。
NAPT時のソースIPアドレスは、参照したExternalNetworkに紐づくAddressPoolから払い出されます。

`spec.vpc`と`spec.externalNetwork`は作成後に変更できません。

## RouteTable との連携

NATGatewayをVpc外への経路として利用するには、対象VpcのRouteTableに`via.type: natGateway`のルートを追加し、`via.natGateway`でNATGateway名を参照します。
たとえば`0.0.0.0/0`のデフォルトルートをこのNATGateway経由に向けることで、Vpc内のPodがクラスタ外へ通信できるようになります。

詳しくは[RouteTable](routetable.md)を参照してください。

## Node ごとのソースIP

NATGatewayを作成すると、対象ExternalNetworkに紐づくNodeごとの[ExternalNetworkAttachment](externalnetworkattachment.md)が自動的に作成され、Nodeごとに1つずつNAPTソースIPアドレスが払い出されます。
Pod がVpc外へ出るとき、そのPodが配置されているNodeに対応するソースIPアドレスが利用されます。

## default NATGateway

`default`という名前のNATGatewayが存在し、Readyになっている場合、`default` Vpcのメインルートテーブルには`0.0.0.0/0`へのルートが`via.type: natGateway`として自動的に追加されます。
これにより明示的にRouteTableを構成しなくても、default Vpc内のPodがクラスタ外へ通信できるようになります。

## status

`status.conditions`の`Ready`は、NATGatewayが正常に利用可能かを表します。
`Ready=True`になるまでは、このNATGatewayを参照するRouteTableのルートも有効にはなりません。
